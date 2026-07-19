import json, subprocess, time
from eth_keys import keys
from Crypto.Hash import keccak as _keccak, cSHAKE128

BASE = 'http://127.0.0.1:3030'

def post(path, body):
    r = subprocess.run(['curl','-s','-X','POST', BASE+path,
        '-H','Content-Type: application/json', '-d', json.dumps(body)],
        capture_output=True, text=True, timeout=15)
    return json.loads(r.stdout) if r.stdout.strip() else {}

PASS = 0; FAIL = 0

def check(label, got, ok_expected, err_substr=None, errors_substr=None):
    global PASS, FAIL
    ok = True; notes = []
    if got.get('success') != ok_expected:
        ok = False; notes.append('success=%s want %s' % (got.get('success'), ok_expected))
    if err_substr:
        e = got.get('error') or ''
        if err_substr not in e:
            ok = False; notes.append('error=%r missing %r' % (e[:80], err_substr))
    if errors_substr:
        es = ' '.join(got.get('errors', []))
        if errors_substr not in es:
            ok = False; notes.append('errors=%r missing %r' % (es[:80], errors_substr))
    if ok: PASS += 1
    else:  FAIL += 1
    print('  [%s] %s' % ('PASS' if ok else 'FAIL', label)
          + ('  -> ' + '; '.join(notes) if notes else ''))
    return ok

# ── Crypto helpers ────────────────────────────────────────────────────────────

def keccak(data):
    h = _keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()

# NIST SP 800-185 helpers
def left_encode(n):
    if n == 0: return bytes([1, 0])
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([len(raw)]) + raw

def right_encode(n):
    if n == 0: return bytes([0, 1])
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return raw + bytes([len(raw)])

def encode_string(s):
    return left_encode(len(s) * 8) + s

def bytepad(x, w):
    out = left_encode(w) + x
    rem = len(out) % w
    if rem: out += b'\x00' * (w - rem)
    return out

def kmac128_hex(key, data):
    """KMAC128(key, data, 32, b'SynQSourceNonce') per NIST SP 800-185.
    Replicates the server's kmac128_hex() exactly:
      cSHAKE128(N="KMAC", S="SynQSourceNonce")
        .absorb(bytepad(encode_string(key), 168))
        .absorb(data)
        .absorb(right_encode(256))
        .squeeze(32)
    """
    h = cSHAKE128.new(custom=b'KMACSynQSourceNonce')
    # Note: pycryptodome cSHAKE128 does NOT handle the KMAC N="KMAC" prefix
    # internally — we must prepend bytepad(encode_string("KMAC")||encode_string(S), 168)
    # to match the server's CShake128Core::new_with_function_name(b"KMAC", b"SynQSourceNonce").
    # pycryptodome's cSHAKE128(custom=b'SynQSourceNonce') absorbs
    #   bytepad(encode_string("")||encode_string(custom), 168)  [N="" per cSHAKE spec]
    # The server absorbs:
    #   bytepad(encode_string("KMAC")||encode_string("SynQSourceNonce"), 168)
    # So we must absorb the difference manually using raw SHAKE128 to match exactly.
    # Use a direct construction instead:
    from Crypto.Hash import SHAKE128
    shake = SHAKE128.new()
    # Build the cSHAKE128 init block manually:
    #   bytepad( encode_string("KMAC") || encode_string("SynQSourceNonce"), 168 )
    n_block = encode_string(b"KMAC") + encode_string(b"SynQSourceNonce")
    shake.update(bytepad(n_block, 168))
    # KMAC key block: bytepad(encode_string(key), 168)
    shake.update(bytepad(encode_string(key), 168))
    # Message
    shake.update(data)
    # KMAC length suffix: right_encode(256) [256 output bits]
    shake.update(right_encode(256))
    return shake.read(32).hex()

def eip712_domain_for_contract(contract_name):
    domain_name = "SynQ \u00b7 " + contract_name   # U+00B7 middle dot
    vc_hash = keccak(("SynQ:" + contract_name).encode())
    vc      = vc_hash[12:]
    type_hash = keccak(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    enc = (type_hash
         + keccak(domain_name.encode())
         + keccak(b"1")
         + (1337).to_bytes(32, 'big')
         + b'\x00'*12 + vc)
    return keccak(enc)

def eip712_struct_hash_source_commit(source_hash_0x, contract_name, nonce):
    type_hash = keccak(b"SourceCommit(string sourceHash,string contractName,string nonce)")
    enc = (type_hash
         + keccak(source_hash_0x.encode())
         + keccak(contract_name.encode())
         + keccak(nonce.encode()))
    return keccak(enc)

def eip712_digest(domain_sep, struct_hash):
    return keccak(b'\x19\x01' + domain_sep + struct_hash)

def sign_digest(digest_bytes, privkey_bytes):
    """Sign 32-byte digest, return 65-byte (r||s||v) sig."""
    pk  = keys.PrivateKey(privkey_bytes)
    sig = pk.sign_msg_hash(digest_bytes)
    r = sig.r.to_bytes(32, 'big')
    s = sig.s.to_bytes(32, 'big')
    v = bytes([sig.v + 27])
    return r + s + v

def privkey_to_address(privkey_bytes):
    pk   = keys.PrivateKey(privkey_bytes)
    pub  = pk.public_key
    addr = keccak(pub.to_bytes())[12:]
    return '0x' + addr.hex()

# ── Test wallets (Hardhat devnet well-known keys — never use for real funds) ──
PRIVKEY1    = bytes.fromhex('ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80')
PRIVKEY2    = bytes.fromhex('59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d')
WALLET1     = privkey_to_address(PRIVKEY1)
WALLET2     = privkey_to_address(PRIVKEY2)
print('Wallet 1: %s' % WALLET1)
print('Wallet 2: %s' % WALLET2)

SRC = (
    'pragma synq ^0.9;\n'
    'contract SimpleToken {\n'
    '  total: UInt256;\n'
    '  function getTotal() { return total; }\n'
    '}'
)
CONTRACT_NAME  = 'SimpleToken'
src_hash_bytes = keccak(SRC.encode())
src_hash_hex   = src_hash_bytes.hex()
src_hash_0x    = '0x' + src_hash_hex

# ── S1: /source-nonce issuance ────────────────────────────────────────────────
print('\n=== S1: /source-nonce — nonce issuance ===')
time.sleep(2)
nr    = post('/source-nonce', {'source_hash': src_hash_hex})
nonce = nr.get('nonce', '')
print('  nonce (first 16): %s...' % nonce[:16])
check('returns nonce (64 hex chars)',  {'success': len(nonce) == 64}, True)
check('expires_in > 0',               {'success': nr.get('expires_in', 0) > 0}, True)

# ── S2: EIP-712 digest construction check ─────────────────────────────────────
print('\n=== S2: EIP-712 digest construction ===')
domain_sep  = eip712_domain_for_contract(CONTRACT_NAME)
struct_hash = eip712_struct_hash_source_commit(src_hash_0x, CONTRACT_NAME, nonce)
digest      = eip712_digest(domain_sep, struct_hash)
signature   = sign_digest(digest, PRIVKEY1)
print('  domain_sep:   %s' % domain_sep.hex())
print('  struct_hash:  %s' % struct_hash.hex())
print('  digest:       %s' % digest.hex())
check('domain_sep  32B', {'success': len(domain_sep)  == 32}, True)
check('struct_hash 32B', {'success': len(struct_hash) == 32}, True)
check('digest      32B', {'success': len(digest)      == 32}, True)
check('signature   65B', {'success': len(signature)   == 65}, True)

# ── S3: /compile/sign-source — happy path: recovered == claimed ───────────────
print('\n=== S3: /compile/sign-source — valid signature (recovered == claimed) ===')
time.sleep(2)
resp = post('/compile/sign-source', {
    'source':        SRC,
    'evm_address':   WALLET1,
    'evm_signature': '0x' + signature.hex(),
    'nonce':         nonce,
})
print('  success=%s  contract=%s  errors=%s' % (
    resp.get('success'), resp.get('contract_name'), resp.get('errors', [])))
check('sign-source succeeds',                    resp, True)
check('contract_name == SimpleToken',            {'success': resp.get('contract_name') == CONTRACT_NAME}, True)
check('bytecode present',                        {'success': bool(resp.get('bytecode'))}, True)
sc = (resp.get('signature_sidecar') or {}).get('source_commit')
check('source_commit sidecar present',           {'success': bool(sc)}, True)

# ── S4: fabricated nonce → rejected ──────────────────────────────────────────
print('\n=== S4: fabricated nonce → rejected ===')
time.sleep(2)
nr4    = post('/source-nonce', {'source_hash': src_hash_hex})
nonce4 = nr4.get('nonce', '')
sh4    = eip712_struct_hash_source_commit(src_hash_0x, CONTRACT_NAME, nonce4)
dig4   = eip712_digest(eip712_domain_for_contract(CONTRACT_NAME), sh4)
sig4   = sign_digest(dig4, PRIVKEY1)
time.sleep(2)
r4 = post('/compile/sign-source', {
    'source':        SRC,
    'evm_address':   WALLET1,
    'evm_signature': '0x' + sig4.hex(),
    'nonce':         'f' * 64,          # fabricated
})
check('fabricated nonce -> nonce invalid', r4, False, errors_substr='nonce invalid')

# ── S5: wrong claimed address → recovered != claimed ─────────────────────────
print('\n=== S5: wrong claimed address (recovered != claimed) ===')
time.sleep(2)
nr5    = post('/source-nonce', {'source_hash': src_hash_hex})
nonce5 = nr5.get('nonce', '')
sh5    = eip712_struct_hash_source_commit(src_hash_0x, CONTRACT_NAME, nonce5)
dig5   = eip712_digest(eip712_domain_for_contract(CONTRACT_NAME), sh5)
sig5   = sign_digest(dig5, PRIVKEY1)   # signed with wallet1
time.sleep(2)
r5 = post('/compile/sign-source', {
    'source':        SRC,
    'evm_address':   '0x' + '00' * 19 + 'ff',   # claim garbage address
    'evm_signature': '0x' + sig5.hex(),
    'nonce':         nonce5,
})
print('  errors:', r5.get('errors', []))
check('wrong claimed addr -> recovered != claimed', r5, False, errors_substr='recovered')

# ── S6: tampered source → nonce hash mismatch ────────────────────────────────
print('\n=== S6: tampered source (nonce bound to original hash) ===')
time.sleep(2)
nr6    = post('/source-nonce', {'source_hash': src_hash_hex})   # nonce for ORIGINAL
nonce6 = nr6.get('nonce', '')
sh6    = eip712_struct_hash_source_commit(src_hash_0x, CONTRACT_NAME, nonce6)
dig6   = eip712_digest(eip712_domain_for_contract(CONTRACT_NAME), sh6)
sig6   = sign_digest(dig6, PRIVKEY1)
TAMPERED = SRC.replace('getTotal', 'getTotal2')  # different source -> different hash
time.sleep(2)
r6 = post('/compile/sign-source', {
    'source':        TAMPERED,
    'evm_address':   WALLET1,
    'evm_signature': '0x' + sig6.hex(),
    'nonce':         nonce6,   # nonce was issued for original hash
})
check('tampered source -> nonce invalid (hash mismatch)', r6, False, errors_substr='nonce invalid')

# ── S7: wrong private key (wallet2 signs, wallet1 claimed) ───────────────────
print('\n=== S7: wrong private key (wallet2 signs, wallet1 address claimed) ===')
time.sleep(2)
nr7    = post('/source-nonce', {'source_hash': src_hash_hex})
nonce7 = nr7.get('nonce', '')
sh7    = eip712_struct_hash_source_commit(src_hash_0x, CONTRACT_NAME, nonce7)
dig7   = eip712_digest(eip712_domain_for_contract(CONTRACT_NAME), sh7)
sig7   = sign_digest(dig7, PRIVKEY2)   # signed with wallet2
time.sleep(2)
r7 = post('/compile/sign-source', {
    'source':        SRC,
    'evm_address':   WALLET1,           # claim wallet1
    'evm_signature': '0x' + sig7.hex(),
    'nonce':         nonce7,
})
print('  expected recovered: %s' % WALLET2)
print('  claimed:            %s' % WALLET1)
print('  errors:', r7.get('errors', []))
check('wallet2 signs, wallet1 claimed -> recovered != claimed', r7, False, errors_substr='recovered')

print('\n' + '='*60)
print('  PASSED: %d   FAILED: %d   TOTAL: %d' % (PASS, FAIL, PASS+FAIL))
print('='*60)
