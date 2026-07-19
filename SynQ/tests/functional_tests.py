
import json, subprocess, time
BASE  = 'http://127.0.0.1:3030'
DELAY = 2.2

def post(path, body):
    r = subprocess.run(['curl','-s','-X','POST', BASE+path,
        '-H','Content-Type: application/json', '-d', json.dumps(body)],
        capture_output=True, text=True, timeout=15)
    return json.loads(r.stdout) if r.stdout.strip() else {}

def get(path):
    r = subprocess.run(['curl','-s', BASE+path],
        capture_output=True, text=True, timeout=10)
    return json.loads(r.stdout) if r.stdout.strip() else {}

def delete(path):
    subprocess.run(['curl','-s','-X','DELETE', BASE+path],
        capture_output=True, timeout=10)

PASS = 0; FAIL = 0

def check(label, got, ok_expected, val=None, err=None, errors=None):
    global PASS, FAIL
    ok = True; notes = []
    if got.get('success') != ok_expected:
        ok = False; notes.append('success=%s want %s' % (got.get('success'), ok_expected))
    if val is not None:
        rv = got.get('result'); v = rv.get('value') if isinstance(rv, dict) else rv
        if str(v) != str(val):
            ok = False; notes.append('val=%r want %r' % (v, val))
    if err:                         # check got['error']
        e = got.get('error') or ''
        if err not in e:
            ok = False; notes.append('error=%r missing %r' % (e[:60], err))
    if errors:                      # check got['errors'] list (compile responses)
        es = ' '.join(got.get('errors', []))
        if errors not in es:
            ok = False; notes.append('errors=%r missing %r' % (es[:80], errors))
    if ok: PASS += 1
    else:  FAIL += 1
    tag = 'PASS' if ok else 'FAIL'
    print('  [%s] %s' % (tag, label) + ('  -> ' + '; '.join(notes) if notes else ''))
    return ok

def run(sid, fn, args=[]):
    time.sleep(DELAY)
    return post('/session/run', {'session_id': sid, 'function': fn, 'args': args})

# ── Contract sources ──────────────────────────────────────────────────────────
SRC_T = (
    'pragma synq ^0.9;\n'
    'contract SimpleToken {\n'
    '  total: UInt256; owner: UInt256; paused: UInt256; initialised: UInt256;\n'
    '  function init() as caller {\n'
    '    require(initialised == 0, "init: contract already initialised");\n'
    '    require(total == 0, "init: cannot reinitialise with live supply");\n'
    '    owner = caller; paused = 0; initialised = 1; return 1; }\n'
    '  function mint(amount: UInt256) as caller requires cap::Minter {\n'
    '    require(paused == 0, "mint: contract is paused");\n'
    '    total = total + amount; return total; }\n'
    '  function burn(amount: UInt256) as caller requires cap::Burner {\n'
    '    require(paused == 0, "burn: contract is paused");\n'
    '    require(total >= amount, "burn: amount exceeds current supply");\n'
    '    total = total - amount; return total; }\n'
    '  function assertBalance(expected: UInt256) {\n'
    '    require(total == expected, "assertBalance: token total out of sync with vault");\n'
    '    return total; }\n'
    '  function getTotal()  { return total; }\n'
    '  function getPaused() { return paused; }\n'
    '}'
)
SRC_V = (
    'pragma synq ^0.9;\n'
    'contract TokenVault {\n'
    '  active: UInt256; vaultOwner: UInt256; totalIn: UInt256; totalOut: UInt256;\n'
    '  function init() as caller {\n'
    '    require(active == 0, "TokenVault.init: already initialised");\n'
    '    vaultOwner = caller; active = 1; totalIn = 0; totalOut = 0;\n'
    '    extern_call("SimpleToken", "init"); return 1; }\n'
    '  function deposit(amount: UInt256) as caller {\n'
    '    require(active == 1, "TokenVault.deposit: vault not active");\n'
    '    require(amount > 0, "TokenVault.deposit: amount must be > 0");\n'
    '    extern_call("SimpleToken", "mint", amount);\n'
    '    totalIn = totalIn + amount; return totalIn - totalOut; }\n'
    '  function withdraw(amount: UInt256) as caller requires cap::Withdrawer {\n'
    '    require(active == 1, "TokenVault.withdraw: vault not active");\n'
    '    require(caller == vaultOwner, "TokenVault.withdraw: caller is not vault owner");\n'
    '    require(amount > 0, "TokenVault.withdraw: amount must be > 0");\n'
    '    require(totalIn >= totalOut + amount, "TokenVault.withdraw: amount exceeds available balance");\n'
    '    extern_call("SimpleToken", "burn", amount);\n'
    '    totalOut = totalOut + amount; return totalIn - totalOut; }\n'
    '  function assertSync() as caller {\n'
    '    require(totalIn >= totalOut, "assertSync: totalOut exceeds totalIn");\n'
    '    extern_call("SimpleToken", "assertBalance", totalIn - totalOut); return 1; }\n'
    '  function balance()     { require(totalIn >= totalOut, "balance: underflow"); return totalIn - totalOut; }\n'
    '  function getTotalIn()  { return totalIn; }\n'
    '  function getTotalOut() { return totalOut; }\n'
    '}'
)

# ── T0: auth prologue (UMA_ANON fix) ─────────────────────────────────────────
print('\n=== T0: auth prologue — UMA_ANON sentinel ===')
src_t0 = 'pragma synq ^0.9; contract T { function f() as caller { return 1; } }'
d0 = post('/compile', {'source': src_t0}); time.sleep(DELAY)
s0 = post('/session/new', {'bytecode': d0['bytecode'], 'state_vars': [], 'contract_name': 'T'})
time.sleep(DELAY)
r0 = post('/session/run', {'session_id': s0['session_id'], 'function': 'f', 'args': []})
check('f() no-auth -> rejected (unauthenticated)', r0, False, err='unauthenticated')

# ── Compile both contracts ────────────────────────────────────────────────────
print('\n=== Compile ===')
time.sleep(2); cd_t = post('/compile', {'source': SRC_T})
time.sleep(2); cd_v = post('/compile', {'source': SRC_V})
check('SimpleToken compiles',                  cd_t, True)
check('TokenVault  compiles',                  cd_v, True)
check('TV extern_contracts == [SimpleToken]',
      {'success': cd_v.get('extern_contracts') == ['SimpleToken']}, True)
if not (cd_t.get('success') and cd_v.get('success')):
    print('  FATAL: compile failed'); exit(1)

# ── Create workspace + sessions ───────────────────────────────────────────────
print('\n=== Workspace + Sessions ===')
wid = post('/workspace/new', {}).get('workspace_id', '')
time.sleep(2)
sd_t = post('/session/new', {'bytecode': cd_t['bytecode'],
    'state_vars': cd_t.get('state_vars', []),
    'contract_name': 'SimpleToken', 'workspace_id': wid})
time.sleep(1)
sd_v = post('/session/new', {'bytecode': cd_v['bytecode'],
    'state_vars': cd_v.get('state_vars', []),
    'contract_name': 'TokenVault',  'workspace_id': wid})
time.sleep(1)
check('SimpleToken session created', sd_t, True)
check('TokenVault  session created', sd_v, True)
sid_t = sd_t.get('session_id', ''); sid_v = sd_v.get('session_id', '')

ws = get('/workspace/%s' % wid)
names = [c['name'] for c in ws.get('contracts', [])]
print('  workspace contracts:', names)
check('workspace lists SimpleToken', {'success': 'SimpleToken' in names}, True)
check('workspace lists TokenVault',  {'success': 'TokenVault'  in names}, True)
di   = {c['name']: c['deploy_index'] for c in ws.get('contracts', [])}
check('SimpleToken deploy_index == 0', {'success': di.get('SimpleToken') == 0}, True)
check('TokenVault  deploy_index == 1', {'success': di.get('TokenVault')  == 1}, True)

# ── T1: pre-init baseline ─────────────────────────────────────────────────────
print('\n=== T1: pre-init baseline ===')
check('ST.getTotal()  == 0', run(sid_t, 'getTotal'),   True, 0)
check('TV.getTotalIn()== 0', run(sid_v, 'getTotalIn'), True, 0)
check('TV.balance()   == 0', run(sid_v, 'balance'),    True, 0)

# ── T2: auth guards (all as-caller fns reject anonymous calls) ────────────────
print('\n=== T2: auth guards ===')
check('TV.init()       no-auth -> unauthenticated', run(sid_v,'init'),         False, err='unauthenticated')
check('TV.deposit(5)   no-auth -> unauthenticated', run(sid_v,'deposit',[5]),  False, err='unauthenticated')
check('TV.withdraw(1)  no-auth -> unauthenticated', run(sid_v,'withdraw',[1]), False, err='unauthenticated')
check('TV.assertSync() no-auth -> unauthenticated', run(sid_v,'assertSync'),   False, err='unauthenticated')
check('ST.init()       no-auth -> unauthenticated', run(sid_t,'init'),         False, err='unauthenticated')
check('ST.mint(1)      no-auth -> unauthenticated', run(sid_t,'mint',[1]),     False, err='unauthenticated')
check('ST.burn(1)      no-auth -> unauthenticated', run(sid_t,'burn',[1]),     False, err='unauthenticated')

# ── T3: assertBalance (the key regression test) ───────────────────────────────
print('\n=== T3: assertBalance consistency ===')
check('ST.assertBalance(0) passes',       run(sid_t,'assertBalance',[0]),  True,  0)
check('ST.assertBalance(1) fails',        run(sid_t,'assertBalance',[1]),  False, err='out of sync')
check('ST.assertBalance(0) after fail',   run(sid_t,'assertBalance',[0]),  True,  0)
check('ST.assertBalance(999) fails',      run(sid_t,'assertBalance',[999]),False, err='out of sync')
check('ST.assertBalance(0) still clean',  run(sid_t,'assertBalance',[0]),  True,  0)

# ── T4: anonymous read-only fns still work ────────────────────────────────────
print('\n=== T4: anonymous reads ===')
check('ST.getTotal()   == 0', run(sid_t,'getTotal'),   True, 0)
check('TV.getTotalOut()== 0', run(sid_v,'getTotalOut'),True, 0)
check('TV.balance()    == 0', run(sid_v,'balance'),    True, 0)

# ── T5: state unchanged after all auth / require failures ─────────────────────
print('\n=== T5: state integrity after failures ===')
check('ST.getTotal()   still 0', run(sid_t,'getTotal'),   True, 0)
check('TV.getTotalIn() still 0', run(sid_v,'getTotalIn'), True, 0)

# ── T6: tamper detection ──────────────────────────────────────────────────────
print('\n=== T6: tamper detection ===')
time.sleep(3)
tamper = post('/compile', {'source': SRC_V, 'wasm_extern_contracts': ['MaliciousContract']})
check('tamper: wrong deps -> rejected',        tamper, False, errors='Tamper detected')
time.sleep(2)
clean  = post('/compile', {'source': SRC_V, 'wasm_extern_contracts': ['SimpleToken']})
check('clean: correct deps -> accepted',       clean,  True)
time.sleep(2)
empty_match = post('/compile', {'source': SRC_T, 'wasm_extern_contracts': []})
check('clean: ST no deps []  -> accepted',     empty_match, True)

# ── T7: duplicate-name compile rejection ─────────────────────────────────────
print('\n=== T7: compile-time duplicate-name rejection ===')
time.sleep(2)
dup = post('/compile', {'source':
    'pragma synq ^0.9; contract D { x: UInt256; x: UInt256; function f() { return x; } }'})
check('duplicate field -> compile error', dup, False)
time.sleep(2)
dup2 = post('/compile', {'source':
    'pragma synq ^0.9; contract D { function f() { return 1; } function f() { return 2; } }'})
check('duplicate fn    -> compile error', dup2, False)

# ── T8: source guard shape in contracts ──────────────────────────────────────
print('\n=== T8: contract source invariants ===')
has_init_guard = ('require(initialised == 0' in SRC_T and 'require(total == 0' in SRC_T)
check('ST: both init guards present',          {'success': has_init_guard}, True)
has_burn_guard = 'require(total >= amount' in SRC_T
check('ST: burn underflow guard present',      {'success': has_burn_guard}, True)
has_bal_guard  = 'require(totalIn >= totalOut + amount' in SRC_V
check('TV: withdraw balance guard present',    {'success': has_bal_guard},  True)

print('\n' + '='*54)
print('  PASSED: %d   FAILED: %d   TOTAL: %d' % (PASS, FAIL, PASS+FAIL))
print('='*54)

delete('/session/%s' % sid_t)
delete('/session/%s' % sid_v)
delete('/workspace/%s' % wid)
