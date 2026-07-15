# Validator Appliance Recovery Status

generated_utc: 2026-07-04T10:08:35Z
phase: status
execute: false

spreadsheet_row_used=true row=16 node=Val2 ssh='ssh synergy-val2' user='rob' public_ip='62.146.182.208' qrpc='5640' ws='5660' metrics='6030'
## Remote Validator Status

generated_utc: 2026-07-04T10:08:38Z
hostname: vmi3226972.contaboserver.net
runtime_root: /var/lib/synergy/validator
config_path: /etc/synergy/validator/config.toml
cli_binary: /opt/synergy/bin/synergy-node
runtime_binary: /opt/synergy/bin/synergy-validator
service_execstart: { path=/opt/synergy/bin/synergy-validator ; argv[]=/opt/synergy/bin/synergy-validator start --config /etc/synergy/validator/config.toml ; ignore_errors=no ; start_time=[Sat 2026-07-04 04:53:13 CEST] ; stop_time=[n/a] ; pid=1245680 ; code=(null) ; status=0/0 }

### Service

~~~text
state=active
show=1245680|active|running|
~~~

### qRPC

~~~json
{
  "health": {"elapsed_sec": 6.049, "error": "timed out"},
  "latest": {"elapsed_sec": 6.053, "error": "timed out"},
  "block_number": {"elapsed_sec": 6.046, "error": "timed out"},
  "canonical_lock": {"elapsed_sec": 0.081, "response": {"id": 1, "jsonrpc": "2.0", "result": {"block_hash": "d736f234b2f1e7c524a20aa9787f48c3dd33b7c8fb703ab7edd73b8404d4ebef", "chain": {"chain_id": 1264, "chain_id_hex": "0x4f0", "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "name": "synergy-testnet-v2", "network_id": "synergy-testnet-v2"}, "found": true, "height": 760986, "parent_hash": "a77d4b894e284c4705620e377b2c37838ed2ee37429d019637470b9e93344936", "qc_block_hash": "d736f234b2f1e7c524a20aa9787f48c3dd33b7c8fb703ab7edd73b8404d4ebef", "qc_hash": "97b7d21037d78e40e3bd07d05f07a6536584a7934ad08c09f2a9d9bb3aecd86e", "transactions_root": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "validator_id": "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt", "written_at_unix_secs": 1783119175}}},
  "node_status": {"elapsed_sec": 6.05, "error": "timed out"},
  "peer_info": {"elapsed_sec": 0.058, "response": {"id": 1, "jsonrpc": "2.0", "result": {"peer_count": 8, "peers": [{"address": "73.79.66.255:57738", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783155413, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783159742, "node_id": "archive-validator-01", "public_address": "archive.synergynode.xyz:5615", "txs_received": 0, "txs_sent": 0, "validator_address": "archive-validator-01", "version": "1.0.0"}, {"address": "62.146.182.209:47878", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783155265, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783159737, "node_id": "genesisval3", "public_address": "62.146.182.209:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re", "version": "1.0.0"}, {"address": "relay1.synergynode.xyz:5622", "blocks_received": 0, "blocks_sent": 263, "capabilities": ["blocks", "transactions"], "connected_at": 1783133621, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783159742, "node_id": "sentry1", "public_address": "195.26.241.95:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv21ga3nsdjagzt9pmks4mzjq4vdjyngdwq6jst632", "version": "1.0.0"}, {"address": "146.190.210.121:38330", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783159723, "genesis_hash": "", "last_seen": 1783159723, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "bootnode1.synergynode.xyz:5620", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783155085, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783155158, "node_id": "bootnode1", "public_address": "bootnode1.synergynode.xyz:5620", "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": "1.0.0"}, {"address": "146.190.210.121:60776", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783159709, "genesis_hash": "", "last_seen": 1783159709, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "157.173.192.45:44732", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783155406, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783159706, "node_id": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "public_address": "157.173.192.45:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "version": "1.0.0"}, {"address": "209.145.50.9:5622", "blocks_received": 0, "blocks_sent": 521, "capabilities": ["blocks", "transactions"], "connected_at": 1783133623, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783159730, "node_id": "observer", "public_address": "209.145.50.9:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv51q8t3jqkt6e0y6kdppwu0dskxuarqg3pquga6n7", "version": "1.0.0"}, {"address": "157.245.226.240:47200", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783159723, "genesis_hash": "", "last_seen": 1783159723, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "157.173.192.45:5622", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783133623, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783147613, "node_id": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "public_address": "157.173.192.45:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "version": "1.0.0"}, {"address": "relay2.synergynode.xyz:5622", "blocks_received": 0, "blocks_sent": 252, "capabilities": ["blocks", "transactions"], "connected_at": 1783133623, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783159743, "node_id": "sentry2", "public_address": "94.72.117.108:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv21xaqlq808sunuchd0jwr4m324h85fza2ps3s4k7", "version": "1.0.0"}, {"address": "170.64.187.206:53124", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783155125, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783155158, "node_id": "bootnode1", "public_address": "bootnode1.synergynode.xyz:5620", "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": "1.0.0"}, {"address": "194.163.183.166:5622", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783159675, "genesis_hash": "", "last_seen": 1783159706, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "109.199.104.37:43688", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783155404, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783159742, "node_id": "synv11um0ddw94q7rph09ymd88dr8hhzmufnwtslz", "public_address": "109.199.104.37:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11um0ddw94q7rph09ymd88dr8hhzmufnwtslz", "version": "1.0.0"}, {"address": "73.79.66.255:5622", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783159675, "genesis_hash": "", "last_seen": 1783159742, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}]}}}
}
~~~

### Listeners

~~~text
LISTEN 0      128          0.0.0.0:5640       0.0.0.0:*    users:(("synergy-validat",pid=1245680,fd=10))
LISTEN 0      128          0.0.0.0:5660       0.0.0.0:*    users:(("synergy-validat",pid=1245680,fd=105))
LISTEN 0      128          0.0.0.0:6030       0.0.0.0:*    users:(("synergy-validat",pid=1245680,fd=102))
LISTEN 0      128          0.0.0.0:5622       0.0.0.0:*    users:(("synergy-validat",pid=1245680,fd=4))
~~~

### Process

~~~text
main_pid=1245680
    PID    PPID STAT     ELAPSED %CPU %MEM   RSS    VSZ COMMAND         COMMAND
1245680       1 Ssl     07:15:50  103  6.7 1667356 5424964 synergy-validat /opt/synergy/bin/synergy-validator start --config /etc/synergy/validator/config.toml
--- threads ---
    PID     TID STAT %CPU COMMAND
1245680 1245680 Ssl   0.1 synergy-validat
1245680 1245738 Ssl   0.0 p2p-listener
1245680 1245739 Rsl  99.1 p2p-message-han
1245680 1245740 Ssl   0.0 p2p-bootstrap
1245680 1245742 Ssl   0.0 synergy-validat
1245680 1245767 Ssl   0.1 p2p-connect-pee
1245680 1245769 Ssl   0.0 p2p-connect-pee
1245680 1245777 Ssl   0.0 p2p-connect-pee
1245680 1245778 Ssl   0.0 p2p-connect-pee
1245680 1245795 Ssl   0.0 synergy-validat
1245680 1245807 Ssl   0.0 synergy-validat
1245680 1246035 Ssl   0.0 ctrl-c
1245680 1246430 Ssl   0.0 posy-consensus
1245680 1291223 Ssl   0.0 p2p-connect-pee
1245680 1291296 Ssl   0.0 p2p-accept-peer
1245680 1291529 Ssl   0.0 p2p-accept-peer
1245680 1291761 Ssl   0.0 p2p-accept-peer
1245680 1291767 Ssl   0.1 p2p-accept-peer
1245680 1291788 Ssl   0.0 p2p-accept-peer
1245680 1303233 Ssl   0.0 p2p-connect-pee
1245680 1303235 Ssl   0.1 p2p-connect-pee
1245680 1303301 Ssl   0.2 p2p-accept-peer
1245680 1303419 Ssl   0.1 p2p-accept-peer
1245680 1303422 Ssl   0.3 p2p-accept-peer
1245680 1303444 Rsl  93.0 synergy-validat
1245680 1303454 Ssl   0.0 synergy-validat
1245680 1303483 Ssl  50.0 p2p-accept-peer
--- fd-count ---
0
--- service-show ---
Restart=on-failure
RestartUSec=5s
MainPID=1245680
ExecMainStartTimestamp=Sat 2026-07-04 04:53:13 CEST
ExecMainPID=1245680
MemoryCurrent=7265148928
CPUUsageNSec=27158278547000
User=node
Group=node
~~~

### Recent Service Logs

~~~text
Jul 04 12:07:55 vmi3226972 synergy-validator[1245680]:   "error": "Broken pipe (os error 32)",
Jul 04 12:07:55 vmi3226972 synergy-validator[1245680]:   "peer": "157.245.226.240:52958"
Jul 04 12:07:55 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:07:55 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:07:55 UTC] [WARN] [p2p] Failed to request status
Jul 04 12:07:55 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:07:55 vmi3226972 synergy-validator[1245680]:   "error": "Broken pipe (os error 32)",
Jul 04 12:07:55 vmi3226972 synergy-validator[1245680]:   "peer": "157.245.226.240:52946"
Jul 04 12:07:55 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:00 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:00 UTC] [WARN] [p2p] Failed to dial peer
Jul 04 12:08:00 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:00 vmi3226972 synergy-validator[1245680]:   "error": "connection timed out",
Jul 04 12:08:00 vmi3226972 synergy-validator[1245680]:   "peer": "seed1.synergynode.xyz:5621"
Jul 04 12:08:00 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:03 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:03 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:08:03 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:03 vmi3226972 synergy-validator[1245680]:   "peer": "157.245.226.240:52966"
Jul 04 12:08:03 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:07 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:07 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:08:07 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:07 vmi3226972 synergy-validator[1245680]:   "peer": "146.190.210.121:43098"
Jul 04 12:08:07 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:23 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:23 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:08:23 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:23 vmi3226972 synergy-validator[1245680]:   "peer": "157.245.226.240:45738"
Jul 04 12:08:23 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:26 UTC] [INFO] [p2p] Received vote request
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "epoch": 760,
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "height": 760987,
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "peer": "157.173.192.45:44732",
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "round": 2158
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:26 UTC] [DEBUG] [consensus] Ignoring local wall-clock view offset for canonical leader selection
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "block_height": 760987,
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "calculated_view_offset": 3689,
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "canonical_view_offset": 0
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:26 UTC] [INFO] [consensus] Selected leader for block
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "block_height": 760987,
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "block_in_epoch": 987,
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "epoch": 760,
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "leader": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "rotation_index": 3,
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "view_offset": 0
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: 🏆 [select_leader_for_block] Selected leader for block 760987 (epoch 760, block_in_epoch 987, rotation_index 3): synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:26 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "peer": "146.190.210.121:55298"
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:26 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "peer": "157.245.226.240:55492"
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:26 UTC] [WARN] [p2p] Failed to proactively send status after handshake
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "error": "Broken pipe (os error 32)",
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "peer": "146.190.210.121:55310"
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:26 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "peer": "146.190.210.121:55310"
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:26 UTC] [WARN] [p2p] Failed to proactively send status after handshake
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "error": "Broken pipe (os error 32)",
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "peer": "157.245.226.240:52958"
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:26 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "peer": "157.245.226.240:52958"
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:26 UTC] [WARN] [p2p] Failed to proactively send status after handshake
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "error": "Broken pipe (os error 32)",
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "peer": "157.245.226.240:52946"
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:26 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "peer": "157.245.226.240:52946"
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: ❌ Failed to ping 146.190.210.121:55314: Broken pipe (os error 32)
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:26 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "peer": "bootnode2.synergynode.xyz:5620"
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:26 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "peer": "bootnode3.synergynode.xyz:5620"
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:26 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "peer": "157.245.226.240:52966"
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:26 UTC] [WARN] [p2p] Failed to proactively send status after handshake
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "error": "Broken pipe (os error 32)",
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "peer": "146.190.210.121:55314"
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:26 UTC] [DEBUG] [p2p] Serving block sync response
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "count": 51,
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "from_height": 756248,
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "host": "209.145.50.9",
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "max_blocks": 64,
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "peer": "209.145.50.9:5622"
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:26 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "peer": "146.190.210.121:55314"
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:26 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "peer": "146.190.210.121:43098"
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:26 UTC] [INFO] [p2p] Vote sent
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "epoch": 760,
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "height": 760987,
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "request_peer": "157.173.192.45:44732",
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "response_peer": "157.173.192.45:44732",
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]:   "round": 2158
Jul 04 12:08:26 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:27 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "connected_age_secs": 40,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "direction": "Incoming",
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "has_identifying_metadata": false,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "has_remote_status": false,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "last_seen_age_secs": 0,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "peer": "62.146.182.207:38574",
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "validator_address": ""
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:27 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "connected_age_secs": 59,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "direction": "Incoming",
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "has_identifying_metadata": true,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "has_remote_status": false,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "last_seen_age_secs": 16,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "peer": "194.163.183.166:33456",
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "validator_address": ""
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:27 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "connected_age_secs": 32,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "direction": "Outgoing",
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "has_identifying_metadata": false,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "has_remote_status": false,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "last_seen_age_secs": 1,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "peer": "rpc.synergynode.xyz:5623",
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "validator_address": ""
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:27 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "connected_age_secs": 32,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "direction": "Outgoing",
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "has_identifying_metadata": false,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "has_remote_status": false,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "last_seen_age_secs": 0,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "peer": "62.146.182.207:5622",
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "validator_address": ""
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:27 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "connected_age_secs": 32,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "direction": "Outgoing",
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "has_identifying_metadata": false,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "has_remote_status": false,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "last_seen_age_secs": 32,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "peer": "seed3.synergynode.xyz:5621",
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "validator_address": ""
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:27 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "connected_age_secs": 32,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "direction": "Outgoing",
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "has_identifying_metadata": false,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "has_remote_status": false,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "last_seen_age_secs": 32,
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "peer": "seed2.synergynode.xyz:5621",
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]:   "validator_address": ""
Jul 04 12:08:27 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:29 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:29 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:08:29 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:29 vmi3226972 synergy-validator[1245680]:   "peer": "146.190.210.121:60776"
Jul 04 12:08:29 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:32 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:32 UTC] [WARN] [p2p] Failed to dial peer
Jul 04 12:08:32 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:32 vmi3226972 synergy-validator[1245680]:   "error": "connection timed out",
Jul 04 12:08:32 vmi3226972 synergy-validator[1245680]:   "peer": "seed1.synergynode.xyz:5621"
Jul 04 12:08:32 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:33 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:33 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:33 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:33 vmi3226972 synergy-validator[1245680]:   "peer": "157.245.226.240:45738"
Jul 04 12:08:33 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:43 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:43 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:08:43 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:43 vmi3226972 synergy-validator[1245680]:   "peer": "146.190.210.121:38330"
Jul 04 12:08:43 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:43 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:43 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:08:43 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:43 vmi3226972 synergy-validator[1245680]:   "peer": "157.245.226.240:47200"
Jul 04 12:08:43 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:54 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:54 UTC] [WARN] [rpc] qRPC served read from fallback state
Jul 04 12:08:54 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:54 vmi3226972 synergy-validator[1245680]:   "reason": "chain_tip_lock_unavailable"
Jul 04 12:08:54 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:08:59 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:08:59 UTC] [WARN] [rpc] qRPC served read from fallback state
Jul 04 12:08:59 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:08:59 vmi3226972 synergy-validator[1245680]:   "reason": "chain_tip_lock_unavailable"
Jul 04 12:08:59 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:09:03 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:09:03 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:09:03 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:09:03 vmi3226972 synergy-validator[1245680]:   "peer": "146.190.210.121:40658"
Jul 04 12:09:03 vmi3226972 synergy-validator[1245680]: }
~~~

### Runtime Recovery Status

#### quarantine-status

~~~json
{
  "chain": {
    "chain_id": 1264,
    "chain_id_hex": "0x4f0",
    "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789",
    "network_id": "synergy-testnet-v2"
  },
  "duty_gate": {
    "can_aggregate_qc": true,
    "can_count_toward_quorum": true,
    "can_enter_proposer_schedule": true,
    "can_propose": true,
    "can_serve_as_canonical_source": true,
    "can_vote": true,
    "shadow_signs_real_votes": false,
    "state": "ACTIVE"
  },
  "marker_paths": [],
  "quarantined": false,
  "recovery_state": "ACTIVE",
  "rejoin_eligibility": false,
  "status": "healthy"
}
~~~

#### self-heal-status

~~~json
{
  "chain": {
    "chain_id": 1264,
    "chain_id_hex": "0x4f0",
    "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789",
    "network_id": "synergy-testnet-v2"
  },
  "fail_closed": true,
  "lifecycle": [
    "ACTIVE",
    "SUSPECT",
    "QUARANTINED",
    "HEALING",
    "SYNCING",
    "VOTE_ONLY",
    "ACTIVE"
  ],
  "manual_state_surgery_allowed": false,
  "quarantine": {
    "chain": {
      "chain_id": 1264,
      "chain_id_hex": "0x4f0",
      "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789",
      "network_id": "synergy-testnet-v2"
    },
    "duty_gate": {
      "can_aggregate_qc": true,
      "can_count_toward_quorum": true,
      "can_enter_proposer_schedule": true,
      "can_propose": true,
      "can_serve_as_canonical_source": true,
      "can_vote": true,
      "shadow_signs_real_votes": false,
      "state": "ACTIVE"
    },
    "marker_paths": [],
    "quarantined": false,
    "recovery_state": "ACTIVE",
    "rejoin_eligibility": false,
    "status": "healthy"
  },
  "snapshot_schedule": {
    "interval_finalized_blocks": 5000,
    "interval_seconds": 900,
    "retain_last": 2
  },
  "status": "ACTIVE",
  "vote_only_probation_blocks": 1000,
  "vote_only_rejoin_enabled": true
}
~~~

#### snapshots

~~~json
{
  "chain": {
    "chain_id": 1264,
    "chain_id_hex": "0x4f0",
    "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789",
    "network_id": "synergy-testnet-v2"
  },
  "schedule": {
    "interval_finalized_blocks": 5000,
    "interval_seconds": 900,
    "retain_last": 2
  },
  "snapshot_root": "/var/lib/synergy/validator/data/snapshots",
  "snapshots": []
}
~~~

### Snapshot Manifests

~~~text
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783116639-1783116639790372449-proposals-above-760985/manifest.json	1120 bytes	2026-07-04T00:10:39.7983230750Z
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783117343-1783117343964463297-proposals-above-760985/manifest.json	1120 bytes	2026-07-04T00:22:23.9672072480Z
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783118737-1783118737227786319-proposals-above-760985/manifest.json	1120 bytes	2026-07-04T00:45:37.2276278910Z
~~~
