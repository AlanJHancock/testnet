# Validator Appliance Recovery Status

generated_utc: 2026-07-04T10:08:11Z
phase: status
execute: false

spreadsheet_row_used=true row=15 node=Val1 ssh='ssh synergy-val1' user='justin' public_ip='62.146.182.207' qrpc='5640' ws='5660' metrics='6030'
## Remote Validator Status

generated_utc: 2026-07-04T10:08:14Z
hostname: vmi3226971.contaboserver.net
runtime_root: /var/lib/synergy/validator
config_path: /etc/synergy/validator/config.toml
cli_binary: /opt/synergy/bin/synergy-node
runtime_binary: /opt/synergy/bin/synergy-validator
service_execstart: { path=/opt/synergy/bin/synergy-validator ; argv[]=/opt/synergy/bin/synergy-validator start --config /etc/synergy/validator/config.toml ; ignore_errors=no ; start_time=[Sat 2026-07-04 04:52:27 CEST] ; stop_time=[n/a] ; pid=2607566 ; code=(null) ; status=0/0 }

### Service

~~~text
state=active
show=2607566|active|running|
~~~

### qRPC

~~~json
{
  "health": {"elapsed_sec": 6.058, "error": "timed out"},
  "latest": {"elapsed_sec": 6.053, "error": "timed out"},
  "block_number": {"elapsed_sec": 0.226, "response": {"id": 1, "jsonrpc": "2.0", "result": 760986}},
  "canonical_lock": {"elapsed_sec": 0.06, "response": {"id": 1, "jsonrpc": "2.0", "result": {"block_hash": "d736f234b2f1e7c524a20aa9787f48c3dd33b7c8fb703ab7edd73b8404d4ebef", "chain": {"chain_id": 1264, "chain_id_hex": "0x4f0", "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "name": "synergy-testnet-v2", "network_id": "synergy-testnet-v2"}, "found": true, "height": 760986, "parent_hash": "a77d4b894e284c4705620e377b2c37838ed2ee37429d019637470b9e93344936", "qc_block_hash": "d736f234b2f1e7c524a20aa9787f48c3dd33b7c8fb703ab7edd73b8404d4ebef", "qc_hash": "97b7d21037d78e40e3bd07d05f07a6536584a7934ad08c09f2a9d9bb3aecd86e", "transactions_root": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "validator_id": "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt", "written_at_unix_secs": 1783119184}}},
  "node_status": {"elapsed_sec": 6.06, "error": "timed out"},
  "peer_info": {"elapsed_sec": 0.044, "response": {"id": 1, "jsonrpc": "2.0", "result": {"peer_count": 7, "peers": [{"address": "73.79.66.255:54582", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783154116, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783159713, "node_id": "archive-validator-01", "public_address": "archive.synergynode.xyz:5615", "txs_received": 0, "txs_sent": 0, "validator_address": "archive-validator-01", "version": "1.0.0"}, {"address": "157.173.192.45:44780", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783154111, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783159707, "node_id": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "public_address": "157.173.192.45:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "version": "1.0.0"}, {"address": "194.163.183.166:59072", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783159691, "genesis_hash": "", "last_seen": 1783159707, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "209.145.50.9:5622", "blocks_received": 0, "blocks_sent": 529, "capabilities": ["blocks", "transactions"], "connected_at": 1783133577, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783159708, "node_id": "observer", "public_address": "209.145.50.9:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv51q8t3jqkt6e0y6kdppwu0dskxuarqg3pquga6n7", "version": "1.0.0"}, {"address": "relay2.synergynode.xyz:5622", "blocks_received": 0, "blocks_sent": 245, "capabilities": ["blocks", "transactions"], "connected_at": 1783133577, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783159713, "node_id": "sentry2", "public_address": "94.72.117.108:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv21xaqlq808sunuchd0jwr4m324h85fza2ps3s4k7", "version": "1.0.0"}, {"address": "194.163.183.166:5622", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783159708, "genesis_hash": "", "last_seen": 1783159708, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "seed2.synergynode.xyz:5621", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783159708, "genesis_hash": "", "last_seen": 1783159708, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "rpc.synergynode.xyz:5623", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783159708, "genesis_hash": "", "last_seen": 1783159708, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "relay1.synergynode.xyz:5622", "blocks_received": 0, "blocks_sent": 280, "capabilities": ["blocks", "transactions"], "connected_at": 1783133574, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783159713, "node_id": "sentry1", "public_address": "195.26.241.95:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv21ga3nsdjagzt9pmks4mzjq4vdjyngdwq6jst632", "version": "1.0.0"}, {"address": "157.173.192.45:5622", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783133577, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783140922, "node_id": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "public_address": "157.173.192.45:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "version": "1.0.0"}, {"address": "109.199.104.37:33284", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783154112, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783159713, "node_id": "synv11um0ddw94q7rph09ymd88dr8hhzmufnwtslz", "public_address": "109.199.104.37:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11um0ddw94q7rph09ymd88dr8hhzmufnwtslz", "version": "1.0.0"}, {"address": "seed3.synergynode.xyz:5621", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783159708, "genesis_hash": "", "last_seen": 1783159708, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "73.79.66.255:5622", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783159667, "genesis_hash": "", "last_seen": 1783159711, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}]}}}
}
~~~

### Listeners

~~~text
LISTEN 0      128          0.0.0.0:5640       0.0.0.0:*    users:(("synergy-validat",pid=2607566,fd=9))
LISTEN 0      128          0.0.0.0:5660       0.0.0.0:*    users:(("synergy-validat",pid=2607566,fd=66))
LISTEN 0      128          0.0.0.0:6030       0.0.0.0:*    users:(("synergy-validat",pid=2607566,fd=11))
LISTEN 0      128          0.0.0.0:5622       0.0.0.0:*    users:(("synergy-validat",pid=2607566,fd=3))
~~~

### Process

~~~text
main_pid=2607566
    PID    PPID STAT     ELAPSED %CPU %MEM   RSS    VSZ COMMAND         COMMAND
2607566       1 Ssl     07:16:06  103  6.3 1561840 5355300 synergy-validat /opt/synergy/bin/synergy-validator start --config /etc/synergy/validator/config.toml
--- threads ---
    PID     TID STAT %CPU COMMAND
2607566 2607566 Ssl   0.1 synergy-validat
2607566 2607610 Ssl   0.0 p2p-listener
2607566 2607611 Rsl  99.6 p2p-message-han
2607566 2607612 Ssl   0.0 p2p-bootstrap
2607566 2607613 Ssl   0.0 synergy-validat
2607566 2607645 Ssl   0.0 p2p-connect-pee
2607566 2607647 Ssl   0.0 p2p-connect-pee
2607566 2607654 Ssl   0.0 p2p-connect-pee
2607566 2607655 Ssl   0.0 p2p-connect-pee
2607566 2607666 Ssl   0.0 synergy-validat
2607566 2607671 Ssl   0.0 synergy-validat
2607566 2607822 Ssl   0.0 ctrl-c
2607566 2607922 Ssl   0.0 posy-consensus
2607566 2646183 Ssl   0.1 p2p-accept-peer
2607566 2646189 Ssl   0.0 p2p-accept-peer
2607566 2646202 Ssl   0.0 p2p-accept-peer
2607566 2658648 Ssl   0.1 p2p-connect-pee
2607566 2658677 Ssl   0.3 p2p-accept-peer
2607566 2658858 Rsl  92.8 synergy-validat
2607566 2658873 Ssl   0.0 synergy-validat
2607566 2658875 Ssl   1.5 p2p-connect-pee
2607566 2658877 Ssl   2.5 p2p-connect-pee
2607566 2658879 Ssl   1.7 p2p-connect-pee
2607566 2658880 Ssl   1.7 p2p-connect-pee
2607566 2658894 Ssl  68.4 p2p-accept-peer
--- fd-count ---
0
--- service-show ---
Restart=on-failure
RestartUSec=5s
MainPID=2607566
ExecMainStartTimestamp=Sat 2026-07-04 04:52:27 CEST
ExecMainPID=2607566
MemoryCurrent=7156248576
CPUUsageNSec=27181891525000
User=node
Group=node
~~~

### Recent Service Logs

~~~text
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]:   "error": "Broken pipe (os error 32)",
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]:   "peer": "157.245.226.240:44090"
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:07:47 UTC] [WARN] [p2p] Failed to request peers
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]:   "error": "Broken pipe (os error 32)",
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]:   "peer": "157.245.226.240:44078"
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:07:47 UTC] [WARN] [p2p] Failed to request peers
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]:   "error": "Broken pipe (os error 32)",
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]:   "peer": "146.190.210.121:37156"
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:07:47 UTC] [WARN] [p2p] Failed to request status
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]:   "error": "Broken pipe (os error 32)",
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]:   "peer": "157.245.226.240:44090"
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:07:47 UTC] [WARN] [p2p] Failed to request status
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]:   "error": "Broken pipe (os error 32)",
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]:   "peer": "157.245.226.240:44078"
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:07:47 UTC] [WARN] [p2p] Failed to request status
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]:   "error": "Broken pipe (os error 32)",
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]:   "peer": "146.190.210.121:37156"
Jul 04 12:07:47 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:07:52 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:07:52 UTC] [WARN] [p2p] Failed to dial peer
Jul 04 12:07:52 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:07:52 vmi3226971 synergy-validator[2607566]:   "error": "connection timed out",
Jul 04 12:07:52 vmi3226971 synergy-validator[2607566]:   "peer": "bootnode1.synergynode.xyz:5620"
Jul 04 12:07:52 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:07:52 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:07:52 UTC] [WARN] [p2p] Failed to dial peer
Jul 04 12:07:52 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:07:52 vmi3226971 synergy-validator[2607566]:   "error": "connection timed out",
Jul 04 12:07:52 vmi3226971 synergy-validator[2607566]:   "peer": "seed1.synergynode.xyz:5621"
Jul 04 12:07:52 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:07:53 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:07:53 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:07:53 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:07:53 vmi3226971 synergy-validator[2607566]:   "peer": "157.245.226.240:44098"
Jul 04 12:07:53 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:07:55 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:07:55 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:07:55 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:07:55 vmi3226971 synergy-validator[2607566]:   "peer": "62.146.182.208:35952"
Jul 04 12:07:55 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:07:57 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:07:57 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:07:57 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:07:57 vmi3226971 synergy-validator[2607566]:   "peer": "146.190.210.121:52650"
Jul 04 12:07:57 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:11 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:11 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:08:11 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:11 vmi3226971 synergy-validator[2607566]:   "peer": "194.163.183.166:59072"
Jul 04 12:08:11 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:13 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:13 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:08:13 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:13 vmi3226971 synergy-validator[2607566]:   "peer": "157.245.226.240:46076"
Jul 04 12:08:13 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:17 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:17 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:08:17 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:17 vmi3226971 synergy-validator[2607566]:   "peer": "146.190.210.121:56944"
Jul 04 12:08:17 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [INFO] [p2p] Received vote request
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "epoch": 760,
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "height": 760987,
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "peer": "157.173.192.45:44780",
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "round": 2115
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [DEBUG] [consensus] Ignoring local wall-clock view offset for canonical leader selection
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "block_height": 760987,
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "calculated_view_offset": 3696,
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "canonical_view_offset": 0
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [INFO] [consensus] Selected leader for block
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "block_height": 760987,
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "block_in_epoch": 987,
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "epoch": 760,
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "leader": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "rotation_index": 3,
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "view_offset": 0
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: 🏆 [select_leader_for_block] Selected leader for block 760987 (epoch 760, block_in_epoch 987, rotation_index 3): synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [WARN] [p2p] Failed to proactively send status after handshake
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "error": "Broken pipe (os error 32)",
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "peer": "146.190.210.121:37156"
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "peer": "146.190.210.121:37156"
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [WARN] [p2p] Failed to proactively send status after handshake
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "error": "Broken pipe (os error 32)",
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "peer": "157.245.226.240:44090"
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "peer": "157.245.226.240:44090"
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [WARN] [p2p] Failed to proactively send status after handshake
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "error": "Broken pipe (os error 32)",
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "peer": "157.245.226.240:44078"
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "peer": "157.245.226.240:44078"
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [WARN] [p2p] Failed to proactively send status after handshake
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "error": "Broken pipe (os error 32)",
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "peer": "146.190.210.121:37148"
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [WARN] [p2p] Failed to proactively send status after handshake
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "error": "Broken pipe (os error 32)",
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "peer": "146.190.210.121:55002"
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "peer": "146.190.210.121:37148"
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "peer": "146.190.210.121:55002"
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [INFO] [p2p] Vote sent
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "epoch": 760,
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "height": 760987,
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "request_peer": "157.173.192.45:44780",
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "response_peer": "157.173.192.45:44780",
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "round": 2115
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "peer": "62.146.182.209:5622"
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "peer": "bootnode2.synergynode.xyz:5620"
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "peer": "bootnode3.synergynode.xyz:5620"
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "peer": "157.245.226.240:44098"
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "peer": "146.190.210.121:52650"
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [INFO] [p2p] Received vote request
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "epoch": 760,
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "height": 760987,
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "peer": "157.173.192.45:44780",
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "round": 2116
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [DEBUG] [p2p] Serving block sync response
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "count": 51,
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "from_height": 756248,
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "host": "209.145.50.9",
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "max_blocks": 64,
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "peer": "209.145.50.9:5622"
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "peer": "157.245.226.240:46076"
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [INFO] [p2p] Vote sent
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "epoch": 760,
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "height": 760987,
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "request_peer": "157.173.192.45:44780",
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "response_peer": "157.173.192.45:44780",
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "round": 2116
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "peer": "62.146.182.208:5622"
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:27 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]:   "peer": "62.146.182.208:35952"
Jul 04 12:08:27 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:30 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:30 UTC] [WARN] [rpc] qRPC served read from fallback state
Jul 04 12:08:30 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:30 vmi3226971 synergy-validator[2607566]:   "reason": "chain_tip_lock_unavailable"
Jul 04 12:08:30 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:33 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:33 UTC] [WARN] [p2p] Failed to dial peer
Jul 04 12:08:33 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:33 vmi3226971 synergy-validator[2607566]:   "error": "connection timed out",
Jul 04 12:08:33 vmi3226971 synergy-validator[2607566]:   "peer": "bootnode1.synergynode.xyz:5620"
Jul 04 12:08:33 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:33 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:33 UTC] [WARN] [p2p] Failed to dial peer
Jul 04 12:08:33 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:33 vmi3226971 synergy-validator[2607566]:   "error": "connection timed out",
Jul 04 12:08:33 vmi3226971 synergy-validator[2607566]:   "peer": "seed1.synergynode.xyz:5621"
Jul 04 12:08:33 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:33 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:33 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:08:33 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:33 vmi3226971 synergy-validator[2607566]:   "peer": "146.190.210.121:56944"
Jul 04 12:08:33 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:08:33 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:08:33 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:08:33 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:08:33 vmi3226971 synergy-validator[2607566]:   "peer": "157.245.226.240:52736"
Jul 04 12:08:33 vmi3226971 synergy-validator[2607566]: }
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
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783116592-1783116592982392970-proposals-above-760985/manifest.json	1120 bytes	2026-07-04T00:09:52.9832127800Z
~~~
