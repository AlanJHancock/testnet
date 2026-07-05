# Validator Appliance Transient Vote Lock Recovery

generated_utc: 2026-07-04T10:11:03Z
phase: transient-lock-recovery
execute: false

spreadsheet_row_used=true row=17 node=Val3 ssh='ssh synergy-val3' user='rob' public_ip='62.146.182.209' qrpc='5640' ws='5660' metrics='6030'
## Transient Vote Lock Recovery Gate

~~~text
target_node=Val3
execute=false
finalized_height=760985
min_age_secs=30
service_state=active
runtime_root=/var/lib/synergy/validator
config_path=/etc/synergy/validator/config.toml
~~~

## Before Diagnosis

### diagnose-consensus-stall

~~~json
~~~

### diagnose-vote-locks

~~~json
{
  "chain": {
    "chain_id": 1264,
    "chain_id_hex": "0x4f0",
    "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789",
    "network_id": "synergy-testnet-v2"
  },
  "conflicting_heights_above_finalized": [],
  "finalized_height": 760985,
  "fresh_locks": [
    {
      "age_seconds": 19,
      "block_hash": "34b2225ef5704ca52daef2f1350952a2a613fee63bc9b11db7200dd9218fc938",
      "epoch": 760,
      "first_round": 11,
      "height": 760987,
      "latest_round": 2165,
      "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
      "validator_address": "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re"
    }
  ],
  "fresh_locks_above_finalized": 1,
  "locks": [
    {
      "age_seconds": 19,
      "block_hash": "34b2225ef5704ca52daef2f1350952a2a613fee63bc9b11db7200dd9218fc938",
      "epoch": 760,
      "first_round": 11,
      "height": 760987,
      "latest_round": 2165,
      "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
      "validator_address": "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re"
    }
  ],
  "locks_above_finalized": 1,
  "parse_error": null,
  "stale_conflicting_heights_above_finalized": [],
  "stale_locks": [],
  "stale_locks_above_finalized": 0,
  "stale_threshold_seconds": 30,
  "total_vote_locks": 969,
  "vote_lock_path": "/var/lib/synergy/validator/data/consensus_vote_locks.json"
}
~~~

### latest-before

~~~json
{"elapsed_sec": 6.052, "error": "timed out"}
~~~

## Supported Runtime Recovery

~~~json
{"ok":false,"dry_run":true,"would_run":"synergy-node recover-transient-vote-locks or synergy_recoverTransientVoteLocks","requires_execute":true,"finalized_height":760985,"min_age_secs":30}
~~~

## After Diagnosis

### diagnose-vote-locks-after

~~~json
{
  "chain": {
    "chain_id": 1264,
    "chain_id_hex": "0x4f0",
    "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789",
    "network_id": "synergy-testnet-v2"
  },
  "conflicting_heights_above_finalized": [],
  "finalized_height": 760985,
  "fresh_locks": [
    {
      "age_seconds": 26,
      "block_hash": "34b2225ef5704ca52daef2f1350952a2a613fee63bc9b11db7200dd9218fc938",
      "epoch": 760,
      "first_round": 11,
      "height": 760987,
      "latest_round": 2165,
      "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
      "validator_address": "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re"
    }
  ],
  "fresh_locks_above_finalized": 1,
  "locks": [
    {
      "age_seconds": 26,
      "block_hash": "34b2225ef5704ca52daef2f1350952a2a613fee63bc9b11db7200dd9218fc938",
      "epoch": 760,
      "first_round": 11,
      "height": 760987,
      "latest_round": 2165,
      "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
      "validator_address": "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re"
    }
  ],
  "locks_above_finalized": 1,
  "parse_error": null,
  "stale_conflicting_heights_above_finalized": [],
  "stale_locks": [],
  "stale_locks_above_finalized": 0,
  "stale_threshold_seconds": 30,
  "total_vote_locks": 969,
  "vote_lock_path": "/var/lib/synergy/validator/data/consensus_vote_locks.json"
}
~~~

### latest-after

~~~json
{"elapsed_sec": 6.049, "error": "timed out"}
~~~

## Remote Validator Status

generated_utc: 2026-07-04T10:12:03Z
hostname: vmi3226973.contaboserver.net
runtime_root: /var/lib/synergy/validator
config_path: /etc/synergy/validator/config.toml
cli_binary: /opt/synergy/bin/synergy-node
runtime_binary: /opt/synergy/bin/synergy-validator
service_execstart: { path=/opt/synergy/bin/synergy-validator ; argv[]=/opt/synergy/bin/synergy-validator start --config /etc/synergy/validator/config.toml ; ignore_errors=no ; start_time=[Sat 2026-07-04 04:53:58 CEST] ; stop_time=[n/a] ; pid=731466 ; code=(null) ; status=0/0 }

### Service

~~~text
state=active
show=731466|active|running|
~~~

### qRPC

~~~json
{
  "health": {"elapsed_sec": 6.052, "error": "timed out"},
  "latest": {"elapsed_sec": 6.052, "error": "timed out"},
  "block_number": {"elapsed_sec": 6.055, "error": "timed out"},
  "canonical_lock": {"elapsed_sec": 0.054, "response": {"id": 1, "jsonrpc": "2.0", "result": {"block_hash": "d736f234b2f1e7c524a20aa9787f48c3dd33b7c8fb703ab7edd73b8404d4ebef", "chain": {"chain_id": 1264, "chain_id_hex": "0x4f0", "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "name": "synergy-testnet-v2", "network_id": "synergy-testnet-v2"}, "found": true, "height": 760986, "parent_hash": "a77d4b894e284c4705620e377b2c37838ed2ee37429d019637470b9e93344936", "qc_block_hash": "d736f234b2f1e7c524a20aa9787f48c3dd33b7c8fb703ab7edd73b8404d4ebef", "qc_hash": "97b7d21037d78e40e3bd07d05f07a6536584a7934ad08c09f2a9d9bb3aecd86e", "transactions_root": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "validator_id": "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt", "written_at_unix_secs": 1783119216}}},
  "node_status": {"elapsed_sec": 6.045, "error": "timed out"},
  "peer_info": {"elapsed_sec": 0.055, "response": {"id": 1, "jsonrpc": "2.0", "result": {"peer_count": 6, "peers": [{"address": "62.146.182.207:37862", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783159908, "genesis_hash": "", "last_seen": 1783159941, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "73.79.66.255:50652", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783159902, "genesis_hash": "", "last_seen": 1783159941, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "157.173.192.45:5622", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783133668, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783136241, "node_id": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "public_address": "157.173.192.45:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "version": "1.0.0"}, {"address": "seed3.synergynode.xyz:5621", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783159892, "genesis_hash": "", "last_seen": 1783159892, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "relay1.synergynode.xyz:5622", "blocks_received": 0, "blocks_sent": 298, "capabilities": ["blocks", "transactions"], "connected_at": 1783133665, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783159948, "node_id": "sentry1", "public_address": "195.26.241.95:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv21ga3nsdjagzt9pmks4mzjq4vdjyngdwq6jst632", "version": "1.0.0"}, {"address": "seed2.synergynode.xyz:5621", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783159892, "genesis_hash": "", "last_seen": 1783159892, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "relay2.synergynode.xyz:5622", "blocks_received": 0, "blocks_sent": 279, "capabilities": ["blocks", "transactions"], "connected_at": 1783133668, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783159947, "node_id": "sentry2", "public_address": "94.72.117.108:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv21xaqlq808sunuchd0jwr4m324h85fza2ps3s4k7", "version": "1.0.0"}, {"address": "157.173.192.45:59642", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783155308, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783159941, "node_id": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "public_address": "157.173.192.45:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "version": "1.0.0"}, {"address": "209.145.50.9:5622", "blocks_received": 0, "blocks_sent": 521, "capabilities": ["blocks", "transactions"], "connected_at": 1783133668, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783159945, "node_id": "observer", "public_address": "209.145.50.9:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv51q8t3jqkt6e0y6kdppwu0dskxuarqg3pquga6n7", "version": "1.0.0"}, {"address": "archive.synergynode.xyz:5615", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783159892, "genesis_hash": "", "last_seen": 1783159947, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "146.190.210.121:59918", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783159942, "genesis_hash": "", "last_seen": 1783159942, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "bootnode1.synergynode.xyz:5620", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783155221, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783155282, "node_id": "bootnode1", "public_address": "bootnode1.synergynode.xyz:5620", "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": "1.0.0"}, {"address": "109.199.104.37:56524", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783159896, "genesis_hash": "", "last_seen": 1783159947, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "157.245.226.240:57478", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783159938, "genesis_hash": "", "last_seen": 1783159941, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "62.146.182.208:5622", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783155209, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783159908, "node_id": "genesisval2", "public_address": "62.146.182.208:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt", "version": "1.0.0"}, {"address": "194.163.183.166:50488", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783159941, "genesis_hash": "", "last_seen": 1783159941, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}]}}}
}
~~~

### Listeners

~~~text
LISTEN 0      128          0.0.0.0:6030      0.0.0.0:*    users:(("synergy-validat",pid=731466,fd=100))            
LISTEN 0      128          0.0.0.0:5640      0.0.0.0:*    users:(("synergy-validat",pid=731466,fd=11))             
LISTEN 0      128          0.0.0.0:5660      0.0.0.0:*    users:(("synergy-validat",pid=731466,fd=106))            
LISTEN 0      128          0.0.0.0:5622      0.0.0.0:*    users:(("synergy-validat",pid=731466,fd=4))              
~~~

### Process

~~~text
main_pid=731466
    PID    PPID STAT     ELAPSED %CPU %MEM   RSS    VSZ COMMAND         COMMAND
 731466       1 Ssl     07:18:30  103  6.4 1589952 5289812 synergy-validat /opt/synergy/bin/synergy-validator start --config /etc/synergy/validator/config.toml
--- threads ---
    PID     TID STAT %CPU COMMAND
 731466  731466 Ssl   0.1 synergy-validat
 731466  731512 Ssl   0.0 p2p-listener
 731466  731513 Rsl  99.5 p2p-message-han
 731466  731514 Ssl   0.0 p2p-bootstrap
 731466  731515 Ssl   0.0 synergy-validat
 731466  731542 Ssl   0.0 p2p-connect-pee
 731466  731544 Ssl   0.0 p2p-connect-pee
 731466  731552 Ssl   0.0 p2p-connect-pee
 731466  731553 Ssl   0.0 p2p-connect-pee
 731466  731568 Ssl   0.0 synergy-validat
 731466  731575 Ssl   0.0 synergy-validat
 731466  731751 Ssl   0.0 ctrl-c
 731466  731871 Ssl   0.0 posy-consensus
 731466  770586 Ssl   0.0 p2p-connect-pee
 731466  770631 Ssl   0.0 p2p-discovery-d
 731466  770769 Ssl   0.1 p2p-accept-peer
 731466  780114 Ssl   0.1 p2p-connect-pee
 731466  780118 Ssl   0.1 p2p-connect-pee
 731466  780119 Ssl   0.1 p2p-connect-pee
 731466  780128 Ssl   0.1 p2p-accept-peer
 731466  780135 Ssl   0.1 p2p-accept-peer
 731466  780140 Ssl   0.1 p2p-accept-peer
 731466  780208 Rsl  91.5 synergy-validat
 731466  780210 Ssl   0.7 p2p-accept-peer
 731466  780213 Ssl   0.7 p2p-accept-peer
 731466  780223 Ssl   0.0 synergy-validat
 731466  780224 Ssl   0.7 p2p-accept-peer
 731466  780233 Ssl   0.0 reqwest-interna
 731466  780234 Ssl   0.0 tokio-rt-worker
--- fd-count ---
0
--- service-show ---
Restart=on-failure
RestartUSec=5s
MainPID=731466
ExecMainStartTimestamp=Sat 2026-07-04 04:53:58 CEST
ExecMainPID=731466
MemoryCurrent=7181991936
CPUUsageNSec=27319480483000
User=node
Group=node
~~~

### Recent Service Logs

~~~text
Jul 04 12:11:31 vmi3226973 synergy-validator[731466]:   "host": "relay1.synergynode.xyz",
Jul 04 12:11:31 vmi3226973 synergy-validator[731466]:   "min_serve_interval_secs": 2,
Jul 04 12:11:31 vmi3226973 synergy-validator[731466]:   "peer": "relay1.synergynode.xyz:5622"
Jul 04 12:11:31 vmi3226973 synergy-validator[731466]: }
Jul 04 12:11:31 vmi3226973 synergy-validator[731466]: [2026-07-04 10:11:31 UTC] [DEBUG] [p2p] Serving block sync response
Jul 04 12:11:31 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:11:31 vmi3226973 synergy-validator[731466]:   "count": 51,
Jul 04 12:11:31 vmi3226973 synergy-validator[731466]:   "from_height": 756248,
Jul 04 12:11:31 vmi3226973 synergy-validator[731466]:   "host": "209.145.50.9",
Jul 04 12:11:31 vmi3226973 synergy-validator[731466]:   "max_blocks": 64,
Jul 04 12:11:31 vmi3226973 synergy-validator[731466]:   "peer": "209.145.50.9:5622"
Jul 04 12:11:31 vmi3226973 synergy-validator[731466]: }
Jul 04 12:11:31 vmi3226973 synergy-validator[731466]: [2026-07-04 10:11:31 UTC] [INFO] [p2p] Vote sent
Jul 04 12:11:31 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:11:31 vmi3226973 synergy-validator[731466]:   "epoch": 760,
Jul 04 12:11:31 vmi3226973 synergy-validator[731466]:   "height": 760987,
Jul 04 12:11:31 vmi3226973 synergy-validator[731466]:   "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
Jul 04 12:11:31 vmi3226973 synergy-validator[731466]:   "request_peer": "157.173.192.45:59642",
Jul 04 12:11:31 vmi3226973 synergy-validator[731466]:   "response_peer": "157.173.192.45:59642",
Jul 04 12:11:31 vmi3226973 synergy-validator[731466]:   "round": 2165
Jul 04 12:11:31 vmi3226973 synergy-validator[731466]: }
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]: [2026-07-04 10:11:32 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "connected_age_secs": 48,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "direction": "Incoming",
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "has_identifying_metadata": false,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "has_remote_status": false,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "last_seen_age_secs": 1,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "peer": "109.199.104.37:57964",
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "validator_address": ""
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]: }
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]: [2026-07-04 10:11:32 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "connected_age_secs": 51,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "direction": "Outgoing",
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "has_identifying_metadata": false,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "has_remote_status": false,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "last_seen_age_secs": 1,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "peer": "rpc.synergynode.xyz:5623",
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "validator_address": ""
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]: }
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]: [2026-07-04 10:11:32 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "connected_age_secs": 92,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "direction": "Outgoing",
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "has_identifying_metadata": true,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "has_remote_status": false,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "last_seen_age_secs": 1,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "peer": "73.79.66.255:5622",
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "validator_address": ""
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]: }
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]: [2026-07-04 10:11:32 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "connected_age_secs": 67,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "direction": "Incoming",
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "has_identifying_metadata": true,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "has_remote_status": false,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "last_seen_age_secs": 25,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "peer": "194.163.183.166:45368",
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "validator_address": ""
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]: }
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]: [2026-07-04 10:11:32 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "connected_age_secs": 51,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "direction": "Incoming",
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "has_identifying_metadata": true,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "has_remote_status": false,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "last_seen_age_secs": 1,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "peer": "73.79.66.255:50756",
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "validator_address": ""
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]: }
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]: [2026-07-04 10:11:32 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "connected_age_secs": 51,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "direction": "Outgoing",
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "has_identifying_metadata": false,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "has_remote_status": false,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "last_seen_age_secs": 1,
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "peer": "62.146.182.207:5622",
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "validator_address": ""
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]: }
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]: [2026-07-04 10:11:32 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]:   "peer": "157.245.226.240:44338"
Jul 04 12:11:32 vmi3226973 synergy-validator[731466]: }
Jul 04 12:11:36 vmi3226973 synergy-validator[731466]: [2026-07-04 10:11:36 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:11:36 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:11:36 vmi3226973 synergy-validator[731466]:   "peer": "109.199.104.37:56524"
Jul 04 12:11:36 vmi3226973 synergy-validator[731466]: }
Jul 04 12:11:36 vmi3226973 synergy-validator[731466]: [2026-07-04 10:11:36 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:11:36 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:11:36 vmi3226973 synergy-validator[731466]:   "peer": "146.190.210.121:53774"
Jul 04 12:11:36 vmi3226973 synergy-validator[731466]: }
Jul 04 12:11:37 vmi3226973 synergy-validator[731466]: [2026-07-04 10:11:37 UTC] [WARN] [p2p] Failed to dial peer
Jul 04 12:11:37 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:11:37 vmi3226973 synergy-validator[731466]:   "error": "connection timed out",
Jul 04 12:11:37 vmi3226973 synergy-validator[731466]:   "peer": "seed1.synergynode.xyz:5621"
Jul 04 12:11:37 vmi3226973 synergy-validator[731466]: }
Jul 04 12:11:42 vmi3226973 synergy-validator[731466]: [2026-07-04 10:11:42 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:11:42 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:11:42 vmi3226973 synergy-validator[731466]:   "peer": "73.79.66.255:50652"
Jul 04 12:11:42 vmi3226973 synergy-validator[731466]: }
Jul 04 12:11:48 vmi3226973 synergy-validator[731466]: [2026-07-04 10:11:48 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:11:48 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:11:48 vmi3226973 synergy-validator[731466]:   "peer": "62.146.182.207:37862"
Jul 04 12:11:48 vmi3226973 synergy-validator[731466]: }
Jul 04 12:11:52 vmi3226973 synergy-validator[731466]: [2026-07-04 10:11:52 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:11:52 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:11:52 vmi3226973 synergy-validator[731466]:   "peer": "157.245.226.240:48228"
Jul 04 12:11:52 vmi3226973 synergy-validator[731466]: }
Jul 04 12:12:02 vmi3226973 synergy-validator[731466]: [2026-07-04 10:12:02 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:12:02 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:12:02 vmi3226973 synergy-validator[731466]:   "peer": "146.190.210.121:59052"
Jul 04 12:12:02 vmi3226973 synergy-validator[731466]: }
Jul 04 12:12:04 vmi3226973 synergy-validator[731466]: [2026-07-04 10:12:04 UTC] [WARN] [rpc] qRPC served read from fallback state
Jul 04 12:12:04 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:12:04 vmi3226973 synergy-validator[731466]:   "reason": "chain_tip_lock_unavailable"
Jul 04 12:12:04 vmi3226973 synergy-validator[731466]: }
Jul 04 12:12:11 vmi3226973 synergy-validator[731466]: [2026-07-04 10:12:11 UTC] [WARN] [rpc] qRPC served read from fallback state
Jul 04 12:12:11 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:12:11 vmi3226973 synergy-validator[731466]:   "reason": "chain_tip_lock_unavailable"
Jul 04 12:12:11 vmi3226973 synergy-validator[731466]: }
Jul 04 12:12:17 vmi3226973 synergy-validator[731466]: [2026-07-04 10:12:17 UTC] [WARN] [rpc] qRPC served read from fallback state
Jul 04 12:12:17 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:12:17 vmi3226973 synergy-validator[731466]:   "reason": "chain_tip_lock_unavailable"
Jul 04 12:12:17 vmi3226973 synergy-validator[731466]: }
Jul 04 12:12:18 vmi3226973 synergy-validator[731466]: [2026-07-04 10:12:18 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:12:18 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:12:18 vmi3226973 synergy-validator[731466]:   "peer": "157.245.226.240:57478"
Jul 04 12:12:18 vmi3226973 synergy-validator[731466]: }
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: [2026-07-04 10:12:21 UTC] [INFO] [p2p] Received vote request
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "epoch": 760,
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "height": 760987,
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "peer": "157.173.192.45:59642",
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "round": 2166
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: }
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: [2026-07-04 10:12:21 UTC] [DEBUG] [consensus] Ignoring local wall-clock view offset for canonical leader selection
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "block_height": 760987,
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "calculated_view_offset": 3716,
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "canonical_view_offset": 0
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: }
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: [2026-07-04 10:12:21 UTC] [INFO] [consensus] Selected leader for block
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "block_height": 760987,
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "block_in_epoch": 987,
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "epoch": 760,
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "leader": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "rotation_index": 3,
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "view_offset": 0
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: }
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: 🏆 [select_leader_for_block] Selected leader for block 760987 (epoch 760, block_in_epoch 987, rotation_index 3): synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: [2026-07-04 10:12:21 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "peer": "bootnode3.synergynode.xyz:5620"
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: }
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: [2026-07-04 10:12:21 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "peer": "bootnode2.synergynode.xyz:5620"
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: }
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: [2026-07-04 10:12:21 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "peer": "157.245.226.240:44338"
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: }
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: [2026-07-04 10:12:21 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "peer": "146.190.210.121:53774"
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: }
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: [2026-07-04 10:12:21 UTC] [DEBUG] [p2p] Serving block sync response
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "count": 4,
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "from_height": 760983,
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "host": "relay2.synergynode.xyz",
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "max_blocks": 64,
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "peer": "relay2.synergynode.xyz:5622"
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: }
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: [2026-07-04 10:12:21 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "peer": "157.245.226.240:48228"
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: }
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: [2026-07-04 10:12:21 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "peer": "146.190.210.121:59052"
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: }
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: [2026-07-04 10:12:21 UTC] [DEBUG] [p2p] Serving block sync response
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "count": 51,
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "from_height": 756248,
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "host": "209.145.50.9",
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "max_blocks": 64,
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "peer": "209.145.50.9:5622"
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: }
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: [2026-07-04 10:12:21 UTC] [INFO] [p2p] Vote sent
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "epoch": 760,
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "height": 760987,
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "request_peer": "157.173.192.45:59642",
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "response_peer": "157.173.192.45:59642",
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "round": 2166
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: }
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: [2026-07-04 10:12:21 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]:   "peer": "194.163.183.166:50488"
Jul 04 12:12:21 vmi3226973 synergy-validator[731466]: }
Jul 04 12:12:22 vmi3226973 synergy-validator[731466]: [2026-07-04 10:12:22 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:12:22 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:12:22 vmi3226973 synergy-validator[731466]:   "peer": "146.190.210.121:59918"
Jul 04 12:12:22 vmi3226973 synergy-validator[731466]: }
Jul 04 12:12:24 vmi3226973 synergy-validator[731466]: [2026-07-04 10:12:24 UTC] [WARN] [rpc] qRPC served read from fallback state
Jul 04 12:12:24 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:12:24 vmi3226973 synergy-validator[731466]:   "reason": "chain_tip_lock_unavailable"
Jul 04 12:12:24 vmi3226973 synergy-validator[731466]: }
Jul 04 12:12:25 vmi3226973 synergy-validator[731466]: [2026-07-04 10:12:25 UTC] [DEBUG] [p2p] Seed peer list request failed
Jul 04 12:12:25 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:12:25 vmi3226973 synergy-validator[731466]:   "error": "error sending request for url (http://seed1.synergynode.xyz:5621/peer-list.json)",
Jul 04 12:12:25 vmi3226973 synergy-validator[731466]:   "seed_server": "http://seed1.synergynode.xyz:5621"
Jul 04 12:12:25 vmi3226973 synergy-validator[731466]: }
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
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783125308-1783125308082949772-proposals-above-760986/manifest.json	1120 bytes	2026-07-04T02:35:08.0851765200Z
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783129015-1783129015028028381-proposals-above-760986/manifest.json	1120 bytes	2026-07-04T03:36:55.0282369710Z
~~~
