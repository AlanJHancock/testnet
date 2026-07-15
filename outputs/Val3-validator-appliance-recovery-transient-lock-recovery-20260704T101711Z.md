# Validator Appliance Transient Vote Lock Recovery

generated_utc: 2026-07-04T10:17:11Z
phase: transient-lock-recovery
execute: true

spreadsheet_row_used=true row=17 node=Val3 ssh='ssh synergy-val3' user='rob' public_ip='62.146.182.209' qrpc='5640' ws='5660' metrics='6030'
## Transient Vote Lock Recovery Gate

~~~text
target_node=Val3
execute=true
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
      "age_seconds": 15,
      "block_hash": "34b2225ef5704ca52daef2f1350952a2a613fee63bc9b11db7200dd9218fc938",
      "epoch": 760,
      "first_round": 11,
      "height": 760987,
      "latest_round": 2178,
      "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
      "validator_address": "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re"
    }
  ],
  "fresh_locks_above_finalized": 1,
  "locks": [
    {
      "age_seconds": 15,
      "block_hash": "34b2225ef5704ca52daef2f1350952a2a613fee63bc9b11db7200dd9218fc938",
      "epoch": 760,
      "first_round": 11,
      "height": 760987,
      "latest_round": 2178,
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
{"elapsed_sec": 6.057, "error": "timed out"}
~~~

## Supported Runtime Recovery

~~~json
{"elapsed_sec": 0.078, "response": {"id": 1, "jsonrpc": "2.0", "result": {"canonical_locks_mutated": false, "chain": {"chain_id": 1264, "chain_id_hex": "0x4f0", "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "network_id": "synergy-testnet-v2"}, "committed_qcs_mutated": false, "finalized_height": 760985, "keys_or_configs_copied": false, "proposal_cache_recovery": {"action": "recover_cached_block_proposals_above_finalized_height", "archived": [], "archived_count": 0, "evidence_dir": "", "finalized_height": 760985, "mutated": false, "proposal_cache_dir": "/var/lib/synergy/validator/data/consensus_proposals", "reason": "operator_approved_stopped_validator_quarantine", "scanned_count": 0, "timestamp": 1783160286}, "vote_lock_recovery": {"action": "recover_transient_vote_locks_above_finalized_height", "before_count": 969, "evidence_path": "", "finalized_height": 760985, "kept_count": 969, "min_age_secs": 30, "mutated": false, "reason": "operator_approved_stopped_validator_quarantine", "removed": [], "removed_count": 0, "timestamp": 1783160286, "vote_lock_path": "/var/lib/synergy/validator/data/consensus_vote_locks.json"}}}}
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
      "age_seconds": 21,
      "block_hash": "34b2225ef5704ca52daef2f1350952a2a613fee63bc9b11db7200dd9218fc938",
      "epoch": 760,
      "first_round": 11,
      "height": 760987,
      "latest_round": 2178,
      "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
      "validator_address": "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re"
    }
  ],
  "fresh_locks_above_finalized": 1,
  "locks": [
    {
      "age_seconds": 21,
      "block_hash": "34b2225ef5704ca52daef2f1350952a2a613fee63bc9b11db7200dd9218fc938",
      "epoch": 760,
      "first_round": 11,
      "height": 760987,
      "latest_round": 2178,
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
{"elapsed_sec": 6.046, "error": "timed out"}
~~~

## Remote Validator Status

generated_utc: 2026-07-04T10:18:12Z
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
  "health": {"elapsed_sec": 6.053, "error": "timed out"},
  "latest": {"elapsed_sec": 6.054, "error": "timed out"},
  "block_number": {"elapsed_sec": 6.049, "error": "timed out"},
  "canonical_lock": {"elapsed_sec": 0.061, "response": {"id": 1, "jsonrpc": "2.0", "result": {"block_hash": "d736f234b2f1e7c524a20aa9787f48c3dd33b7c8fb703ab7edd73b8404d4ebef", "chain": {"chain_id": 1264, "chain_id_hex": "0x4f0", "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "name": "synergy-testnet-v2", "network_id": "synergy-testnet-v2"}, "found": true, "height": 760986, "parent_hash": "a77d4b894e284c4705620e377b2c37838ed2ee37429d019637470b9e93344936", "qc_block_hash": "d736f234b2f1e7c524a20aa9787f48c3dd33b7c8fb703ab7edd73b8404d4ebef", "qc_hash": "97b7d21037d78e40e3bd07d05f07a6536584a7934ad08c09f2a9d9bb3aecd86e", "transactions_root": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "validator_id": "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt", "written_at_unix_secs": 1783119216}}},
  "node_status": {"elapsed_sec": 6.048, "error": "timed out"},
  "peer_info": {"elapsed_sec": 0.06, "response": {"id": 1, "jsonrpc": "2.0", "result": {"peer_count": 6, "peers": [{"address": "62.146.182.207:5622", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160280, "genesis_hash": "", "last_seen": 1783160280, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "194.163.183.166:5622", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160280, "genesis_hash": "", "last_seen": 1783160280, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "157.245.226.240:51350", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160310, "genesis_hash": "", "last_seen": 1783160310, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "157.245.226.240:47766", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160290, "genesis_hash": "", "last_seen": 1783160290, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "157.173.192.45:5622", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783133668, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783136241, "node_id": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "public_address": "157.173.192.45:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "version": "1.0.0"}, {"address": "bootnode2.synergynode.xyz:5620", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160280, "genesis_hash": "", "last_seen": 1783160280, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "73.79.66.255:5622", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160280, "genesis_hash": "", "last_seen": 1783160280, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "rpc.synergynode.xyz:5623", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160280, "genesis_hash": "", "last_seen": 1783160280, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "109.199.104.37:44080", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160284, "genesis_hash": "", "last_seen": 1783160284, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "relay1.synergynode.xyz:5622", "blocks_received": 0, "blocks_sent": 301, "capabilities": ["blocks", "transactions"], "connected_at": 1783133665, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160317, "node_id": "sentry1", "public_address": "195.26.241.95:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv21ga3nsdjagzt9pmks4mzjq4vdjyngdwq6jst632", "version": "1.0.0"}, {"address": "relay2.synergynode.xyz:5622", "blocks_received": 0, "blocks_sent": 283, "capabilities": ["blocks", "transactions"], "connected_at": 1783133668, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160317, "node_id": "sentry2", "public_address": "94.72.117.108:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv21xaqlq808sunuchd0jwr4m324h85fza2ps3s4k7", "version": "1.0.0"}, {"address": "146.190.210.121:54174", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160277, "genesis_hash": "", "last_seen": 1783160277, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "157.173.192.45:59642", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783155308, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160265, "node_id": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "public_address": "157.173.192.45:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "version": "1.0.0"}, {"address": "209.145.50.9:5622", "blocks_received": 0, "blocks_sent": 527, "capabilities": ["blocks", "transactions"], "connected_at": 1783133668, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160316, "node_id": "observer", "public_address": "209.145.50.9:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv51q8t3jqkt6e0y6kdppwu0dskxuarqg3pquga6n7", "version": "1.0.0"}, {"address": "146.190.210.121:54186", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160280, "genesis_hash": "", "last_seen": 1783160280, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "bootnode3.synergynode.xyz:5620", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160280, "genesis_hash": "", "last_seen": 1783160280, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "73.79.66.255:51661", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160281, "genesis_hash": "", "last_seen": 1783160281, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "bootnode1.synergynode.xyz:5620", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783155221, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783155282, "node_id": "bootnode1", "public_address": "bootnode1.synergynode.xyz:5620", "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": "1.0.0"}, {"address": "62.146.182.208:5622", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783155209, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160280, "node_id": "genesisval2", "public_address": "62.146.182.208:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt", "version": "1.0.0"}, {"address": "146.190.210.121:39768", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160273, "genesis_hash": "", "last_seen": 1783160273, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "146.190.210.121:56778", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160310, "genesis_hash": "", "last_seen": 1783160310, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "157.245.226.240:37934", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160279, "genesis_hash": "", "last_seen": 1783160279, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "62.146.182.207:40980", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160286, "genesis_hash": "", "last_seen": 1783160286, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "146.190.210.121:54192", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160284, "genesis_hash": "", "last_seen": 1783160284, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "157.245.226.240:37924", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160279, "genesis_hash": "", "last_seen": 1783160279, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "157.245.226.240:37944", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160280, "genesis_hash": "", "last_seen": 1783160280, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}]}}}
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
 731466       1 Ssl     07:24:40  104  6.3 1574440 5291960 synergy-validat /opt/synergy/bin/synergy-validator start --config /etc/synergy/validator/config.toml
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
 731466  781231 Ssl   0.1 p2p-accept-peer
 731466  781240 Ssl   0.1 p2p-accept-peer
 731466  781241 Ssl   0.2 p2p-accept-peer
 731466  781245 Ssl   0.2 p2p-accept-peer
 731466  781251 Ssl   0.1 p2p-accept-peer
 731466  781258 Ssl   0.2 p2p-accept-peer
 731466  781259 Ssl   0.1 p2p-connect-pee
 731466  781260 Ssl   0.3 p2p-connect-pee
 731466  781261 Ssl   0.2 p2p-connect-pee
 731466  781262 Ssl   0.1 p2p-connect-pee
 731466  781263 Ssl   0.2 p2p-connect-pee
 731466  781264 Ssl   0.2 p2p-connect-pee
 731466  781269 Ssl   0.2 p2p-accept-peer
 731466  781275 Ssl   0.2 p2p-accept-peer
 731466  781276 Ssl   0.2 p2p-accept-peer
 731466  781279 Ssl   0.1 p2p-accept-peer
 731466  781295 Ssl   0.2 p2p-accept-peer
 731466  781341 Rsl  91.7 synergy-validat
 731466  781348 Ssl   2.6 p2p-accept-peer
 731466  781349 Ssl   0.9 p2p-accept-peer
 731466  781356 Ssl   0.0 synergy-validat
--- fd-count ---
0
--- service-show ---
Restart=on-failure
RestartUSec=5s
MainPID=731466
ExecMainStartTimestamp=Sat 2026-07-04 04:53:58 CEST
ExecMainPID=731466
MemoryCurrent=4214329344
CPUUsageNSec=27763194456000
User=node
Group=node
~~~

### Recent Service Logs

~~~text
Jul 04 12:17:45 vmi3226973 synergy-validator[731466]:   "peer": "157.245.226.240:54556"
Jul 04 12:17:45 vmi3226973 synergy-validator[731466]: }
Jul 04 12:17:45 vmi3226973 synergy-validator[731466]: [2026-07-04 10:17:45 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:17:45 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:17:45 vmi3226973 synergy-validator[731466]:   "peer": "146.190.210.121:50640"
Jul 04 12:17:45 vmi3226973 synergy-validator[731466]: }
Jul 04 12:17:45 vmi3226973 synergy-validator[731466]: [2026-07-04 10:17:45 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:17:45 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:17:45 vmi3226973 synergy-validator[731466]:   "peer": "146.190.210.121:41582"
Jul 04 12:17:45 vmi3226973 synergy-validator[731466]: }
Jul 04 12:17:45 vmi3226973 synergy-validator[731466]: [2026-07-04 10:17:45 UTC] [INFO] [p2p] Vote sent
Jul 04 12:17:45 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:17:45 vmi3226973 synergy-validator[731466]:   "epoch": 760,
Jul 04 12:17:45 vmi3226973 synergy-validator[731466]:   "height": 760987,
Jul 04 12:17:45 vmi3226973 synergy-validator[731466]:   "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
Jul 04 12:17:45 vmi3226973 synergy-validator[731466]:   "request_peer": "157.173.192.45:59642",
Jul 04 12:17:45 vmi3226973 synergy-validator[731466]:   "response_peer": "157.173.192.45:59642",
Jul 04 12:17:45 vmi3226973 synergy-validator[731466]:   "round": 2178
Jul 04 12:17:45 vmi3226973 synergy-validator[731466]: }
Jul 04 12:17:49 vmi3226973 synergy-validator[731466]: [2026-07-04 10:17:49 UTC] [DEBUG] [p2p] Seed peer list request failed
Jul 04 12:17:49 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:17:49 vmi3226973 synergy-validator[731466]:   "error": "error sending request for url (http://seed1.synergynode.xyz:5621/peer-list.json)",
Jul 04 12:17:49 vmi3226973 synergy-validator[731466]:   "seed_server": "http://seed1.synergynode.xyz:5621"
Jul 04 12:17:49 vmi3226973 synergy-validator[731466]: }
Jul 04 12:17:50 vmi3226973 synergy-validator[731466]: [2026-07-04 10:17:50 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:17:50 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:17:50 vmi3226973 synergy-validator[731466]:   "peer": "157.245.226.240:35644"
Jul 04 12:17:50 vmi3226973 synergy-validator[731466]: }
Jul 04 12:17:53 vmi3226973 synergy-validator[731466]: [2026-07-04 10:17:53 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:17:53 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:17:53 vmi3226973 synergy-validator[731466]:   "peer": "146.190.210.121:39768"
Jul 04 12:17:53 vmi3226973 synergy-validator[731466]: }
Jul 04 12:17:57 vmi3226973 synergy-validator[731466]: [2026-07-04 10:17:57 UTC] [DEBUG] [p2p] Failed to register self with seed server
Jul 04 12:17:57 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:17:57 vmi3226973 synergy-validator[731466]:   "error": "error sending request for url (http://seed1.synergynode.xyz:5621/peers/register)",
Jul 04 12:17:57 vmi3226973 synergy-validator[731466]:   "seed_server": "http://seed1.synergynode.xyz:5621"
Jul 04 12:17:57 vmi3226973 synergy-validator[731466]: }
Jul 04 12:17:57 vmi3226973 synergy-validator[731466]: [2026-07-04 10:17:57 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:17:57 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:17:57 vmi3226973 synergy-validator[731466]:   "peer": "146.190.210.121:54174"
Jul 04 12:17:57 vmi3226973 synergy-validator[731466]: }
Jul 04 12:17:59 vmi3226973 synergy-validator[731466]: [2026-07-04 10:17:59 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:17:59 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:17:59 vmi3226973 synergy-validator[731466]:   "peer": "157.245.226.240:37924"
Jul 04 12:17:59 vmi3226973 synergy-validator[731466]: }
Jul 04 12:17:59 vmi3226973 synergy-validator[731466]: [2026-07-04 10:17:59 UTC] [DEBUG] [p2p] Registered self with seed server
Jul 04 12:17:59 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:17:59 vmi3226973 synergy-validator[731466]:   "dial": "62.146.182.209:5622",
Jul 04 12:17:59 vmi3226973 synergy-validator[731466]:   "seed_server": "http://seed2.synergynode.xyz:5621"
Jul 04 12:17:59 vmi3226973 synergy-validator[731466]: }
Jul 04 12:17:59 vmi3226973 synergy-validator[731466]: [2026-07-04 10:17:59 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:17:59 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:17:59 vmi3226973 synergy-validator[731466]:   "peer": "157.245.226.240:37934"
Jul 04 12:17:59 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:00 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "peer": "157.245.226.240:37944"
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:00 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "peer": "146.190.210.121:54186"
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:00 UTC] [DEBUG] [p2p] Registered self with seed server
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "dial": "62.146.182.209:5622",
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "seed_server": "http://seed3.synergynode.xyz:5621"
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:00 UTC] [INFO] [p2p] Resolved bootstrap dial targets
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "targets": "[\"157.173.192.45:5622\", \"194.163.183.166:5622\", \"209.145.50.9:5622\", \"62.146.182.207:5622\", \"62.146.182.208:5622\", \"73.79.66.255:5622\", \"archive.synergynode.xyz:5615\", \"bootnode1.synergynode.xyz:5620\", \"bootnode2.synergynode.xyz:5620\", \"bootnode3.synergynode.xyz:5620\", \"relay1.synergynode.xyz:5622\", \"relay2.synergynode.xyz:5622\", \"rpc.synergynode.xyz:5623\", \"seed1.synergynode.xyz:5621\", \"seed2.synergynode.xyz:5621\", \"seed3.synergynode.xyz:5621\"]"
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:00 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "connected_age_secs": 72,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "direction": "Incoming",
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "has_identifying_metadata": false,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "has_remote_status": false,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "last_seen_age_secs": 9,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "peer": "62.146.182.207:33278",
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "validator_address": ""
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:00 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "connected_age_secs": 80,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "direction": "Outgoing",
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "has_identifying_metadata": false,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "has_remote_status": false,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "last_seen_age_secs": 80,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "peer": "seed3.synergynode.xyz:5621",
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "validator_address": ""
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:00 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "connected_age_secs": 54,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "direction": "Incoming",
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "has_identifying_metadata": true,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "has_remote_status": false,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "last_seen_age_secs": 15,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "peer": "194.163.183.166:49736",
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "validator_address": ""
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:00 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "connected_age_secs": 80,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "direction": "Outgoing",
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "has_identifying_metadata": false,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "has_remote_status": false,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "last_seen_age_secs": 80,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "peer": "seed2.synergynode.xyz:5621",
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "validator_address": ""
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:00 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "connected_age_secs": 72,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "direction": "Incoming",
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "has_identifying_metadata": true,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "has_remote_status": false,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "last_seen_age_secs": 10,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "peer": "73.79.66.255:51814",
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "validator_address": ""
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:00 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "connected_age_secs": 80,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "direction": "Outgoing",
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "has_identifying_metadata": false,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "has_remote_status": false,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "last_seen_age_secs": 1,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "peer": "archive.synergynode.xyz:5615",
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "validator_address": ""
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:00 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "connected_age_secs": 75,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "direction": "Incoming",
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "has_identifying_metadata": false,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "has_remote_status": false,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "last_seen_age_secs": 0,
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "peer": "109.199.104.37:53480",
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "validator_address": ""
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:00 UTC] [WARN] [p2p] Failed to request peers
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "error": "Broken pipe (os error 32)",
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "peer": "146.190.210.121:54174"
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:00 UTC] [WARN] [p2p] Failed to request peers
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "error": "Broken pipe (os error 32)",
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "peer": "157.245.226.240:37934"
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:00 UTC] [WARN] [p2p] Failed to request peers
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "error": "Broken pipe (os error 32)",
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "peer": "157.245.226.240:37924"
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:00 UTC] [WARN] [p2p] Failed to request status
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "error": "Broken pipe (os error 32)",
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "peer": "146.190.210.121:54174"
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:00 UTC] [WARN] [p2p] Failed to request status
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "error": "Broken pipe (os error 32)",
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "peer": "157.245.226.240:37934"
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:00 UTC] [WARN] [p2p] Failed to request status
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "error": "Broken pipe (os error 32)",
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]:   "peer": "157.245.226.240:37924"
Jul 04 12:18:00 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:01 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:01 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:18:01 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:01 vmi3226973 synergy-validator[731466]:   "peer": "73.79.66.255:51661"
Jul 04 12:18:01 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:04 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:04 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:18:04 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:04 vmi3226973 synergy-validator[731466]:   "peer": "146.190.210.121:54192"
Jul 04 12:18:04 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:04 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:04 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:18:04 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:04 vmi3226973 synergy-validator[731466]:   "peer": "109.199.104.37:44080"
Jul 04 12:18:04 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:05 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:05 UTC] [WARN] [p2p] Failed to dial peer
Jul 04 12:18:05 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:05 vmi3226973 synergy-validator[731466]:   "error": "connection timed out",
Jul 04 12:18:05 vmi3226973 synergy-validator[731466]:   "peer": "seed1.synergynode.xyz:5621"
Jul 04 12:18:05 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:06 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:06 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:18:06 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:06 vmi3226973 synergy-validator[731466]:   "peer": "62.146.182.207:40980"
Jul 04 12:18:06 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:10 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:10 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:18:10 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:10 vmi3226973 synergy-validator[731466]:   "peer": "157.245.226.240:47766"
Jul 04 12:18:10 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:16 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:16 UTC] [WARN] [rpc] qRPC served read from fallback state
Jul 04 12:18:16 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:16 vmi3226973 synergy-validator[731466]:   "reason": "chain_tip_lock_unavailable"
Jul 04 12:18:16 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:22 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:22 UTC] [WARN] [rpc] qRPC served read from fallback state
Jul 04 12:18:22 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:22 vmi3226973 synergy-validator[731466]:   "reason": "chain_tip_lock_unavailable"
Jul 04 12:18:22 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:28 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:28 UTC] [WARN] [rpc] qRPC served read from fallback state
Jul 04 12:18:28 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:28 vmi3226973 synergy-validator[731466]:   "reason": "chain_tip_lock_unavailable"
Jul 04 12:18:28 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:30 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:30 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:18:30 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:30 vmi3226973 synergy-validator[731466]:   "peer": "146.190.210.121:56778"
Jul 04 12:18:30 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:30 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:30 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:18:30 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:30 vmi3226973 synergy-validator[731466]:   "peer": "157.245.226.240:51350"
Jul 04 12:18:30 vmi3226973 synergy-validator[731466]: }
Jul 04 12:18:34 vmi3226973 synergy-validator[731466]: [2026-07-04 10:18:34 UTC] [WARN] [rpc] qRPC served read from fallback state
Jul 04 12:18:34 vmi3226973 synergy-validator[731466]:   Metadata: {
Jul 04 12:18:34 vmi3226973 synergy-validator[731466]:   "reason": "chain_tip_lock_unavailable"
Jul 04 12:18:34 vmi3226973 synergy-validator[731466]: }
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
