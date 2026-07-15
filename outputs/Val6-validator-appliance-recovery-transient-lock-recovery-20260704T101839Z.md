# Validator Appliance Transient Vote Lock Recovery

generated_utc: 2026-07-04T10:18:39Z
phase: transient-lock-recovery
execute: true

spreadsheet_row_used=true row=20 node=Val6 ssh='ssh synergy-val6' user='root' public_ip='157.173.192.45' qrpc='5640' ws='5660' metrics='6030'
## Transient Vote Lock Recovery Gate

~~~text
target_node=Val6
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
  "fresh_locks": [],
  "fresh_locks_above_finalized": 0,
  "locks": [
    {
      "age_seconds": 134,
      "block_hash": "34b2225ef5704ca52daef2f1350952a2a613fee63bc9b11db7200dd9218fc938",
      "epoch": 760,
      "first_round": 1,
      "height": 760987,
      "latest_round": 2193,
      "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
      "validator_address": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx"
    }
  ],
  "locks_above_finalized": 1,
  "parse_error": null,
  "stale_conflicting_heights_above_finalized": [],
  "stale_locks": [
    {
      "age_seconds": 134,
      "block_hash": "34b2225ef5704ca52daef2f1350952a2a613fee63bc9b11db7200dd9218fc938",
      "epoch": 760,
      "first_round": 1,
      "height": 760987,
      "latest_round": 2193,
      "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
      "validator_address": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx"
    }
  ],
  "stale_locks_above_finalized": 1,
  "stale_threshold_seconds": 30,
  "total_vote_locks": 233,
  "vote_lock_path": "/var/lib/synergy/validator/data/consensus_vote_locks.json"
}
~~~

### latest-before

~~~json
{"elapsed_sec": 6.056, "error": "timed out"}
~~~

## Supported Runtime Recovery

~~~json
{"elapsed_sec": 0.083, "response": {"id": 1, "jsonrpc": "2.0", "result": {"canonical_locks_mutated": false, "chain": {"chain_id": 1264, "chain_id_hex": "0x4f0", "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "network_id": "synergy-testnet-v2"}, "committed_qcs_mutated": false, "finalized_height": 760985, "keys_or_configs_copied": false, "proposal_cache_recovery": {"action": "recover_cached_block_proposals_above_finalized_height", "archived": [{"block_hash": "34b2225ef5704ca52daef2f1350952a2a613fee63bc9b11db7200dd9218fc938", "block_index": 760987, "evidence_path": "/var/lib/synergy/validator/data/consensus_recovery_evidence/1783160372-1783160372978913426-proposals-above-760985/323a697113b02fe19bd1499f52f2d8b7b1cdf561e66b39fbec77d4305c331507.json", "parent_hash": "d736f234b2f1e7c524a20aa9787f48c3dd33b7c8fb703ab7edd73b8404d4ebef", "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "source_path": "/var/lib/synergy/validator/data/consensus_proposals/323a697113b02fe19bd1499f52f2d8b7b1cdf561e66b39fbec77d4305c331507.json"}], "archived_count": 1, "evidence_dir": "/var/lib/synergy/validator/data/consensus_recovery_evidence/1783160372-1783160372978913426-proposals-above-760985", "finalized_height": 760985, "mutated": true, "proposal_cache_dir": "/var/lib/synergy/validator/data/consensus_proposals", "reason": "operator_approved_stopped_validator_quarantine", "scanned_count": 2, "timestamp": 1783160372}, "vote_lock_recovery": {"action": "recover_transient_vote_locks_above_finalized_height", "before_count": 233, "evidence_path": "/var/lib/synergy/validator/data/consensus_recovery_evidence/1783160372-1783160372966091457-transient-vote-locks-above-760985.json", "finalized_height": 760985, "kept_count": 232, "min_age_secs": 30, "mutated": true, "reason": "operator_approved_stopped_validator_quarantine", "removed": [{"block_hash": "34b2225ef5704ca52daef2f1350952a2a613fee63bc9b11db7200dd9218fc938", "block_index": 760987, "created_at": 1783133594, "epoch_number": 760, "first_round_number": 1, "latest_round_number": 2193, "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "updated_at": 1783160232, "validator_address": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx"}], "removed_count": 1, "timestamp": 1783160372, "vote_lock_path": "/var/lib/synergy/validator/data/consensus_vote_locks.json"}}}}
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
  "fresh_locks": [],
  "fresh_locks_above_finalized": 0,
  "locks": [],
  "locks_above_finalized": 0,
  "parse_error": null,
  "stale_conflicting_heights_above_finalized": [],
  "stale_locks": [],
  "stale_locks_above_finalized": 0,
  "stale_threshold_seconds": 30,
  "total_vote_locks": 232,
  "vote_lock_path": "/var/lib/synergy/validator/data/consensus_vote_locks.json"
}
~~~

### latest-after

~~~json
{"elapsed_sec": 6.046, "error": "timed out"}
~~~

## Remote Validator Status

generated_utc: 2026-07-04T10:19:39Z
hostname: vmi3371822.contaboserver.net
runtime_root: /var/lib/synergy/validator
config_path: /etc/synergy/validator/config.toml
cli_binary: /opt/synergy/bin/synergy-node
runtime_binary: /opt/synergy/bin/synergy-validator
service_execstart: { path=/opt/synergy/bin/synergy-validator ; argv[]=/opt/synergy/bin/synergy-validator start --config /etc/synergy/validator/config.toml ; ignore_errors=no ; start_time=[Sat 2026-07-04 04:51:40 CEST] ; stop_time=[n/a] ; pid=690884 ; code=(null) ; status=0/0 }

### Service

~~~text
state=active
show=690884|active|running|
~~~

### qRPC

~~~json
{
  "health": {"elapsed_sec": 6.049, "error": "timed out"},
  "latest": {"elapsed_sec": 0.04, "response": {"id": 1, "jsonrpc": "2.0", "result": {"block_index": 760986, "hash": "d736f234b2f1e7c524a20aa9787f48c3dd33b7c8fb703ab7edd73b8404d4ebef", "nonce": 760986, "parent_hash": "a77d4b894e284c4705620e377b2c37838ed2ee37429d019637470b9e93344936", "previous_hash": "a77d4b894e284c4705620e377b2c37838ed2ee37429d019637470b9e93344936", "timestamp": 1783096754, "transactions": [], "tx_count": 0, "validator": "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt", "validator_id": "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt"}}},
  "block_number": {"elapsed_sec": 0.044, "response": {"id": 1, "jsonrpc": "2.0", "result": 760986}},
  "canonical_lock": {"elapsed_sec": 0.782, "response": {"id": 1, "jsonrpc": "2.0", "result": {"block_hash": "d736f234b2f1e7c524a20aa9787f48c3dd33b7c8fb703ab7edd73b8404d4ebef", "chain": {"chain_id": 1264, "chain_id_hex": "0x4f0", "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "name": "synergy-testnet-v2", "network_id": "synergy-testnet-v2"}, "found": true, "height": 760986, "parent_hash": "a77d4b894e284c4705620e377b2c37838ed2ee37429d019637470b9e93344936", "qc_block_hash": "d736f234b2f1e7c524a20aa9787f48c3dd33b7c8fb703ab7edd73b8404d4ebef", "qc_hash": "97b7d21037d78e40e3bd07d05f07a6536584a7934ad08c09f2a9d9bb3aecd86e", "transactions_root": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "validator_id": "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt", "written_at_unix_secs": 1783119177}}},
  "node_status": {"elapsed_sec": 0.046, "response": {"id": 1, "jsonrpc": "2.0", "result": {"average_block_time": 92501444.94736843, "avg_block_time": 92501444.94736843, "highest_block": 760986, "last_block": 760986, "network": "synergy-testnet-v2", "node_type": null, "peer_count": 10, "peers": 10, "peers_connected": 10, "status": "running", "sync_status": "synced", "timestamp": 1783160386, "uptime": "31.1%", "uptime_seconds": 26861, "version": "15.0.6"}}},
  "peer_info": {"elapsed_sec": 0.044, "response": {"id": 1, "jsonrpc": "2.0", "result": {"peer_count": 10, "peers": [{"address": "62.146.182.209:5622", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783133529, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160382, "node_id": "genesisval3", "public_address": "62.146.182.209:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re", "version": "1.0.0"}, {"address": "relay1.synergynode.xyz:5622", "blocks_received": 0, "blocks_sent": 8809, "capabilities": ["blocks", "transactions"], "connected_at": 1783133529, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160387, "node_id": "sentry1", "public_address": "195.26.241.95:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv21ga3nsdjagzt9pmks4mzjq4vdjyngdwq6jst632", "version": "1.0.0"}, {"address": "62.146.182.207:5622", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783133577, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160383, "node_id": "genesisval1", "public_address": "62.146.182.207:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs", "version": "1.0.0"}, {"address": "209.145.50.9:5622", "blocks_received": 0, "blocks_sent": 1674, "capabilities": ["blocks", "transactions"], "connected_at": 1783133529, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160384, "node_id": "observer", "public_address": "209.145.50.9:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv51q8t3jqkt6e0y6kdppwu0dskxuarqg3pquga6n7", "version": "1.0.0"}, {"address": "62.146.182.208:5622", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783133529, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160382, "node_id": "genesisval2", "public_address": "62.146.182.208:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt", "version": "1.0.0"}, {"address": "109.199.104.37:58034", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783160384, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160386, "node_id": "synv11um0ddw94q7rph09ymd88dr8hhzmufnwtslz", "public_address": "109.199.104.37:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11um0ddw94q7rph09ymd88dr8hhzmufnwtslz", "version": "1.0.0"}, {"address": "seed2.synergynode.xyz:5621", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160382, "genesis_hash": "", "last_seen": 1783160382, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "167.86.83.83:5623", "blocks_received": 0, "blocks_sent": 6, "capabilities": ["blocks", "transactions"], "connected_at": 1783138212, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160387, "node_id": "genesisrpc", "public_address": "167.86.83.83:5623", "txs_received": 0, "txs_sent": 0, "validator_address": "synv5d2b6a255a574438fd8bdcb194a782acbdcf2", "version": "1.0.0"}, {"address": "170.64.187.206:54420", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783154966, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783155402, "node_id": "bootnode1", "public_address": "bootnode1.synergynode.xyz:5620", "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": "1.0.0"}, {"address": "relay2.synergynode.xyz:5622", "blocks_received": 0, "blocks_sent": 8795, "capabilities": ["blocks", "transactions"], "connected_at": 1783133528, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160387, "node_id": "sentry2", "public_address": "94.72.117.108:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv21xaqlq808sunuchd0jwr4m324h85fza2ps3s4k7", "version": "1.0.0"}, {"address": "73.79.66.255:5622", "blocks_received": 0, "blocks_sent": 24, "capabilities": ["blocks", "transactions"], "connected_at": 1783158867, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160385, "node_id": "genesisval4", "public_address": "73.79.66.255:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5", "version": "1.0.0"}, {"address": "seed3.synergynode.xyz:5621", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160382, "genesis_hash": "", "last_seen": 1783160382, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "194.163.183.166:5622", "blocks_received": 0, "blocks_sent": 21, "capabilities": ["blocks", "transactions"], "connected_at": 1783158887, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160385, "node_id": "genesisval5", "public_address": "194.163.183.166:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11kguave5fpdpm9hru4acfvw0hcp4fcc7zv9f", "version": "1.0.0"}]}}}
}
~~~

### Listeners

~~~text
LISTEN 0      128          0.0.0.0:5622       0.0.0.0:*    users:(("synergy-validat",pid=690884,fd=3))
LISTEN 0      128          0.0.0.0:6030       0.0.0.0:*    users:(("synergy-validat",pid=690884,fd=75))
LISTEN 0      128          0.0.0.0:5640       0.0.0.0:*    users:(("synergy-validat",pid=690884,fd=4))
LISTEN 0      128          0.0.0.0:5660       0.0.0.0:*    users:(("synergy-validat",pid=690884,fd=13))
~~~

### Process

~~~text
main_pid=690884
    PID    PPID STAT     ELAPSED %CPU %MEM   RSS    VSZ COMMAND         COMMAND
 690884       1 Ssl     07:28:06 45.1 21.8 5374300 9506700 synergy-validat /opt/synergy/bin/synergy-validator start --config /etc/synergy/validator/config.toml
--- threads ---
    PID     TID STAT %CPU COMMAND
 690884  690884 Ssl   0.1 synergy-validat
 690884  690899 Ssl   0.0 p2p-listener
 690884  690900 Ssl   2.5 p2p-message-han
 690884  690901 Ssl   0.6 p2p-bootstrap
 690884  690902 Ssl   0.0 synergy-validat
 690884  690923 Ssl   0.0 p2p-connect-pee
 690884  690930 Ssl   0.1 p2p-connect-pee
 690884  690931 Ssl   0.1 p2p-connect-pee
 690884  690937 Ssl   0.0 synergy-validat
 690884  690940 Ssl   0.0 synergy-validat
 690884  690975 Ssl   0.0 p2p-accept-peer
 690884  691000 Ssl   0.0 ctrl-c
 690884  691001 Ssl   1.1 posy-consensus
 690884  691150 Ssl   0.0 p2p-accept-peer
 690884  691352 Ssl   0.0 p2p-accept-peer
 690884  760539 Ssl   0.0 p2p-discovery-d
 690884  763677 Ssl   0.0 p2p-accept-peer
 690884  763962 Ssl   0.0 p2p-discovery-d
 690884  764120 Ssl   0.0 p2p-connect-pee
 690884  764247 Ssl   0.0 p2p-discovery-d
 690884  772074 Ssl   0.0 p2p-discovery-d
 690884  772130 Ssl   0.0 p2p-connect-pee
 690884  775930 Rsl  89.8 synergy-validat
 690884  775932 Rsl  89.3 synergy-validat
 690884  775963 Rsl  84.5 synergy-validat
 690884  775970 Ssl   0.0 p2p-discovery-d
 690884  775971 Ssl   1.3 p2p-discovery-d
 690884  775972 Ssl   1.7 p2p-discovery-d
 690884  776007 Ssl   0.0 reqwest-interna
 690884  776008 Ssl   0.0 tokio-rt-worker
--- fd-count ---
63
--- service-show ---
Restart=on-failure
RestartUSec=5s
MainPID=690884
ExecMainStartTimestamp=Sat 2026-07-04 04:51:40 CEST
ExecMainPID=690884
MemoryCurrent=6509432832
CPUUsageNSec=12132298082000
User=node
Group=node
~~~

### Recent Service Logs

~~~text
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "count": 4,
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "from_height": 760983,
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "host": "73.79.66.255",
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "min_serve_interval_secs": 2,
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "peer": "73.79.66.255:5622"
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:45 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "count": 4,
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "from_height": 760983,
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "host": "relay1.synergynode.xyz",
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "min_serve_interval_secs": 2,
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "peer": "relay1.synergynode.xyz:5622"
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:45 UTC] [DEBUG] [p2p] Ping received
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "peer": "relay1.synergynode.xyz:5622"
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:45 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "count": 4,
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "from_height": 760983,
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "host": "relay2.synergynode.xyz",
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "min_serve_interval_secs": 2,
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "peer": "relay2.synergynode.xyz:5622"
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:45 UTC] [DEBUG] [p2p] Ping received
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "peer": "relay2.synergynode.xyz:5622"
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:45 UTC] [INFO] [p2p] Received status
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "height": 0,
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "peer": "bootnode3.synergynode.xyz:5620"
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:45 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "count": 65,
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "from_height": 0,
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "host": "109.199.104.37",
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "min_serve_interval_secs": 2,
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "peer": "109.199.104.37:5622"
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:45 UTC] [DEBUG] [p2p] Ping received
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "peer": "109.199.104.37:5622"
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:45 UTC] [INFO] [p2p] Received status
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "height": 0,
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "peer": "109.199.104.37:5622"
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:45 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "count": 4,
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "from_height": 760983,
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "host": "relay1.synergynode.xyz",
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "min_serve_interval_secs": 2,
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "peer": "relay1.synergynode.xyz:5622"
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:45 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "count": 4,
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "from_height": 760983,
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "host": "relay2.synergynode.xyz",
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "min_serve_interval_secs": 2,
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "peer": "relay2.synergynode.xyz:5622"
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:45 UTC] [DEBUG] [p2p] Ping received
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]:   "peer": "194.163.183.166:5622"
Jul 04 12:19:45 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:46 UTC] [DEBUG] [p2p] Serving block sync response
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "count": 4,
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "from_height": 760983,
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "host": "relay2.synergynode.xyz",
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "max_blocks": 64,
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "peer": "relay2.synergynode.xyz:5622"
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:46 UTC] [DEBUG] [p2p] Ping received
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "peer": "relay2.synergynode.xyz:5622"
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:46 UTC] [DEBUG] [p2p] Serving block sync response
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "count": 4,
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "from_height": 760983,
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "host": "relay1.synergynode.xyz",
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "max_blocks": 64,
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "peer": "relay1.synergynode.xyz:5622"
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:46 UTC] [DEBUG] [p2p] Ping received
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "peer": "relay1.synergynode.xyz:5622"
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:46 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "count": 4,
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "from_height": 760983,
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "host": "relay2.synergynode.xyz",
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "min_serve_interval_secs": 2,
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "peer": "relay2.synergynode.xyz:5622"
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:46 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "count": 4,
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "from_height": 760983,
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "host": "relay1.synergynode.xyz",
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "min_serve_interval_secs": 2,
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "peer": "relay1.synergynode.xyz:5622"
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:46 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "peer": "109.199.104.37:58034"
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:46 UTC] [INFO] [p2p] Handshake received
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "consensus_version": "posy/1.0.0",
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789",
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "network_magic_bytes": "ec6a253c",
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "node_id": "synv11um0ddw94q7rph09ymd88dr8hhzmufnwtslz",
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "peer": "109.199.104.37:58034",
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "protocol_version": "1.0.0",
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "public_address": "109.199.104.37:5622",
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "validator_address": "synv11um0ddw94q7rph09ymd88dr8hhzmufnwtslz",
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "version": "1.0.0"
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:46 UTC] [INFO] [p2p] Received status
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "height": 0,
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "peer": "109.199.104.37:58034"
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:46 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "peer": "bootnode3.synergynode.xyz:5620"
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:46 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "peer": "146.190.210.121:33598"
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:46 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "count": 65,
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "from_height": 0,
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "host": "109.199.104.37",
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "min_serve_interval_secs": 2,
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "peer": "109.199.104.37:58034"
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:46 UTC] [INFO] [p2p] Received status
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "height": 0,
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "peer": "109.199.104.37:58034"
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:46 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "count": 65,
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "from_height": 0,
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "host": "109.199.104.37",
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "min_serve_interval_secs": 2,
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]:   "peer": "109.199.104.37:58034"
Jul 04 12:19:46 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:47 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "count": 4,
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "from_height": 760983,
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "host": "relay1.synergynode.xyz",
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "min_serve_interval_secs": 2,
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "peer": "relay1.synergynode.xyz:5622"
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:47 UTC] [DEBUG] [p2p] Ping received
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "peer": "relay1.synergynode.xyz:5622"
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:47 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "count": 4,
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "from_height": 760983,
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "host": "relay2.synergynode.xyz",
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "min_serve_interval_secs": 2,
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "peer": "relay2.synergynode.xyz:5622"
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:47 UTC] [DEBUG] [p2p] Ping received
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "peer": "relay2.synergynode.xyz:5622"
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:47 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "count": 4,
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "from_height": 760983,
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "host": "relay2.synergynode.xyz",
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "min_serve_interval_secs": 2,
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "peer": "relay2.synergynode.xyz:5622"
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:47 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "count": 4,
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "from_height": 760983,
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "host": "relay1.synergynode.xyz",
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "min_serve_interval_secs": 2,
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "peer": "relay1.synergynode.xyz:5622"
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:47 UTC] [DEBUG] [p2p] Serving block sync response
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "count": 65,
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "from_height": 0,
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "host": "109.199.104.37",
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "max_blocks": 64,
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "peer": "109.199.104.37:58034"
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:47 UTC] [WARN] [p2p] Refusing deep support-peer block sync request
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "from_height": 0,
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "max_support_peer_deep_sync_lag": 64000,
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "peer": "109.199.104.37:58034"
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]: }
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]: [2026-07-04 10:19:47 UTC] [DEBUG] [p2p] Ping received
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   Metadata: {
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]:   "peer": "109.199.104.37:58034"
Jul 04 12:19:47 vmi3371822 synergy-validator[690884]: }
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
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783119261-1783119261703136356-proposals-above-760985/manifest.json	1120 bytes	2026-07-04T00:54:21.7045162450Z
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783120451-1783120451486570760-proposals-above-760986/manifest.json	1120 bytes	2026-07-04T01:14:11.4869132860Z
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783121754-1783121754894119849-proposals-above-760986/manifest.json	1120 bytes	2026-07-04T01:35:54.8975741260Z
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783122608-1783122608063170628-proposals-above-760986/manifest.json	1120 bytes	2026-07-04T01:50:08.0642341530Z
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783123373-1783123373613427615-proposals-above-760986/manifest.json	1120 bytes	2026-07-04T02:02:53.6139592980Z
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783124176-1783124176475074740-proposals-above-760986/manifest.json	1120 bytes	2026-07-04T02:16:16.4762944740Z
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783125165-1783125165642143959-proposals-above-760986/manifest.json	1120 bytes	2026-07-04T02:32:45.6443404340Z
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783126049-1783126049300445339-proposals-above-760986/manifest.json	1120 bytes	2026-07-04T02:47:29.2992296680Z
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783126873-1783126873585523610-proposals-above-760986/manifest.json	1120 bytes	2026-07-04T03:01:13.5857048630Z
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783127393-1783127393233867123-proposals-above-760986/manifest.json	1120 bytes	2026-07-04T03:09:53.2336314780Z
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783127817-1783127817190973962-proposals-above-760986/manifest.json	1120 bytes	2026-07-04T03:16:57.1908283060Z
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783127990-1783127990460274207-proposals-above-760986/manifest.json	1120 bytes	2026-07-04T03:19:50.4630218800Z
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783128871-1783128871615181804-proposals-above-760986/manifest.json	1120 bytes	2026-07-04T03:34:31.6176553850Z
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783130142-1783130142669038170-proposals-above-760986/manifest.json	1120 bytes	2026-07-04T03:55:42.6691552570Z
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783130575-1783130575524978932-proposals-above-760986/manifest.json	1120 bytes	2026-07-04T04:02:55.5261148770Z
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783131265-1783131265866694242-proposals-above-760986/manifest.json	1120 bytes	2026-07-04T04:14:25.8669594760Z
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783131486-1783131486916851708-proposals-above-760986/manifest.json	1120 bytes	2026-07-04T04:18:06.9189421090Z
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783132566-1783132566630722174-proposals-above-760986/manifest.json	1120 bytes	2026-07-04T04:36:06.6303753350Z
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783133500-1783133500332890276-proposals-above-760986/manifest.json	1120 bytes	2026-07-04T04:51:40.3330107420Z
/var/lib/synergy/validator/data/consensus_recovery_evidence/1783160372-1783160372978913426-proposals-above-760985/manifest.json	1125 bytes	2026-07-04T12:19:32.9831069650Z
~~~
