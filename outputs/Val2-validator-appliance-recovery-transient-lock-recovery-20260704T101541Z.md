# Validator Appliance Transient Vote Lock Recovery

generated_utc: 2026-07-04T10:15:41Z
phase: transient-lock-recovery
execute: true

spreadsheet_row_used=true row=16 node=Val2 ssh='ssh synergy-val2' user='rob' public_ip='62.146.182.208' qrpc='5640' ws='5660' metrics='6030'
## Transient Vote Lock Recovery Gate

~~~text
target_node=Val2
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
      "age_seconds": 37,
      "block_hash": "34b2225ef5704ca52daef2f1350952a2a613fee63bc9b11db7200dd9218fc938",
      "epoch": 760,
      "first_round": 6,
      "height": 760987,
      "latest_round": 2177,
      "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
      "validator_address": "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt"
    }
  ],
  "locks_above_finalized": 1,
  "parse_error": null,
  "stale_conflicting_heights_above_finalized": [],
  "stale_locks": [
    {
      "age_seconds": 37,
      "block_hash": "34b2225ef5704ca52daef2f1350952a2a613fee63bc9b11db7200dd9218fc938",
      "epoch": 760,
      "first_round": 6,
      "height": 760987,
      "latest_round": 2177,
      "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
      "validator_address": "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt"
    }
  ],
  "stale_locks_above_finalized": 1,
  "stale_threshold_seconds": 30,
  "total_vote_locks": 535,
  "vote_lock_path": "/var/lib/synergy/validator/data/consensus_vote_locks.json"
}
~~~

### latest-before

~~~json
{"elapsed_sec": 6.055, "error": "timed out"}
~~~

## Supported Runtime Recovery

~~~json
{"elapsed_sec": 0.092, "response": {"id": 1, "jsonrpc": "2.0", "result": {"canonical_locks_mutated": false, "chain": {"chain_id": 1264, "chain_id_hex": "0x4f0", "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "network_id": "synergy-testnet-v2"}, "committed_qcs_mutated": false, "finalized_height": 760985, "keys_or_configs_copied": false, "proposal_cache_recovery": {"action": "recover_cached_block_proposals_above_finalized_height", "archived": [], "archived_count": 0, "evidence_dir": "", "finalized_height": 760985, "mutated": false, "proposal_cache_dir": "/var/lib/synergy/validator/data/consensus_proposals", "reason": "operator_approved_stopped_validator_quarantine", "scanned_count": 0, "timestamp": 1783160195}, "vote_lock_recovery": {"action": "recover_transient_vote_locks_above_finalized_height", "before_count": 535, "evidence_path": "/var/lib/synergy/validator/data/consensus_recovery_evidence/1783160195-1783160195519633413-transient-vote-locks-above-760985.json", "finalized_height": 760985, "kept_count": 534, "min_age_secs": 30, "mutated": true, "reason": "operator_approved_stopped_validator_quarantine", "removed": [{"block_hash": "34b2225ef5704ca52daef2f1350952a2a613fee63bc9b11db7200dd9218fc938", "block_index": 760987, "created_at": 1783133676, "epoch_number": 760, "first_round_number": 6, "latest_round_number": 2177, "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "updated_at": 1783160152, "validator_address": "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt"}], "removed_count": 1, "timestamp": 1783160195, "vote_lock_path": "/var/lib/synergy/validator/data/consensus_vote_locks.json"}}}}
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
  "total_vote_locks": 534,
  "vote_lock_path": "/var/lib/synergy/validator/data/consensus_vote_locks.json"
}
~~~

### latest-after

~~~json
{"elapsed_sec": 6.044, "error": "timed out"}
~~~

## Remote Validator Status

generated_utc: 2026-07-04T10:16:41Z
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
  "health": {"elapsed_sec": 6.046, "error": "timed out"},
  "latest": {"elapsed_sec": 6.045, "error": "timed out"},
  "block_number": {"elapsed_sec": 6.047, "error": "timed out"},
  "canonical_lock": {"elapsed_sec": 0.048, "response": {"id": 1, "jsonrpc": "2.0", "result": {"block_hash": "d736f234b2f1e7c524a20aa9787f48c3dd33b7c8fb703ab7edd73b8404d4ebef", "chain": {"chain_id": 1264, "chain_id_hex": "0x4f0", "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "name": "synergy-testnet-v2", "network_id": "synergy-testnet-v2"}, "found": true, "height": 760986, "parent_hash": "a77d4b894e284c4705620e377b2c37838ed2ee37429d019637470b9e93344936", "qc_block_hash": "d736f234b2f1e7c524a20aa9787f48c3dd33b7c8fb703ab7edd73b8404d4ebef", "qc_hash": "97b7d21037d78e40e3bd07d05f07a6536584a7934ad08c09f2a9d9bb3aecd86e", "transactions_root": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "validator_id": "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt", "written_at_unix_secs": 1783119175}}},
  "node_status": {"elapsed_sec": 6.056, "error": "timed out"},
  "peer_info": {"elapsed_sec": 0.063, "response": {"id": 1, "jsonrpc": "2.0", "result": {"peer_count": 8, "peers": [{"address": "73.79.66.255:57738", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783155413, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160227, "node_id": "archive-validator-01", "public_address": "archive.synergynode.xyz:5615", "txs_received": 0, "txs_sent": 0, "validator_address": "archive-validator-01", "version": "1.0.0"}, {"address": "62.146.182.209:47878", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783155265, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160200, "node_id": "genesisval3", "public_address": "62.146.182.209:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re", "version": "1.0.0"}, {"address": "bootnode3.synergynode.xyz:5620", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160201, "genesis_hash": "", "last_seen": 1783160201, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "73.79.66.255:55484", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160208, "genesis_hash": "", "last_seen": 1783160208, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "relay1.synergynode.xyz:5622", "blocks_received": 0, "blocks_sent": 268, "capabilities": ["blocks", "transactions"], "connected_at": 1783133621, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160226, "node_id": "sentry1", "public_address": "195.26.241.95:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv21ga3nsdjagzt9pmks4mzjq4vdjyngdwq6jst632", "version": "1.0.0"}, {"address": "bootnode1.synergynode.xyz:5620", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783155085, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783155158, "node_id": "bootnode1", "public_address": "bootnode1.synergynode.xyz:5620", "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": "1.0.0"}, {"address": "62.146.182.207:47912", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160208, "genesis_hash": "", "last_seen": 1783160208, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "157.173.192.45:44732", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783155406, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160201, "node_id": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "public_address": "157.173.192.45:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "version": "1.0.0"}, {"address": "209.145.50.9:5622", "blocks_received": 0, "blocks_sent": 531, "capabilities": ["blocks", "transactions"], "connected_at": 1783133623, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160225, "node_id": "observer", "public_address": "209.145.50.9:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv51q8t3jqkt6e0y6kdppwu0dskxuarqg3pquga6n7", "version": "1.0.0"}, {"address": "157.245.226.240:34732", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160214, "genesis_hash": "", "last_seen": 1783160214, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "bootnode2.synergynode.xyz:5620", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160201, "genesis_hash": "", "last_seen": 1783160201, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "157.173.192.45:5622", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783133623, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783147613, "node_id": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "public_address": "157.173.192.45:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "version": "1.0.0"}, {"address": "194.163.183.166:56230", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160226, "genesis_hash": "", "last_seen": 1783160226, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "relay2.synergynode.xyz:5622", "blocks_received": 0, "blocks_sent": 256, "capabilities": ["blocks", "transactions"], "connected_at": 1783133623, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160227, "node_id": "sentry2", "public_address": "94.72.117.108:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv21xaqlq808sunuchd0jwr4m324h85fza2ps3s4k7", "version": "1.0.0"}, {"address": "170.64.187.206:53124", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783155125, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783155158, "node_id": "bootnode1", "public_address": "bootnode1.synergynode.xyz:5620", "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": "1.0.0"}, {"address": "109.199.104.37:43688", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783155404, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160227, "node_id": "synv11um0ddw94q7rph09ymd88dr8hhzmufnwtslz", "public_address": "109.199.104.37:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11um0ddw94q7rph09ymd88dr8hhzmufnwtslz", "version": "1.0.0"}, {"address": "146.190.210.121:39048", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160207, "genesis_hash": "", "last_seen": 1783160207, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}]}}}
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
1245680       1 Ssl     07:23:54  104  6.3 1567216 5293916 synergy-validat /opt/synergy/bin/synergy-validator start --config /etc/synergy/validator/config.toml
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
1245680 1305140 Ssl   0.2 p2p-connect-pee
1245680 1305141 Ssl   0.2 p2p-connect-pee
1245680 1305151 Ssl   0.2 p2p-accept-peer
1245680 1305155 Ssl   0.3 p2p-accept-peer
1245680 1305159 Ssl   0.3 p2p-accept-peer
1245680 1305168 Ssl   0.4 p2p-accept-peer
1245680 1305172 Rsl  84.8 synergy-validat
1245680 1305191 Ssl   0.0 synergy-validat
1245680 1305201 Ssl   4.1 p2p-accept-peer
1245680 1305213 Ssl  37.5 p2p-accept-peer
--- fd-count ---
0
--- service-show ---
Restart=on-failure
RestartUSec=5s
MainPID=1245680
ExecMainStartTimestamp=Sat 2026-07-04 04:53:13 CEST
ExecMainPID=1245680
MemoryCurrent=1961508864
CPUUsageNSec=27779993726000
User=node
Group=node
~~~

### Recent Service Logs

~~~text
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "min_serve_interval_secs": 2,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "peer": "109.199.104.37:5622"
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:41 UTC] [INFO] [p2p] Vote sent
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "epoch": 760,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "height": 760987,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "request_peer": "157.173.192.45:44732",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "response_peer": "157.173.192.45:44732",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "round": 2179
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:41 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "count": 65,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "from_height": 0,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "host": "109.199.104.37",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "min_serve_interval_secs": 2,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "peer": "109.199.104.37:5622"
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:41 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "count": 65,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "from_height": 0,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "host": "109.199.104.37",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "min_serve_interval_secs": 2,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "peer": "109.199.104.37:5622"
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:41 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "count": 65,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "from_height": 0,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "host": "109.199.104.37",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "min_serve_interval_secs": 2,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "peer": "109.199.104.37:5622"
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:41 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "count": 65,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "from_height": 0,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "host": "109.199.104.37",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "min_serve_interval_secs": 2,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "peer": "109.199.104.37:5622"
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:41 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "count": 65,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "from_height": 0,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "host": "109.199.104.37",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "min_serve_interval_secs": 2,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "peer": "109.199.104.37:5622"
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:41 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "count": 65,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "from_height": 0,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "host": "109.199.104.37",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "min_serve_interval_secs": 2,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "peer": "109.199.104.37:5622"
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:41 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "count": 65,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "from_height": 0,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "host": "109.199.104.37",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "min_serve_interval_secs": 2,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "peer": "109.199.104.37:5622"
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:41 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "count": 65,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "from_height": 0,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "host": "109.199.104.37",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "min_serve_interval_secs": 2,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "peer": "109.199.104.37:5622"
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:41 UTC] [INFO] [p2p] Received vote request
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "epoch": 760,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "height": 760987,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "peer": "157.173.192.45:44732",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "round": 2180
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:41 UTC] [DEBUG] [p2p] Serving block sync response
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "count": 51,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "from_height": 756248,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "host": "209.145.50.9",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "max_blocks": 64,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "peer": "209.145.50.9:5622"
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:41 UTC] [INFO] [p2p] Vote sent
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "epoch": 760,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "height": 760987,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "request_peer": "157.173.192.45:44732",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "response_peer": "157.173.192.45:44732",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "round": 2180
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:41 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "connected_age_secs": 48,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "direction": "Outgoing",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "has_identifying_metadata": false,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "has_remote_status": false,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "last_seen_age_secs": 0,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "peer": "rpc.synergynode.xyz:5623",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "validator_address": ""
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:41 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "connected_age_secs": 48,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "direction": "Outgoing",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "has_identifying_metadata": false,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "has_remote_status": false,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "last_seen_age_secs": 1,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "peer": "62.146.182.207:5622",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "validator_address": ""
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:41 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "connected_age_secs": 48,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "direction": "Outgoing",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "has_identifying_metadata": false,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "has_remote_status": false,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "last_seen_age_secs": 48,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "peer": "seed3.synergynode.xyz:5621",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "validator_address": ""
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:41 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "connected_age_secs": 86,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "direction": "Outgoing",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "has_identifying_metadata": true,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "has_remote_status": false,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "last_seen_age_secs": 49,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "peer": "194.163.183.166:5622",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "validator_address": ""
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:41 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "connected_age_secs": 48,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "direction": "Outgoing",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "has_identifying_metadata": false,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "has_remote_status": false,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "last_seen_age_secs": 48,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "peer": "seed2.synergynode.xyz:5621",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "validator_address": ""
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:41 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "connected_age_secs": 86,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "direction": "Outgoing",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "has_identifying_metadata": true,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "has_remote_status": false,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "last_seen_age_secs": 1,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "peer": "73.79.66.255:5622",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "validator_address": ""
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:41 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "connected_age_secs": 51,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "direction": "Incoming",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "has_identifying_metadata": true,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "has_remote_status": false,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "last_seen_age_secs": 49,
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "peer": "194.163.183.166:55162",
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]:   "validator_address": ""
Jul 04 12:16:41 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:42 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:42 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:16:42 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:42 vmi3226972 synergy-validator[1245680]:   "peer": "157.245.226.240:49422"
Jul 04 12:16:42 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:42 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:42 UTC] [WARN] [rpc] qRPC served read from fallback state
Jul 04 12:16:42 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:42 vmi3226972 synergy-validator[1245680]:   "reason": "chain_tip_lock_unavailable"
Jul 04 12:16:42 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:46 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:46 UTC] [WARN] [p2p] Failed to dial peer
Jul 04 12:16:46 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:46 vmi3226972 synergy-validator[1245680]:   "error": "connection timed out",
Jul 04 12:16:46 vmi3226972 synergy-validator[1245680]:   "peer": "seed1.synergynode.xyz:5621"
Jul 04 12:16:46 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:47 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:47 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:16:47 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:47 vmi3226972 synergy-validator[1245680]:   "peer": "146.190.210.121:39048"
Jul 04 12:16:47 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:48 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:48 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:16:48 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:48 vmi3226972 synergy-validator[1245680]:   "peer": "62.146.182.207:47912"
Jul 04 12:16:48 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:48 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:48 UTC] [WARN] [rpc] qRPC served read from fallback state
Jul 04 12:16:48 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:48 vmi3226972 synergy-validator[1245680]:   "reason": "chain_tip_lock_unavailable"
Jul 04 12:16:48 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:48 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:48 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:16:48 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:48 vmi3226972 synergy-validator[1245680]:   "peer": "73.79.66.255:55484"
Jul 04 12:16:48 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:54 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:54 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:16:54 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:54 vmi3226972 synergy-validator[1245680]:   "peer": "157.245.226.240:34732"
Jul 04 12:16:54 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:16:55 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:16:55 UTC] [WARN] [rpc] qRPC served read from fallback state
Jul 04 12:16:55 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:16:55 vmi3226972 synergy-validator[1245680]:   "reason": "chain_tip_lock_unavailable"
Jul 04 12:16:55 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:17:01 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:17:01 UTC] [WARN] [rpc] qRPC served read from fallback state
Jul 04 12:17:01 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:17:01 vmi3226972 synergy-validator[1245680]:   "reason": "chain_tip_lock_unavailable"
Jul 04 12:17:01 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:17:06 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:17:06 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:17:06 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:17:06 vmi3226972 synergy-validator[1245680]:   "peer": "194.163.183.166:56230"
Jul 04 12:17:06 vmi3226972 synergy-validator[1245680]: }
Jul 04 12:17:07 vmi3226972 synergy-validator[1245680]: [2026-07-04 10:17:07 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:17:07 vmi3226972 synergy-validator[1245680]:   Metadata: {
Jul 04 12:17:07 vmi3226972 synergy-validator[1245680]:   "peer": "146.190.210.121:38238"
Jul 04 12:17:07 vmi3226972 synergy-validator[1245680]: }
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
