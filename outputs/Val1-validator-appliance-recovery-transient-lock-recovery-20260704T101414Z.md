# Validator Appliance Transient Vote Lock Recovery

generated_utc: 2026-07-04T10:14:14Z
phase: transient-lock-recovery
execute: true

spreadsheet_row_used=true row=15 node=Val1 ssh='ssh synergy-val1' user='justin' public_ip='62.146.182.207' qrpc='5640' ws='5660' metrics='6030'
## Transient Vote Lock Recovery Gate

~~~text
target_node=Val1
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
      "age_seconds": 47,
      "block_hash": "34b2225ef5704ca52daef2f1350952a2a613fee63bc9b11db7200dd9218fc938",
      "epoch": 760,
      "first_round": 1,
      "height": 760987,
      "latest_round": 2132,
      "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
      "validator_address": "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs"
    }
  ],
  "locks_above_finalized": 1,
  "parse_error": null,
  "stale_conflicting_heights_above_finalized": [],
  "stale_locks": [
    {
      "age_seconds": 47,
      "block_hash": "34b2225ef5704ca52daef2f1350952a2a613fee63bc9b11db7200dd9218fc938",
      "epoch": 760,
      "first_round": 1,
      "height": 760987,
      "latest_round": 2132,
      "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
      "validator_address": "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs"
    }
  ],
  "stale_locks_above_finalized": 1,
  "stale_threshold_seconds": 30,
  "total_vote_locks": 271,
  "vote_lock_path": "/var/lib/synergy/validator/data/consensus_vote_locks.json"
}
~~~

### latest-before

~~~json
{"elapsed_sec": 6.054, "error": "timed out"}
~~~

## Supported Runtime Recovery

~~~json
{"elapsed_sec": 0.095, "response": {"id": 1, "jsonrpc": "2.0", "result": {"canonical_locks_mutated": false, "chain": {"chain_id": 1264, "chain_id_hex": "0x4f0", "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "network_id": "synergy-testnet-v2"}, "committed_qcs_mutated": false, "finalized_height": 760985, "keys_or_configs_copied": false, "proposal_cache_recovery": {"action": "recover_cached_block_proposals_above_finalized_height", "archived": [], "archived_count": 0, "evidence_dir": "", "finalized_height": 760985, "mutated": false, "proposal_cache_dir": "/var/lib/synergy/validator/data/consensus_proposals", "reason": "operator_approved_stopped_validator_quarantine", "scanned_count": 7, "timestamp": 1783160109}, "vote_lock_recovery": {"action": "recover_transient_vote_locks_above_finalized_height", "before_count": 271, "evidence_path": "", "finalized_height": 760985, "kept_count": 271, "min_age_secs": 30, "mutated": false, "reason": "operator_approved_stopped_validator_quarantine", "removed": [], "removed_count": 0, "timestamp": 1783160109, "vote_lock_path": "/var/lib/synergy/validator/data/consensus_vote_locks.json"}}}}
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
      "age_seconds": 3,
      "block_hash": "34b2225ef5704ca52daef2f1350952a2a613fee63bc9b11db7200dd9218fc938",
      "epoch": 760,
      "first_round": 1,
      "height": 760987,
      "latest_round": 2135,
      "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
      "validator_address": "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs"
    }
  ],
  "fresh_locks_above_finalized": 1,
  "locks": [
    {
      "age_seconds": 3,
      "block_hash": "34b2225ef5704ca52daef2f1350952a2a613fee63bc9b11db7200dd9218fc938",
      "epoch": 760,
      "first_round": 1,
      "height": 760987,
      "latest_round": 2135,
      "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
      "validator_address": "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs"
    }
  ],
  "locks_above_finalized": 1,
  "parse_error": null,
  "stale_conflicting_heights_above_finalized": [],
  "stale_locks": [],
  "stale_locks_above_finalized": 0,
  "stale_threshold_seconds": 30,
  "total_vote_locks": 271,
  "vote_lock_path": "/var/lib/synergy/validator/data/consensus_vote_locks.json"
}
~~~

### latest-after

~~~json
{"elapsed_sec": 6.048, "error": "timed out"}
~~~

## Remote Validator Status

generated_utc: 2026-07-04T10:15:15Z
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
  "health": {"elapsed_sec": 6.052, "error": "timed out"},
  "latest": {"elapsed_sec": 6.056, "error": "timed out"},
  "block_number": {"elapsed_sec": 6.046, "error": "timed out"},
  "canonical_lock": {"elapsed_sec": 0.05, "response": {"id": 1, "jsonrpc": "2.0", "result": {"block_hash": "d736f234b2f1e7c524a20aa9787f48c3dd33b7c8fb703ab7edd73b8404d4ebef", "chain": {"chain_id": 1264, "chain_id_hex": "0x4f0", "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "name": "synergy-testnet-v2", "network_id": "synergy-testnet-v2"}, "found": true, "height": 760986, "parent_hash": "a77d4b894e284c4705620e377b2c37838ed2ee37429d019637470b9e93344936", "qc_block_hash": "d736f234b2f1e7c524a20aa9787f48c3dd33b7c8fb703ab7edd73b8404d4ebef", "qc_hash": "97b7d21037d78e40e3bd07d05f07a6536584a7934ad08c09f2a9d9bb3aecd86e", "transactions_root": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "validator_id": "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt", "written_at_unix_secs": 1783119184}}},
  "node_status": {"elapsed_sec": 6.051, "error": "timed out"},
  "peer_info": {"elapsed_sec": 0.044, "response": {"id": 1, "jsonrpc": "2.0", "result": {"peer_count": 7, "peers": [{"address": "bootnode3.synergynode.xyz:5620", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160121, "genesis_hash": "", "last_seen": 1783160121, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "73.79.66.255:38138", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160122, "genesis_hash": "", "last_seen": 1783160122, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "157.245.226.240:58602", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160111, "genesis_hash": "", "last_seen": 1783160111, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "bootnode2.synergynode.xyz:5620", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160121, "genesis_hash": "", "last_seen": 1783160121, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "73.79.66.255:54582", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783154116, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160135, "node_id": "archive-validator-01", "public_address": "archive.synergynode.xyz:5615", "txs_received": 0, "txs_sent": 0, "validator_address": "archive-validator-01", "version": "1.0.0"}, {"address": "157.245.226.240:55196", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160120, "genesis_hash": "", "last_seen": 1783160120, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "157.173.192.45:44780", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783154111, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160106, "node_id": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "public_address": "157.173.192.45:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "version": "1.0.0"}, {"address": "146.190.210.121:43284", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160111, "genesis_hash": "", "last_seen": 1783160111, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "209.145.50.9:5622", "blocks_received": 0, "blocks_sent": 537, "capabilities": ["blocks", "transactions"], "connected_at": 1783133577, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160136, "node_id": "observer", "public_address": "209.145.50.9:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv51q8t3jqkt6e0y6kdppwu0dskxuarqg3pquga6n7", "version": "1.0.0"}, {"address": "relay2.synergynode.xyz:5622", "blocks_received": 0, "blocks_sent": 250, "capabilities": ["blocks", "transactions"], "connected_at": 1783133577, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160139, "node_id": "sentry2", "public_address": "94.72.117.108:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv21xaqlq808sunuchd0jwr4m324h85fza2ps3s4k7", "version": "1.0.0"}, {"address": "194.163.183.166:5622", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160121, "genesis_hash": "", "last_seen": 1783160121, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "62.146.182.209:5622", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160121, "genesis_hash": "", "last_seen": 1783160121, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "62.146.182.208:5622", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160121, "genesis_hash": "", "last_seen": 1783160121, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "194.163.183.166:34820", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160109, "genesis_hash": "", "last_seen": 1783160109, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "146.190.210.121:45380", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160131, "genesis_hash": "", "last_seen": 1783160131, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "146.190.210.121:57490", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160121, "genesis_hash": "", "last_seen": 1783160121, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "relay1.synergynode.xyz:5622", "blocks_received": 0, "blocks_sent": 285, "capabilities": ["blocks", "transactions"], "connected_at": 1783133574, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160139, "node_id": "sentry1", "public_address": "195.26.241.95:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv21ga3nsdjagzt9pmks4mzjq4vdjyngdwq6jst632", "version": "1.0.0"}, {"address": "157.245.226.240:55192", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160120, "genesis_hash": "", "last_seen": 1783160120, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "146.190.210.121:57474", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160119, "genesis_hash": "", "last_seen": 1783160119, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}, {"address": "157.173.192.45:5622", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783133577, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783140922, "node_id": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "public_address": "157.173.192.45:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx", "version": "1.0.0"}, {"address": "109.199.104.37:33284", "blocks_received": 0, "blocks_sent": 0, "capabilities": ["blocks", "transactions"], "connected_at": 1783154112, "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", "last_seen": 1783160140, "node_id": "synv11um0ddw94q7rph09ymd88dr8hhzmufnwtslz", "public_address": "109.199.104.37:5622", "txs_received": 0, "txs_sent": 0, "validator_address": "synv11um0ddw94q7rph09ymd88dr8hhzmufnwtslz", "version": "1.0.0"}, {"address": "157.245.226.240:42732", "blocks_received": 0, "blocks_sent": 0, "capabilities": [], "connected_at": 1783160137, "genesis_hash": "", "last_seen": 1783160137, "node_id": null, "public_address": null, "txs_received": 0, "txs_sent": 0, "validator_address": null, "version": null}]}}}
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
2607566       1 Ssl     07:23:13  104  6.4 1591672 5420932 synergy-validat /opt/synergy/bin/synergy-validator start --config /etc/synergy/validator/config.toml
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
2607566 2659716 Ssl   0.3 p2p-accept-peer
2607566 2659721 Ssl   0.4 p2p-accept-peer
2607566 2659722 Ssl   0.2 p2p-accept-peer
2607566 2659766 Ssl   0.3 p2p-accept-peer
2607566 2659768 Ssl   0.5 p2p-accept-peer
2607566 2659769 Ssl   0.3 p2p-accept-peer
2607566 2659772 Ssl   0.3 p2p-accept-peer
2607566 2659773 Ssl   0.4 p2p-connect-pee
2607566 2659774 Ssl   0.6 p2p-connect-pee
2607566 2659775 Ssl   0.6 p2p-connect-pee
2607566 2659777 Ssl   0.8 p2p-connect-pee
2607566 2659778 Ssl   0.4 p2p-connect-pee
2607566 2659781 Ssl   0.4 p2p-accept-peer
2607566 2659793 Rsl  92.2 synergy-validat
2607566 2659801 Ssl   1.3 p2p-accept-peer
2607566 2659812 Ssl   0.0 synergy-validat
2607566 2659815 Ssl   2.0 p2p-accept-peer
--- fd-count ---
0
--- service-show ---
Restart=on-failure
RestartUSec=5s
MainPID=2607566
ExecMainStartTimestamp=Sat 2026-07-04 04:52:27 CEST
ExecMainPID=2607566
MemoryCurrent=7186354176
CPUUsageNSec=27753474023000
User=node
Group=node
~~~

### Recent Service Logs

~~~text
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "min_serve_interval_secs": 2,
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "peer": "relay1.synergynode.xyz:5622"
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:06 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "count": 65,
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "from_height": 0,
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "host": "109.199.104.37",
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "min_serve_interval_secs": 2,
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "peer": "109.199.104.37:5622"
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:06 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "count": 4,
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "from_height": 760983,
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "host": "relay2.synergynode.xyz",
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "min_serve_interval_secs": 2,
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "peer": "relay2.synergynode.xyz:5622"
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:06 UTC] [DEBUG] [p2p] Throttling block sync response
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "count": 65,
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "from_height": 0,
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "host": "109.199.104.37",
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "min_serve_interval_secs": 2,
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "peer": "109.199.104.37:5622"
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:06 UTC] [DEBUG] [p2p] Serving block sync response
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "count": 51,
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "from_height": 756248,
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "host": "209.145.50.9",
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "max_blocks": 64,
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "peer": "209.145.50.9:5622"
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:06 UTC] [INFO] [p2p] Vote sent
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "epoch": 760,
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "height": 760987,
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "proposer": "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "request_peer": "157.173.192.45:44780",
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "response_peer": "157.173.192.45:44780",
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]:   "round": 2135
Jul 04 12:15:06 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:09 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:09 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:15:09 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:09 vmi3226971 synergy-validator[2607566]:   "peer": "194.163.183.166:5622"
Jul 04 12:15:09 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:09 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:09 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:15:09 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:09 vmi3226971 synergy-validator[2607566]:   "peer": "194.163.183.166:34820"
Jul 04 12:15:09 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:09 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:09 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:15:09 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:09 vmi3226971 synergy-validator[2607566]:   "peer": "62.146.182.209:5622"
Jul 04 12:15:09 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:09 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:09 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:15:09 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:09 vmi3226971 synergy-validator[2607566]:   "peer": "62.146.182.209:44440"
Jul 04 12:15:09 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:10 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:10 UTC] [DEBUG] [p2p] Seed peer list request failed
Jul 04 12:15:10 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:10 vmi3226971 synergy-validator[2607566]:   "error": "error sending request for url (http://seed1.synergynode.xyz:5621/peer-list.json)",
Jul 04 12:15:10 vmi3226971 synergy-validator[2607566]:   "seed_server": "http://seed1.synergynode.xyz:5621"
Jul 04 12:15:10 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:11 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:11 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:15:11 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:11 vmi3226971 synergy-validator[2607566]:   "peer": "146.190.210.121:43284"
Jul 04 12:15:11 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:11 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:11 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:15:11 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:11 vmi3226971 synergy-validator[2607566]:   "peer": "157.245.226.240:58602"
Jul 04 12:15:11 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:15 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:15 UTC] [INFO] [p2p] Peer disconnected
Jul 04 12:15:15 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:15 vmi3226971 synergy-validator[2607566]:   "peer": "62.146.182.208:41318"
Jul 04 12:15:15 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:18 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:18 UTC] [WARN] [rpc] qRPC served read from fallback state
Jul 04 12:15:18 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:18 vmi3226971 synergy-validator[2607566]:   "reason": "chain_tip_lock_unavailable"
Jul 04 12:15:18 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:19 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:19 UTC] [DEBUG] [p2p] Failed to register self with seed server
Jul 04 12:15:19 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:19 vmi3226971 synergy-validator[2607566]:   "error": "error sending request for url (http://seed1.synergynode.xyz:5621/peers/register)",
Jul 04 12:15:19 vmi3226971 synergy-validator[2607566]:   "seed_server": "http://seed1.synergynode.xyz:5621"
Jul 04 12:15:19 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:19 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:19 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:15:19 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:19 vmi3226971 synergy-validator[2607566]:   "peer": "146.190.210.121:57474"
Jul 04 12:15:19 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:20 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:20 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:15:20 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:20 vmi3226971 synergy-validator[2607566]:   "peer": "157.245.226.240:55192"
Jul 04 12:15:20 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:20 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:20 UTC] [DEBUG] [p2p] Registered self with seed server
Jul 04 12:15:20 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:20 vmi3226971 synergy-validator[2607566]:   "dial": "62.146.182.207:5622",
Jul 04 12:15:20 vmi3226971 synergy-validator[2607566]:   "seed_server": "http://seed2.synergynode.xyz:5621"
Jul 04 12:15:20 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:20 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:20 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:15:20 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:20 vmi3226971 synergy-validator[2607566]:   "peer": "157.245.226.240:55196"
Jul 04 12:15:20 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:21 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "peer": "146.190.210.121:57490"
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:21 UTC] [DEBUG] [p2p] Registered self with seed server
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "dial": "62.146.182.207:5622",
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "seed_server": "http://seed3.synergynode.xyz:5621"
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:21 UTC] [INFO] [p2p] Resolved bootstrap dial targets
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "targets": "[\"157.173.192.45:5622\", \"194.163.183.166:5622\", \"209.145.50.9:5622\", \"62.146.182.208:5622\", \"62.146.182.209:5622\", \"73.79.66.255:5622\", \"archive.synergynode.xyz:5615\", \"bootnode1.synergynode.xyz:5620\", \"bootnode2.synergynode.xyz:5620\", \"bootnode3.synergynode.xyz:5620\", \"relay1.synergynode.xyz:5622\", \"relay2.synergynode.xyz:5622\", \"rpc.synergynode.xyz:5623\", \"seed1.synergynode.xyz:5621\", \"seed2.synergynode.xyz:5621\", \"seed3.synergynode.xyz:5621\"]"
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:21 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "connected_age_secs": 65,
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "direction": "Outgoing",
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "has_identifying_metadata": false,
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "has_remote_status": false,
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "last_seen_age_secs": 65,
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "peer": "seed2.synergynode.xyz:5621",
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "validator_address": ""
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:21 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "connected_age_secs": 65,
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "direction": "Outgoing",
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "has_identifying_metadata": false,
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "has_remote_status": false,
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "last_seen_age_secs": 5,
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "peer": "rpc.synergynode.xyz:5623",
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "validator_address": ""
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:21 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "connected_age_secs": 65,
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "direction": "Outgoing",
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "has_identifying_metadata": false,
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "has_remote_status": false,
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "last_seen_age_secs": 65,
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "peer": "seed3.synergynode.xyz:5621",
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "validator_address": ""
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:21 UTC] [WARN] [p2p] Disconnecting stale peer to force mesh recovery
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "connected_age_secs": 65,
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "direction": "Outgoing",
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "has_identifying_metadata": true,
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "has_remote_status": false,
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "last_seen_age_secs": 13,
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "peer": "73.79.66.255:5622",
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "validator_address": ""
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:21 UTC] [WARN] [p2p] Failed to request peers
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "error": "Broken pipe (os error 32)",
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "peer": "157.245.226.240:55196"
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:21 UTC] [WARN] [p2p] Failed to request peers
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "error": "Broken pipe (os error 32)",
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "peer": "157.245.226.240:55192"
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:21 UTC] [WARN] [p2p] Failed to request peers
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "error": "Broken pipe (os error 32)",
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "peer": "146.190.210.121:57474"
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:21 UTC] [WARN] [p2p] Failed to request status
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "error": "Broken pipe (os error 32)",
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "peer": "157.245.226.240:55196"
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:21 UTC] [WARN] [p2p] Failed to request status
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "error": "Broken pipe (os error 32)",
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "peer": "157.245.226.240:55192"
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:21 UTC] [WARN] [p2p] Failed to request status
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "error": "Broken pipe (os error 32)",
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]:   "peer": "146.190.210.121:57474"
Jul 04 12:15:21 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:22 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:22 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:15:22 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:22 vmi3226971 synergy-validator[2607566]:   "peer": "73.79.66.255:38138"
Jul 04 12:15:22 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:24 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:24 UTC] [WARN] [rpc] qRPC served read from fallback state
Jul 04 12:15:24 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:24 vmi3226971 synergy-validator[2607566]:   "reason": "chain_tip_lock_unavailable"
Jul 04 12:15:24 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:26 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:26 UTC] [WARN] [p2p] Failed to dial peer
Jul 04 12:15:26 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:26 vmi3226971 synergy-validator[2607566]:   "error": "connection timed out",
Jul 04 12:15:26 vmi3226971 synergy-validator[2607566]:   "peer": "bootnode1.synergynode.xyz:5620"
Jul 04 12:15:26 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:26 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:26 UTC] [WARN] [p2p] Failed to dial peer
Jul 04 12:15:26 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:26 vmi3226971 synergy-validator[2607566]:   "error": "connection timed out",
Jul 04 12:15:26 vmi3226971 synergy-validator[2607566]:   "peer": "seed1.synergynode.xyz:5621"
Jul 04 12:15:26 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:29 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:29 UTC] [WARN] [rpc] qRPC served read from fallback state
Jul 04 12:15:29 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:29 vmi3226971 synergy-validator[2607566]:   "reason": "chain_tip_lock_unavailable"
Jul 04 12:15:29 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:31 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:31 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:15:31 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:31 vmi3226971 synergy-validator[2607566]:   "peer": "146.190.210.121:45380"
Jul 04 12:15:31 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:36 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:36 UTC] [WARN] [rpc] qRPC served read from fallback state
Jul 04 12:15:36 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:36 vmi3226971 synergy-validator[2607566]:   "reason": "chain_tip_lock_unavailable"
Jul 04 12:15:36 vmi3226971 synergy-validator[2607566]: }
Jul 04 12:15:37 vmi3226971 synergy-validator[2607566]: [2026-07-04 10:15:37 UTC] [INFO] [p2p] Incoming peer connection
Jul 04 12:15:37 vmi3226971 synergy-validator[2607566]:   Metadata: {
Jul 04 12:15:37 vmi3226971 synergy-validator[2607566]:   "peer": "157.245.226.240:42732"
Jul 04 12:15:37 vmi3226971 synergy-validator[2607566]: }
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
