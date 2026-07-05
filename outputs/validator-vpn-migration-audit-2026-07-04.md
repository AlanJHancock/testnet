# Validator VPN Migration Audit - 2026-07-04

## Scope

Target machines:

- synergy-val1
- synergy-val2
- synergy-val3
- synergy-val4
- synergy-val5
- synergy-val6
- synergy-relayer1
- synergy-relayer2
- synergy-relayer3

Required order:

1. Audit all nine machines.
2. Disable old VPN material everywhere with backups.
3. Install and activate the new validator/relayer VPN architecture.
4. Normalize validator and relayer configs from canonical source.
5. Verify VPN/config/runtime topology before consensus start.
6. Start consensus only after all pre-start checks pass.
7. Verify chain health after startup.

## Safety Rules

- Do not start or restart consensus while old VPN material is still active.
- Do not delete chain data.
- Do not print, commit, or log private keys, sudo passwords, or credentials.
- Use workbook-backed `ssh synergy-*` aliases only.
- Preserve backups before disabling old VPN material.

## Pre-Migration Audit

Pending.

## Old VPN Disablement

Pending.

## New VPN Rollout

Pending.

## Config And Runtime Normalization

Pending.

## Pre-Start Verification

Pending.

## Controlled Startup

Pending.

## Post-Startup Verification

Pending.

## Final Topology

Pending.
