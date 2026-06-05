# Synergy Testnet Observability Dashboard Guide

This guide explains the observer-backed Grafana dashboards in `ops/observability/grafana`.
Prometheus scrapes the observer, validators, relayers, Archive Validator, public edge probes, and node_exporter host metrics from the observer node. Validator, relayer, and archive Synergy app metrics come from `/metrics` on port `6030`; generic host metrics come from node_exporter on port `9100`.

## Percentiles: p50, p95, and p99

Percentiles show the shape of a group of measurements instead of only showing the average.

- `p50` is the median. Half of the measurements were at or below this value, and half were above it.
- `p95` means 95% of measurements were at or below this value. The slowest 5% were above it.
- `p99` means 99% of measurements were at or below this value. The slowest 1% were above it.

For a latency graph, `p50 = 2s`, `p95 = 4s`, and `p99 = 9s` means typical behavior is about 2 seconds, but the slowest tail sometimes stretches much higher. p95 and p99 are useful because averages can hide short stalls.

## Network Overview

File: `ops/observability/grafana/network-overview.json`

Purpose: gives a fast read on whether the network is alive, whether the observer is scraping expected services, whether public endpoints are reachable, and whether block production is moving.

Panels:

- `Validator App Scrapes Up`: count of validator `/metrics` targets currently reachable by Prometheus. Expected value is 5 for the current genesis validator set.
- `Relayer App Scrapes Up`: count of relayer `/metrics` targets currently reachable.
- `Observer Scrape Up`: whether Prometheus can scrape the observer process itself.
- `Private Host Scrapes Up`: count of private WireGuard node_exporter targets reachable on port `9100`.
- `Public HTTPS Probes Up`: public HTTPS health checks that returned success through blackbox_exporter.
- `Public TCP Probes Up`: public bootnode and seed TCP checks that returned success.
- `Block Height by Node`: local block height reported by each scraped Synergy node. Validators should stay close together. Archive Validator height is displayed as archive state, not voting consensus state.
- `Block Production Rate`: per-validator block-height change rate converted to blocks per minute. A flat zero line means no new blocks from that node over the selected window.
- `Average Block Time`: average seconds per block over the selected window. Lower is faster. This answers: "How quickly are blocks being created?" The primary query is `300 / clamp_min(max(delta(synergy_block_height{job="synergy-validators"}[5m])), 1)`, which uses the fastest validator height delta instead of summing validators and double-counting the same block.
- `Latest Block Age`: seconds since each node's latest local block. Rising age means that node has not seen a new block.
- `Sync Gap Blocks`: highest block observed by the sync manager minus the node's local height.
- `Mempool Pending Transactions`: local pending transaction count per node.
- `Gas Price in Mempool`: min, average, and max gas price for pending transactions, in nWei.
- `Public Probe Latency`: blackbox probe duration for public HTTP and TCP endpoints.
- `Scrape Target Status`: table of Prometheus `up` values for all configured observer targets. `1` means reachable, `0` means the scrape failed.

## Consensus and Chain

File: `ops/observability/grafana/consensus-and-chain.json`

Purpose: shows Synergy-specific chain, consensus, validator, P2P, mempool, and gas behavior from the runtime exporter.

Panels:

- `Highest Validator Height`: highest `synergy_block_height` across voting validators.
- `Lowest Validator Height`: lowest `synergy_block_height` across voting validators.
- `Validator Height Difference`: highest voting-validator height minus lowest voting-validator height. This should normally be 0 or very small.
- `Validators Syncing`: number of validators reporting active sync.
- `Active Validators in Registry`: active validator count from the local validator registry.
- `Pending Validator Registrations`: validator registrations waiting for activation.
- `Average Block Time`: average seconds per block over the selected window. It replaces the old p95 block interval panel and avoids double-counting validators.
- `Block Production Rate by Validator`: `rate(synergy_block_height[5m]) * 60`, useful for spotting stuck validators.
- `Peer Count by Node`: connected peers seen by each Synergy process.
- `Status-Ready Validator Peers`: connected validator peers that have exchanged enough status data for consensus membership checks.
- `Best Validator Peer Height vs Local Height`: compares local chain height to the best connected validator-peer height.
- `Peer Reported Heights`: per-peer last known heights. Divergence here is a direct split/sync warning.
- `Peer Last-Seen Age`: seconds since each peer was last seen.
- `Mempool Size`: pending transaction count.
- `Mempool Fee Total`: total pending transaction fee units, in nWei.
- `Recent Gas Utilization Ratio`: average gas used per block over the latest 100 local blocks divided by block gas limit.
- `Latest Block Transactions`: transaction count in each node's latest block.
- `Recent Avg Transactions Per Block`: average transactions per block over the latest 100 local blocks.
- `Recent Avg Gas Per Block`: average fee units per block over the latest 100 local blocks.
- `Validator Produced Blocks Total`: registry-reported block production by validator.
- `Validator Missed Blocks / Vote Windows`: missed block count plus missed-vote windows.
- `Validator Synergy Score`: registry-reported Synergy score by validator.
- `Validator Uptime Percent`: registry-reported validator uptime.
- `Validator Average Block Time`: registry-reported average block time by validator.
- `Current Sync State by Node`: current sync state label, such as `idle`, `synced`, `downloading`, or `validating`.
- `Current Peer Labels`: peer identity, direction, node id, and validator address labels.

## Host Infrastructure

File: `ops/observability/grafana/host-infrastructure.json`

Purpose: shows generic Linux host health for validators, relayers, observer, and public-role hosts through node_exporter.

Panels:

- `Node Exporter Targets Up`: count of node_exporter targets reachable by Prometheus.
- `Prometheus Samples Scraped per Second`: scrape ingestion rate.
- `Scrape Failures`: number of targets currently down.
- `Prometheus TSDB Head Series`: active in-memory Prometheus time series.
- `Host CPUs Visible`: CPU label count seen by node_exporter.
- `Filesystem Mounts Visible`: non-temporary filesystem count.
- `CPU Busy Percent`: host CPU usage derived from non-idle CPU time.
- `Load Average`: 1, 5, and 15 minute Linux load average.
- `Memory Used Percent`: memory pressure based on `MemAvailable`.
- `Swap Used Percent`: swap usage percentage. Nonzero sustained swap can cause validator latency.
- `Disk Used Percent`: filesystem fill level by mountpoint.
- `Disk IO Bytes / sec`: disk reads and writes by device.
- `Network Traffic Bytes / sec`: receive and transmit throughput by network interface.
- `Network Errors / sec`: network receive/transmit error rates.
- `Open File Descriptors Percent`: host file descriptor table usage.
- `Systemd Unit State`: active state for selected services where node_exporter exposes systemd collector data.
- `Scrape Duration`: time Prometheus spends scraping each target.
- `Host Kernel and OS Info`: kernel and OS labels from node_exporter.
- `Down or Failing Targets`: any target with `up == 0`.

## Public Edge and Bootstrap

File: `ops/observability/grafana/public-edge-and-bootstrap.json`

Purpose: focuses on public RPC, explorer, bootnode, and seed reachability from the observer.

Key readings:

- Public HTTP probe panels show whether public health endpoints return 2xx responses.
- Public TCP probe panels show whether bootnode and seed ports accept TCP connections.
- Shared public host metrics panels show whether edge app metrics and public host node_exporter proxy endpoints are reachable.
- Probe duration panels show public endpoint latency from the observer's perspective.

## Fleet Roster

The Fleet Overview and Network Overview dashboards include a `Node Metrics Roster` table with these columns: Node Name, Role, Target, Up, Block Height, Peer Count, Syncing, Last Seen, and Notes/Status. Missing values are displayed as `N/A` when a metric is not emitted by that role.

The roster includes Val1 through Val5, relayers, rpc-gateway, explorer, observer, bootnodes, seeds, and `Archive Validator`. Archive Validator is labeled with role `archive_validator` or `archive`; it is not treated as an active voting validator in consensus or PoSy panels.

## New Synergy Metrics Added

The runtime `/metrics` exporter now emits additional Synergy-specific metrics:

- Chain: latest block age, latest block interval, latest block transaction count, total transactions, recent average block time, recent average transactions per block, recent gas per block, block gas limit, recent gas utilization ratio.
- Mempool: pending transactions, total gas limit, total fee, min/avg/max gas price.
- Sync: sync state label, sync-in-progress flag, highest observed block, starting block, sync gap, progress percent.
- P2P: connected peer count, status-ready validator count, best validator peer height, peer labels, per-peer height, last-seen age, status age, blocks sent/received, transactions sent/received.
- Consensus config: block time, vote timeout, block timeout, leader timeout, validator vote threshold, minimum validators.
- Validator registry: produced blocks, validated transactions, missed blocks, average block time, uptime percent, Synergy score, stake, missed-vote counters, equivocation evidence.

## What To Look For During Incidents

- Chain stalled: `Latest Block Age` rises on all validators, `Blocks Per Minute` goes to zero, and `Average Block Time` climbs.
- Height split: `Height Spread` is above 0 and `Peer Reported Heights` shows different peer heights.
- Sync issue: `Sync Gap Blocks` remains above 0 or `Current Sync State` stays in `downloading`, `validating`, or `applying`.
- Network partition: P2P peer counts drop, peer last-seen age rises, or scrape targets stay up while peer status becomes stale.
- Host pressure: CPU, memory, swap, disk IO, or disk fill panels spike before average block time rises.
- Public edge issue: internal validators keep producing blocks but public HTTP/TCP probes fail or probe latency rises sharply.
