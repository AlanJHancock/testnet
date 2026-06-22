# Synergy Testnet Command Reference

## Frozen Port Model

| Purpose | Canonical Port | Slot 0 | Slot 1 | Slot 2 |
|---|---:|---:|---:|---:|
| Bootnode P2P | 5620 | 5620 | 5620 | 5620 |
| Seed HTTP | 5621 | 5621 | 5621 | 5621 |
| Validator / Service P2P | 5622 | 5622 | 5622 | 5622 |
| RPC (HTTP) | 5640 | 5640 | 5640 | 5640 |
| WebSocket | 5660 | 5660 | 5660 | 5660 |
| Discovery | 5680 | 5680 | 5680 | 5680 |
| Metrics | 6030 | 6030 | 6030 | 6030 |

## Canonical Public Endpoints

```text
https://testnet-core-rpc.synergy-network.io
wss://testnet-core-ws.synergy-network.io
https://testnet-api.synergy-network.io
https://testnet-explorer.synergy-network.io
https://testnet-atlas-api.synergy-network.io
```

## Bootnodes

```text
snr://bootstrap@bootnode1.synergy-network.io:5620
snr://bootstrap@bootnode2.synergy-network.io:5620
snr://bootstrap@bootnode3.synergy-network.io:5620
```

## Seed Servers

```text
http://seed1.synergy-network.io:5621
http://seed2.synergy-network.io:5621
http://seed3.synergy-network.io:5621
```

## Process Status

```bash
pgrep -la synergy-testnet
ps aux | grep synergy-testnet | grep -v grep
systemctl status synergy-bootnode
systemctl status synergy-seed
```

## Node PID Checks

```bash
cat ~/bootnode1/data/node.pid
cat ~/seed1/data/seed.pid
kill -0 "$(cat ~/bootnode1/data/node.pid)" && echo "running" || echo "dead"
```

## Local Listener Checks

```bash
lsof -iTCP:5622 -sTCP:LISTEN
lsof -iTCP:5640 -sTCP:LISTEN
lsof -iTCP:5660 -sTCP:LISTEN
lsof -iTCP:6030 -sTCP:LISTEN

ss -tlnp | grep -E '5620|5621|5622|5640|5660|5680|6030'
netstat -an | grep -E '5620|5621|5622|5640|5660|5680|6030'
```

## Local RPC

```bash
curl -s http://127.0.0.1:5640/health

curl -s -X POST http://127.0.0.1:5640 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"synergy_blockNumber","params":[],"id":1}'

curl -s -X POST http://127.0.0.1:5640 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"synergy_getLatestBlock","params":[],"id":1}'

curl -s -X POST http://127.0.0.1:5640 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"synergy_getPeerInfo","params":[],"id":1}'

curl -s -X POST http://127.0.0.1:5640 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":1}'
```

## Public RPC Comparison

```bash
LOCAL=$(curl -s -X POST http://127.0.0.1:5640 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"synergy_blockNumber","params":[],"id":1}' \
  | python3 -c "import sys,json; print(int(json.load(sys.stdin)['result'],16))")

PUBLIC=$(curl -s -X POST https://testnet-core-rpc.synergy-network.io \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"synergy_blockNumber","params":[],"id":1}' \
  | python3 -c "import sys,json; print(int(json.load(sys.stdin)['result'],16))")

echo "Local: $LOCAL | Public: $PUBLIC | Diff: $((PUBLIC - LOCAL))"
```

## Seed Service Checks

```bash
curl -s http://seed1.synergy-network.io:5621/healthz
curl -s http://seed2.synergy-network.io:5621/healthz
curl -s http://seed3.synergy-network.io:5621/healthz

curl -s http://seed1.synergy-network.io:5621/peers
curl -s http://seed1.synergy-network.io:5621/peer-list.json
curl -s http://seed1.synergy-network.io:5621/dns/bootstrap.txt

curl -s -X POST http://seed1.synergy-network.io:5621/peers/register \
  -H 'Content-Type: application/json' \
  -d '{"endpoint":"<your_public_ip>:5622","node_id":"<your_node_id>"}'
```

## Bootnode Connectivity

```bash
nc -zv bootnode1.synergy-network.io 5620
nc -zv bootnode2.synergy-network.io 5620
nc -zv bootnode3.synergy-network.io 5620

for host in bootnode1 bootnode2 bootnode3; do
  nc -zv "${host}.synergy-network.io" 5620 2>&1
done

timeout 5 bash -c 'echo >/dev/tcp/bootnode1.synergy-network.io/5620' && echo "open" || echo "closed"
```

## External Accessibility

```bash
curl -s https://api.ipify.org

nc -zv <your_public_ip> 5622
ss -tlnp | grep 5640

curl -s https://portchecker.io/api/port-checker \
  -H 'Content-Type: application/json' \
  -d "{\"host\":\"$(curl -s https://api.ipify.org)\",\"ports\":[5622]}"

sudo iptables -L INPUT -n | grep 5622
sudo ufw status | grep 5622
```

## Metrics

```bash
curl -s http://127.0.0.1:6030/metrics | head -40
curl -s http://127.0.0.1:6030/metrics | grep synergy_block_height
watch -n 5 "curl -s http://127.0.0.1:6030/metrics | grep synergy_block_height"
```

## Launch Package Commands

```bash
nohup synergy-testnet start \
  --config ~/.synergy/testnet/node-01/config/node.toml \
  > ~/.synergy/testnet/node-01/logs/node.out 2>&1 &

tail -f ~/.synergy/testnet/node-01/logs/node.out
tail -f ~/.synergy/testnet/node-01/data/logs/validator.log
```

## Bootnode / Seed Bundle Health

```bash
curl -s http://127.0.0.1:5621/healthz
curl -s -X DELETE http://127.0.0.1:5621/peers

curl -s http://seed1.synergy-network.io:5621/peers | python3 -m json.tool
curl -s http://seed1.synergy-network.io:5621/peer-list.json | python3 -m json.tool
```

## Quick Smoke Check

```bash
echo "=== Process ===" && pgrep -la synergy-testnet || echo "NOT RUNNING"
echo "=== P2P ===" && lsof -iTCP:5622 -sTCP:LISTEN || echo "NOT LISTENING"
echo "=== RPC ===" && lsof -iTCP:5640 -sTCP:LISTEN || echo "NOT LISTENING"
echo "=== Metrics ===" && lsof -iTCP:6030 -sTCP:LISTEN || echo "NOT LISTENING"
echo "=== Seed Health ===" && curl -s http://seed1.synergy-network.io:5621/healthz
echo "=== Latest Block ===" && curl -s -X POST http://127.0.0.1:5640 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"synergy_getLatestBlock","params":[],"id":1}'
```
