# Synergy Testnet Commands Reference

Complete command reference for building, testing, deploying, and managing the Synergy Testnet network.

---

## 📋 Table of Contents

1. [Git & GitHub Operations](#-git--github-operations)
2. [Building & Compilation](#-building--compilation)
3. [Testing](#-testing)
4. [Node Operations](#-node-operations)
5. [Network & Connectivity](#-network--connectivity)
6. [API & RPC Commands](#-api--rpc-commands)
7. [Metrics & Monitoring](#-metrics--monitoring)
8. [Configuration & Setup](#-configuration--setup)
9. [Troubleshooting](#-troubleshooting)

---

## 🔧 Git & GitHub Operations

### Push Changes and Trigger Binary Builds

The GitHub Actions workflow (`.github/workflows/build-binaries.yml`) automatically builds binaries on:
- Push to `main` branch
- Published releases (tags)
- Manual workflow dispatch

#### Standard Push to Main (Auto-builds)
```bash
# Stage all changes
git add .

# Commit with descriptive message
git commit -m "feat: description of changes"

# Push to main (triggers CI build)
git push origin main
```

#### Create Tagged Release Build (Recommended for Production)

```bash
# 1. Ensure you're on main with latest changes
git checkout main
git pull origin main

# 2. Verify all changes are committed
git status

# 3. Create an annotated tag (starting at v1.0.0)
git tag -a v1.0.0 -m "Release v1.0.0 - Initial release"

# 4. Push the tag to GitHub (triggers release build)
git push origin v1.0.0

# OR push tag + main in one command
git push origin main v1.0.0
```

#### Create Subsequent Release Tags

```bash
# Increment version following semver (major.minor.patch)
git tag -a v1.0.1 -m "Release v1.0.1 - Bug fixes"
git push origin v1.0.1

# Or for minor release
git tag -a v1.1.0 -m "Release v1.1.0 - New features"
git push origin v1.1.0
```

#### List Existing Tags
```bash
# List all tags
git tag -l

# List tags matching pattern
git tag -l "v1.*"
```

#### Delete a Tag (if needed)
```bash
# Delete local tag
git tag -d v1.0.0

# Delete remote tag
git push origin --delete v1.0.0
```

#### Manual Workflow Dispatch
```bash
# Trigger build workflow manually via GitHub CLI
gh workflow run build-binaries.yml --ref main
```

### What Gets Built

When you push a tag, GitHub Actions builds these binaries for **linux-amd64**, **windows-amd64**, and **macos-arm64**:

| Binary | Description |
|--------|-------------|
| `synergy-testnet` | Main node binary |
| `generate-node-keys` | Node key generation utility |
| `synergy-address-engine` | Address generation tool |
| `wallet-pqc-cli` | Wallet PQC command-line interface |

Release artifacts include:
- Platform-specific binaries with SHA256 checksums
- `latest-{platform}.json` manifest per platform
- Unified `latest.json` with all platforms

---

## 🏗️ Building & Compilation

### Build All Binaries (Release)
```bash
cargo build --release --locked -p synergy-testnet \
  --bin synergy-testnet \
  --bin generate-node-keys \
  --bin synergy-address-engine \
  --bin wallet-pqc-cli
```

### Build Specific Binary
```bash
# Main node
cargo build --release --bin synergy-testnet

# Node key generator
cargo build --release --bin generate-node-keys

# Address engine
cargo build --release --bin synergy-address-engine

# Wallet CLI
cargo build --release --bin wallet-pqc-cli
```

### Build (Development)
```bash
cargo build
```

### Run Directly
```bash
# Run main node
cargo run --release --bin synergy-testnet -- start

# Run with custom config
cargo run --release --bin synergy-testnet -- \
  --config ~/.synergy/testnet/node-01/config/node.toml
```

### Clean Build
```bash
cargo clean
cargo build --release
```

---

## 🧪 Testing

### Run All Tests
```bash
cargo test
```

### Run Specific Test Suites
```bash
# Token tests
cargo test token

# Consensus tests
cargo test consensus

# RPC tests
cargo test rpc
```

### Release Tests (including ignored/benchmarks)
```bash
cargo test --release -- --ignored
```

### Integration Tests
```bash
cargo test --test integration_tests
```

### Test with Output
```bash
cargo test -- --nocapture
```

---

## 🖥️ Node Operations

### Initialize Configuration
```bash
cargo run --release --bin synergy-testnet -- init
```

### Start Node
```bash
# From cargo
cargo run --release --bin synergy-testnet -- start

# From binary
./target/release/synergy-testnet start

# With custom config
./target/release/synergy-testnet start \
  --config ~/.synergy/testnet/node-01/config/node.toml
```

### Background Process
```bash
nohup synergy-testnet start \
  --config ~/.synergy/testnet/node-01/config/node.toml \
  > ~/.synergy/testnet/node-01/logs/node.out 2>&1 &

# View logs
tail -f ~/.synergy/testnet/node-01/logs/node.out
```

### Systemd Service
```bash
# Check status
systemctl status synergy-bootnode
systemctl status synergy-seed

# Start/Stop/Restart
systemctl start synergy-testnet
systemctl stop synergy-testnet
systemctl restart synergy-testnet

# Enable on boot
systemctl enable synergy-testnet
```

### Process Management
```bash
# Check running processes
pgrep -la synergy-testnet
ps aux | grep synergy-testnet | grep -v grep

# Check PID file
cat ~/bootnode1/data/node.pid
cat ~/seed1/data/seed.pid

# Verify process running
kill -0 "$(cat ~/bootnode1/data/node.pid)" && echo "running" || echo "dead"

# Stop node
kill $(cat ~/synergy-testnet/data/node.pid)
```

---

## 🌐 Network & Connectivity

### Port Reference

| Purpose | Canonical Port |
|---------|----------------|
| Bootnode P2P | 5620 |
| Seed HTTP | 5621 |
| Validator P2P | 5622 |
| RPC (HTTP) | 5640 |
| WebSocket | 5660 |
| Discovery | 5680 |
| Metrics | 6030 |

### Check Listening Ports
```bash
# Using lsof
lsof -iTCP:5622 -sTCP:LISTEN
lsof -iTCP:5640 -sTCP:LISTEN
lsof -iTCP:5660 -sTCP:LISTEN
lsof -iTCP:6030 -sTCP:LISTEN

# Using ss
ss -tlnp | grep -E '5620|5621|5622|5640|5660|5680|6030'

# Using netstat (macOS)
netstat -an | grep -E '5620|5621|5622|5640|5660|5680|6030'
```

### Bootnode Connectivity
```bash
# Test individual bootnodes
nc -zv bootnode1.synergy-network.io 5620
nc -zv bootnode2.synergy-network.io 5620
nc -zv bootnode3.synergy-network.io 5620

# Test all at once
for host in bootnode1 bootnode2 bootnode3; do
  nc -zv "${host}.synergy-network.io" 5620 2>&1
done

# Using bash TCP
timeout 5 bash -c 'echo >/dev/tcp/bootnode1.synergy-network.io/5620' && echo "open" || echo "closed"
```

### External Accessibility
```bash
# Get your public IP
curl -s https://api.ipify.org

# Test if your port is reachable
nc -zv <your_public_ip> 5622

# Check firewall
sudo iptables -L INPUT -n | grep 5622
sudo ufw status | grep 5622
```

### Seed Server Checks
```bash
# Health check
curl -s http://seed1.synergy-network.io:5621/healthz
curl -s http://seed2.synergy-network.io:5621/healthz
curl -s http://seed3.synergy-network.io:5621/healthz

# Get peer list
curl -s http://seed1.synergy-network.io:5621/peers
curl -s http://seed1.synergy-network.io:5621/peer-list.json
curl -s http://seed1.synergy-network.io:5621/dns/bootstrap.txt

# Register peer
curl -s -X POST http://seed1.synergy-network.io:5621/peers/register \
  -H 'Content-Type: application/json' \
  -d '{"endpoint":"<your_public_ip>:5622","node_id":"<your_node_id>"}'
```

### Canonical Public Endpoints
```text
https://testnet-core-rpc.synergy-network.io
wss://testnet-core-ws.synergy-network.io
https://testnet-api.synergy-network.io
https://testnet-explorer.synergy-network.io
https://testnet-atlas-api.synergy-network.io
```

### Bootnodes
```text
snr://bootstrap@bootnode1.synergy-network.io:5620
snr://bootstrap@bootnode2.synergy-network.io:5620
snr://bootstrap@bootnode3.synergy-network.io:5620
```

---

## 📡 API & RPC Commands

### Health Check
```bash
curl -s http://127.0.0.1:5640/health
```

### Get Block Number
```bash
curl -s -X POST http://127.0.0.1:5640 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"synergy_blockNumber","params":[],"id":1}'
```

### Get Latest Block
```bash
curl -s -X POST http://127.0.0.1:5640 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"synergy_getLatestBlock","params":[],"id":1}'
```

### Get Peer Info
```bash
curl -s -X POST http://127.0.0.1:5640 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"synergy_getPeerInfo","params":[],"id":1}'
```

### Get Network Stats
```bash
curl -s -X POST http://127.0.0.1:5640 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"synergy_getNetworkStats","params":[],"id":1}'
```

### Create Token
```bash
curl -s -X POST http://127.0.0.1:5640 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"synergy_createToken","params":["MYTOKEN","My Token",18,1000000,"sYn..."],"id":1}'
```

### Stake Tokens
```bash
curl -s -X POST http://127.0.0.1:5640 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"synergy_stakeTokensDirect","params":["sYn...","sYn...", "SNRG",1000000],"id":1}'
```

### Compare Local vs Public Block Height
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

---

## 📊 Metrics & Monitoring

### Get Metrics
```bash
curl -s http://127.0.0.1:6030/metrics | head -40
```

### Get Block Height from Metrics
```bash
curl -s http://127.0.0.1:6030/metrics | grep synergy_block_height
```

### Watch Block Height
```bash
watch -n 5 "curl -s http://127.0.0.1:6030/metrics | grep synergy_block_height"
```

### View Logs
```bash
# Node logs
tail -f ~/.synergy/testnet/node-01/logs/node.out
tail -f ~/.synergy/testnet/node-01/data/logs/validator.log

# System logs
journalctl -u synergy-testnet -f
```

---

## ⚙️ Configuration & Setup

### Initialize Fresh Node
```bash
cargo run --release --bin synergy-testnet -- init
```

### Configuration Files Location
```bash
# Node configuration
~/.synergy/testnet/node-01/config/node.toml

# Network configuration
config/network-config.toml

# Node-specific configuration
config/node_config.toml
```

### Scripts
```bash
# Start testnet
./scripts/start-testnet.sh

# Stop testnet
./scripts/stop-testnet.sh

# Reset testnet
./scripts/reset-testnet.sh

# Build all
./scripts/build-all.sh

# Monitor blocks
./monitor-blocks.sh
```

---

## 🔍 Troubleshooting

### Quick Smoke Check
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

### Check Seed Bundle Health
```bash
curl -s http://127.0.0.1:5621/healthz
curl -s -X DELETE http://127.0.0.1:5621/peers
```

### Common Issues

#### Node Not Starting
```bash
# Check if port is already in use
lsof -iTCP:5640 -sTCP:LISTEN

# Check logs for errors
tail -100 ~/.synergy/testnet/node-01/logs/node.out
```

#### Not Connecting to Peers
```bash
# Verify bootnode connectivity
nc -zv bootnode1.synergy-network.io 5620

# Check peer count
curl -s -X POST http://127.0.0.1:5640 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":1}'
```

#### Firewall Issues
```bash
# Ubuntu/Debian
sudo ufw allow 5622/tcp
sudo ufw allow 5640/tcp

# CentOS/RHEL
sudo firewall-cmd --add-port=5622/tcp --permanent
sudo firewall-cmd --reload
```

---

## 📝 Quick Reference Card

### Daily Operations
```bash
# Start node
cargo run --release --bin synergy-testnet -- start

# Check status
pgrep -la synergy-testnet
curl -s http://127.0.0.1:5640/health

# Check block height
curl -s -X POST http://127.0.0.1:5640 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"synergy_blockNumber","params":[],"id":1}'

# View logs
tail -f ~/.synergy/testnet/node-01/logs/node.out
```

### Release Workflow
```bash
# 1. Commit changes
git add . && git commit -m "fix: description"

# 2. Create tag
git tag -a v1.0.0 -m "Release v1.0.0"

# 3. Push tag (triggers build)
git push origin v1.0.0

# 4. Monitor GitHub Actions
# Visit: https://github.com/synergy-network-hq/testnet/actions
```

---

*Last updated: April 2026*
