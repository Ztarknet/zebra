# Zebrad Systemd Service

Scripts to run zebrad as a systemd service.

## Files

- **zebrad.service** - Systemd service unit file
- **install-service.sh** - Install the service
- **uninstall-service.sh** - Remove the service

## Setup

**Install the service:**
```bash
cd deploy
./install-service.sh
```

**Start zebrad:**
```bash
sudo systemctl start zebrad
```

## Service Management

```bash
# Start/stop/restart
sudo systemctl start zebrad
sudo systemctl stop zebrad
sudo systemctl restart zebrad

# Check status
sudo systemctl status zebrad

# View logs
journalctl -u zebrad -f
journalctl -u zebrad -n 100

# Enable/disable auto-start on boot
sudo systemctl enable zebrad
sudo systemctl disable zebrad
```

## Configuration

The service automatically uses:
- **User**: Current user (auto-detected)
- **Working Directory**: `~/zebra` (parent of deploy dir)
- **Config File**: `~/zebra/ztarknet.toml`
- **Binary**: `~/zebra/target/release/zebrad`
- **Data Directory**: `~/.cache/zebra`

## Uninstall

```bash
cd deploy
./uninstall-service.sh
```

## Troubleshooting

**Service won't start:**
```bash
journalctl -u zebrad -n 50
```

**Binary not found:**
```bash
# Build zebrad first
cd ~/zebra
cargo build --release
```

**Config file not found:**
```bash
# Ensure ztarknet.toml exists in repo root
ls -la ~/zebra/ztarknet.toml
```

**Port already in use:**
```bash
ps aux | grep zebrad
pkill zebrad  # Kill if needed
```
