# dumpcap-orchestrator

A small shell orchestrator for running `dumpcap` (Wireshark's capture utility) with sane defaults, rotation and simple lifecycle helpers.

## Goal / overview

This is an **idempotent orchestrator** for running `dumpcap` as a systemd service with:
- **Automatic systemd unit creation** (`dumpcap@<iface>.service`)
- **Ring-buffer rotation** (configurable file size and file count)
- **Optional BPF filtering** and time-based rotation
- **Retention via tmpfiles.d** (automated cleanup of old captures)
- **Hardened systemd service** (capabilities-based, minimal privileges)
- **Multi-interface support** (create multiple instances for different interfaces)

The script handles setup, uninstall, service lifecycle management, and optional purge operations.

## Prerequisites

- **Linux with systemd** (the script creates systemd units)
- **Root/sudo access** (required for systemd unit creation, setcap, and directory setup)
- **`dumpcap`** — the script will attempt to auto-install `wireshark-common` (Debian/Ubuntu) or `wireshark-cli` (Fedora/RHEL) if missing
- **Bash** (script uses `#!/usr/bin/env bash`)

The script automatically:
- Creates the `wireshark` group (if missing)
- Sets capabilities on `dumpcap` binary (`CAP_NET_RAW`, `CAP_NET_ADMIN`)
- Creates capture directories with appropriate permissions
- Generates systemd unit, environment files, and tmpfiles.d rules

## Quick usage

Make the script executable and run as root:

```bash
chmod +x dumpcap-orchestrator.sh
```

**Setup and start capture on `eth0` with defaults** (1 GiB per file, 24 files, 14-day retention):

```bash
sudo ./dumpcap-orchestrator.sh --iface eth0
```

This will:
1. Install `dumpcap` if missing
2. Create the `wireshark` group and `/var/pcaps` directory
3. Set capabilities on `dumpcap`
4. Generate `/etc/systemd/system/dumpcap@.service` template unit
5. Create environment file `/etc/dumpcap.d/eth0.env`
6. Enable and start `dumpcap@eth0.service`

**Examples with custom parameters:**

```bash
# Capture on interface 'any', 256 MB per file, 200 files total, rotate every 15 min
sudo ./dumpcap-orchestrator.sh --iface any --filesize-mb 256 --files 200 --duration-sec 900

# Capture on wlp7s0 with BPF filter and limited snaplen (headers only)
sudo ./dumpcap-orchestrator.sh --iface wlp7s0 --snaplen 256 --filter 'tcp port 6500'

# Custom capture directory and group
sudo ./dumpcap-orchestrator.sh --iface eth0 --cap-dir /data/pcaps --cap-group netops

# Dry-run mode (preview actions without executing)
sudo ./dumpcap-orchestrator.sh --iface eth0 --dry-run

# Setup without auto-enabling/starting the service
sudo ./dumpcap-orchestrator.sh --iface eth0 --no-enable-start
```

## CLI options reference

### Core

- `--iface IFACE` — **Required**. Network interface to capture (e.g., `eth0`, `ens160`, `any`)

### Rotation

- `--filesize-mb N` — Per-file size in MB (default: `1024` = 1 GiB)
- `--files N` — Number of files to keep in ring buffer (default: `24`)
- `--duration-sec N` — Optional. Rotate every N seconds (in addition to size-based rotation)

### Capture parameters

- `--snaplen N` — Snapshot length; `0` = full packet (default: `0`)
- `--buffer-mb N` — OS capture buffer in MB (default: `16`)
- `--filter 'BPF expr'` — Berkeley Packet Filter expression (e.g., `'tcp port 443'`, `'vlan and host 10.0.1.5'`)

### Paths and identity

- `--cap-dir PATH` — Capture directory (default: `/var/pcaps`)
- `--env-dir PATH` — Environment file directory (default: `/etc/dumpcap.d`)
- `--cap-group GROUP` — Group owning capture files (default: `wireshark`)
- `--service-user USER` — Systemd `User=` directive (default: `root`)

### Retention

- `--retention-days N` — Age in days for tmpfiles cleanup (default: `14`)
- `--no-apply-tmpfiles` — Skip immediate `systemd-tmpfiles --create`

### Behavior flags

- `--no-setcap` — Skip `setcap` on `/usr/bin/dumpcap`
- `--no-enable-start` — Do not enable/start the service after setup
- `--dry-run` — Print actions without executing them

### Actions

Use `--action <ACTION>` to perform lifecycle operations:

- `setup` — **Default**. Create/update unit, env, tmpfiles; optionally enable & start
- `uninstall` — Stop & disable service, remove env file and tmpfiles rule (keeps pcaps)
- `start` — Start `dumpcap@<iface>.service`
- `stop` — Stop `dumpcap@<iface>.service`
- `restart` — Restart `dumpcap@<iface>.service`
- `status` — Show `systemctl status` for `dumpcap@<iface>.service`
- `enable` — Enable and start the service
- `disable` — Disable the service
- `stop-all` — Stop all `dumpcap@*` services
- `purge` — **Destructive**. Stop all services, remove unit/env/tmpfiles/pcap directory

## Service lifecycle management

Once you've run `./dumpcap-orchestrator.sh --iface <IFACE>`, systemd manages the capture:

```bash
# Check status
sudo systemctl status dumpcap@eth0.service

# View logs
sudo journalctl -u dumpcap@eth0.service -f

# Stop capture
sudo ./dumpcap-orchestrator.sh --iface eth0 --action stop
# or directly:
sudo systemctl stop dumpcap@eth0.service

# Restart capture
sudo ./dumpcap-orchestrator.sh --iface eth0 --action restart

# Stop all active captures
sudo ./dumpcap-orchestrator.sh --action stop-all
```

### Managing multiple interfaces

You can run the script multiple times with different `--iface` values:

```bash
sudo ./dumpcap-orchestrator.sh --iface eth0 --filesize-mb 512 --files 48
sudo ./dumpcap-orchestrator.sh --iface eth1 --filter 'port 443'
sudo ./dumpcap-orchestrator.sh --iface any --snaplen 128 --retention-days 7
```

Each creates a separate systemd instance: `dumpcap@eth0.service`, `dumpcap@eth1.service`, `dumpcap@any.service`.

## Disk management and retention

The script uses **tmpfiles.d** for automatic cleanup:
- Default: files in `/var/pcaps` older than **14 days** are purged
- Configure with `--retention-days N`
- Rule is written to `/etc/tmpfiles.d/pcaps.conf`

To manually trigger cleanup:

```bash
sudo systemd-tmpfiles --clean /etc/tmpfiles.d/pcaps.conf
```

**Ring buffer limits disk usage:**
- Default: 24 files × 1 GiB = max ~24 GiB per interface
- Customize with `--filesize-mb` and `--files`

**Monitor disk usage:**

```bash
df -h /var/pcaps
du -sh /var/pcaps
```

## Troubleshooting

**"dumpcap: insufficient privileges"**
- The script auto-runs `setcap cap_net_raw,cap_net_admin+eip` on dumpcap
- If you used `--no-setcap`, manually grant capabilities:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip $(which dumpcap)
  ```

**Service fails to start**
- Check logs: `sudo journalctl -u dumpcap@<iface>.service -xe`
- Verify interface exists: `ip link show <iface>`
- Test dumpcap manually:
  ```bash
  sudo /usr/bin/dumpcap -i eth0 -w /tmp/test.pcapng
  ```

**No traffic captured**
- Verify interface is up: `ip link show <iface>`
- Check BPF filter syntax (test with `tcpdump -i <iface> -d '<filter>'`)
- Ensure interface has link and is receiving packets: `ip -s link show <iface>`

**Service enabled but not running after reboot**
- Ensure interface is available early in boot (if using `--iface` for a hotplugged device, add dependencies in the unit)

**Uninstall or remove captures**
- **Remove service for one interface (keep pcaps):**
  ```bash
  sudo ./dumpcap-orchestrator.sh --iface eth0 --action uninstall
  ```
- **Complete purge (removes ALL services, env files, and pcap directory):**
  ```bash
  sudo ./dumpcap-orchestrator.sh --action purge
  ```

## Safety & privacy

Captured packets may contain sensitive data. Follow privacy and legal requirements for packet captures. Avoid capturing on networks where you don't have permission.

## Advanced usage

### Using a custom BPF filter

```bash
# Capture only VLAN-tagged traffic on TCP port 6500
sudo ./dumpcap-orchestrator.sh --iface eth0 --filter 'vlan and tcp port 6500'

# Capture DNS traffic only
sudo ./dumpcap-orchestrator.sh --iface eth0 --filter 'port 53'

# Capture traffic from/to specific subnet
sudo ./dumpcap-orchestrator.sh --iface eth0 --filter 'net 192.168.1.0/24'
```

### Headers-only capture (save disk space)

```bash
# Capture only first 128 bytes (headers) for traffic analysis
sudo ./dumpcap-orchestrator.sh --iface eth0 --snaplen 128
```

### Time-based rotation + size-based rotation

```bash
# Rotate every 15 minutes OR when file reaches 512 MB
sudo ./dumpcap-orchestrator.sh --iface eth0 --filesize-mb 512 --duration-sec 900
```

### Dry-run mode (test before applying)

```bash
sudo ./dumpcap-orchestrator.sh --iface eth0 --filesize-mb 2048 --files 50 --dry-run
```

## Contribution

Improvements welcome! Suggested enhancements:
- Support for remote capture targets (rpcapd)
- Prometheus exporter for capture metrics (packets/s, disk usage)
- Configurable alerting on capture failures
- Integration with packet analysis pipelines (e.g., Zeek, Suricata)

Please open issues or PRs with test steps and environment details.

## License

This repository does not include a license file. If you intend to share or reuse this script, add an appropriate license (e.g., MIT) to clarify usage and redistribution.
