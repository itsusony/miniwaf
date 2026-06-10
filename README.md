# miniwaf

A lightweight, real-time Web Application Firewall (WAF) for nginx. It monitors nginx logs, detects malicious requests, and automatically blocks attacker IPs using **UFW**.

## Versions

| File | Language | Notes |
|------|----------|-------|
| `miniwaf.pl` | Perl | Original version. Uses `File::Tail` and writes `deny` rules to an nginx include file. |
| `miniwaf.py` | Python | Asyncio-based. Monitors both error and access logs via UFW. |
| `miniwaf.c` | **C** | **New high-performance version** (this project). Single binary, minimal dependencies, cross-platform polling, threshold-based blocking, gzip support, and graceful signal handling. |

## Features (C version)

- **Dual log monitoring**: Watches both `error_log` and `access_log` in real time.
- **Historical log processing**: Scans existing log files (including rotated `.gz` archives) on startup.
- **Logrotate-aware**: Detects file rotation via `stat()` polling; no inotify/kqueue required.
- **Threshold-based blocking**: Blocks an IP only after N hits within a configurable time window (default: 3 hits / 60s).
- **Whitelist support**: IPs listed in a whitelist file are never blocked.
- **IPv4 & IPv6 support**: IP extraction and validation via `inet_pton`.
- **Graceful shutdown**: Handles `SIGINT` and `SIGTERM` cleanly.
- **Dry run mode**: Test rules without executing any block commands.

## Build

Requires a C11 compiler, POSIX environment, and `zlib`.

```bash
make
```

Or manually:

```bash
gcc -O2 -Wall -Wextra -std=c11 -D_POSIX_C_SOURCE=200809L -o miniwaf miniwaf.c -lz
```

## Usage

```bash
# Run normally (requires root for ufw)
sudo ./miniwaf

# Dry run: show what would be blocked without taking action
./miniwaf dry_run
```

## Configuration

All settings are controlled via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `NGINX_ERROR_LOG` | `/var/log/nginx/error.log` | Path to nginx error log |
| `NGINX_ACCESS_LOG` | `/var/log/nginx/access.log` | Path to nginx access log |
| `UFW_ADD_RULE` | `ufw deny from %s to any` | Command template to block an IP. `%s` is replaced with the IP. |
| `WHITELIST_FILE` | `/etc/nginx/whitelist.txt` | One IP per line. Empty lines and `# comments` are ignored. |
| `THRESHOLD_HITS` | `3` | Number of hits required before blocking |
| `THRESHOLD_WINDOW` | `60` | Time window (seconds) for counting hits |

### Example

```bash
export NGINX_ERROR_LOG=/var/log/nginx/error.log
export NGINX_ACCESS_LOG=/var/log/nginx/access.log
export WHITELIST_FILE=/etc/nginx/whitelist.txt
export THRESHOLD_HITS=3
export THRESHOLD_WINDOW=60
sudo ./miniwaf
```

## Default Blocked Patterns

The following substrings in a log line trigger a hit:

- `phpmyadmin`
- `wp-login.php`
- `/wp-config.php`
- `CoordinatorPortType`
- `azenv.php`
- `.vscode`
- `.git`
- `.env`
- `phpinfo`
- `/cdn-cgi/`
- `/cgi-bin/`
- `paloaltonetworks.com`

## Whitelist Format

```
# /etc/nginx/whitelist.txt
127.0.0.1
::1
203.0.113.5
```

## Systemd Service Example

Create `/etc/systemd/system/miniwaf.service`:

```ini
[Unit]
Description=miniwaf
After=network.target

[Service]
Type=simple
Environment="NGINX_ERROR_LOG=/var/log/nginx/error.log"
Environment="NGINX_ACCESS_LOG=/var/log/nginx/access.log"
Environment="THRESHOLD_HITS=3"
Environment="THRESHOLD_WINDOW=60"
ExecStart=/usr/local/bin/miniwaf
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now miniwaf
```

## How It Works

1. **Startup**: Loads whitelist, loads existing UFW rules, and scans all historical logs (including `.gz` archives).
2. **Matching**: Extracts the client IP from each log line and checks against a list of known attack patterns.
3. **Thresholding**: Increments a per-IP hit counter. When the counter reaches `THRESHOLD_HITS` within `THRESHOLD_WINDOW`, the IP is passed to the blocker.
4. **Blocking**: Executes the `UFW_ADD_RULE` command (e.g. `ufw deny from <ip> to any`).
5. **Monitoring**: Enters a polling loop, checking monitored log files every 500ms. Automatically handles log rotation by detecting inode changes.

## Differences from Perl/Python versions

| Feature | Perl | Python | C |
|---------|------|--------|---|
| Real-time method | `File::Tail` | `aiofiles` polling | `stat()` polling |
| Logrotate handling | Partial | No | Yes |
| Access log support | No | Yes | Yes |
| Gzip history | No | Yes | Yes |
| Threshold blocking | No | No | Yes |
| Whitelist | No | Yes | Yes |
| Graceful shutdown | No | No | Yes |
| Dependencies | Perl + File::Tail + Try::Tiny | Python + aiofiles | libc + zlib |

## License

Public domain / do whatever you want.
