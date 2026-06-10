# miniwaf

A lightweight, real-time Web Application Firewall (WAF) for nginx. It monitors nginx logs, detects malicious requests, and automatically blocks attacker IPs using **UFW**.

## Features

- **Dual log monitoring**: Watches both `error_log` and `access_log` in real time.
- **Historical log processing**: Scans existing log files (including rotated `.gz` archives) on startup.
- **Logrotate-aware**: Detects file rotation via `stat()` polling; no inotify/kqueue required.
- **Threshold-based blocking**: Blocks an IP only after N hits within a configurable time window (default: 3 hits / 60s).
- **Whitelist support**: IPs listed in a whitelist file are never blocked.
- **IPv4 & IPv6 support**: IP extraction and validation via `inet_pton`.
- **Graceful shutdown**: Handles `SIGINT` and `SIGTERM` cleanly.
- **Dry run mode**: Test rules without executing any block commands.

## Quick Start

### 1. Build

Requires a C11 compiler, POSIX environment, and `zlib`.

```bash
make
```

Or manually:

```bash
gcc -O2 -Wall -Wextra -std=c11 -D_POSIX_C_SOURCE=200809L -o miniwaf miniwaf.c -lz
```

### 2. Initialize UFW (first time only)

Before running miniwaf, run the helper script to check your UFW state and apply safe defaults:

```bash
sudo python3 init_ufw.py
```

This will:
- Check if UFW is installed and active
- Warn you if SSH (port 22) is not allowed before enabling UFW
- Optionally set `default allow incoming` (blacklist mode) and enable UFW

If you are running this in an automated deployment, use `-y` to auto-accept:

```bash
sudo python3 init_ufw.py -y
```

### 3. Test with dry run

Always test first to see what would be blocked, without touching your firewall:

```bash
./miniwaf dry_run
```

Example output:

```
Starting in dry run mode
Processing historical log: /var/log/nginx/error.log
[dry_run] Would block IP 192.168.1.10 due to: phpmyadmin (error log)
[dry_run] Would block IP 192.168.1.10 due to: .env (error log)
Processing historical log: /var/log/nginx/access.log
[dry_run] Would block IP 203.0.113.5 due to: /wp-config.php (access log)
Dry run finished
```

### 4. Run for real

```bash
sudo ./miniwaf
```

Example output with threshold=3:

```
Processing historical log: /var/log/nginx/error.log
IP 192.168.1.10 hit 1/3 (reason: phpmyadmin)
IP 192.168.1.10 hit 2/3 (reason: .env)
Blocking IP 192.168.1.10 (reason: .git, hits: 3/3)
Blocking IP: 192.168.1.10
Starting log monitoring (2 file(s))...
```

Leave it running. It will monitor logs in real time and block new attackers automatically.

Press `Ctrl+C` to stop gracefully.

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

### Example with custom settings

```bash
export NGINX_ERROR_LOG=/var/log/nginx/error.log
export NGINX_ACCESS_LOG=/var/log/nginx/access.log
export WHITELIST_FILE=/etc/nginx/whitelist.txt
export THRESHOLD_HITS=3
export THRESHOLD_WINDOW=60
sudo ./miniwaf
```

### Strict mode (block on first hit)

```bash
export THRESHOLD_HITS=1
export THRESHOLD_WINDOW=1
sudo ./miniwaf
```

### Ensure deny rules take priority

If you have existing UFW allow rules for subnets (e.g. `ufw allow from 10.0.0.0/8`), a deny rule for an IP inside that subnet may not take effect because the allow rule matches first.

Fix this by inserting deny rules at the top of the UFW rule list:

```bash
export UFW_ADD_RULE='ufw insert 1 deny from %s to any'
sudo ./miniwaf
```

## Whitelist Format

Create a whitelist file to prevent your own IP or trusted sources from being blocked:

```
# /etc/nginx/whitelist.txt
127.0.0.1
::1
203.0.113.5
# 10.0.0.0/8 is not supported; list individual IPs
```

Then point miniwaf to it:

```bash
export WHITELIST_FILE=/etc/nginx/whitelist.txt
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

## Systemd Service

Create `/etc/systemd/system/miniwaf.service`:

```ini
[Unit]
Description=miniwaf
After=network.target

[Service]
Type=simple
Environment="NGINX_ERROR_LOG=/var/log/nginx/error.log"
Environment="NGINX_ACCESS_LOG=/var/log/nginx/access.log"
Environment="WHITELIST_FILE=/etc/nginx/whitelist.txt"
Environment="THRESHOLD_HITS=3"
Environment="THRESHOLD_WINDOW=60"
ExecStart=/usr/local/bin/miniwaf
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Install and start:

```bash
sudo cp miniwaf /usr/local/bin/
sudo systemctl daemon-reload
sudo systemctl enable --now miniwaf
```

Check status and logs:

```bash
sudo systemctl status miniwaf
sudo journalctl -u miniwaf -f
```

## How It Works

1. **Startup**: Loads whitelist, loads existing UFW rules, and scans all historical logs (including `.gz` archives).
2. **Matching**: Extracts the client IP from each log line and checks against a list of known attack patterns.
3. **Thresholding**: Increments a per-IP hit counter. When the counter reaches `THRESHOLD_HITS` within `THRESHOLD_WINDOW`, the IP is passed to the blocker.
4. **Blocking**: Executes the `UFW_ADD_RULE` command (e.g. `ufw deny from <ip> to any`).
5. **Monitoring**: Enters a polling loop, checking monitored log files every 500ms. Automatically handles log rotation by detecting inode changes.

## Troubleshooting

### miniwaf prints "No log files to monitor"
Check that `NGINX_ERROR_LOG` and `NGINX_ACCESS_LOG` point to existing files.

### Block command failed (exit 127)
UFW is not installed. Install it with `sudo apt install ufw` (Debian/Ubuntu) or equivalent.

### Block command failed (exit 1)
The IP may already be blocked, or you are not running as root. UFW requires root privileges.

### Some IPs are not being blocked even though they appear in logs
- Check if the IP is in your whitelist.
- If you have broad `ufw allow from <subnet>` rules, use `UFW_ADD_RULE='ufw insert 1 deny from %s to any'`.
- Check that the log line actually contains one of the blocked patterns (case-insensitive substring match).

### Logrotate not detected
The program detects rotation by comparing `inode` and file size via `stat()`. If your log rotation uses `copytruncate` (which keeps the same inode), detection may be delayed until the file shrinks. This is rare for nginx.

## License

Public domain / do whatever you want.
