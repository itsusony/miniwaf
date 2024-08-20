import os, re, subprocess, time
from typing import Callable, Optional

# Configuration
NGINX_ERROR_LOG = os.environ.get('NGINX_ERROR_LOG', '/var/log/nginx/error.log')
NGINX_DENY_CONF = os.environ.get('NGINX_DENY_CONF', '/etc/nginx/conf.d/deny.conf')
NGINX_RELOAD = os.environ.get('NGINX_RELOAD', 'nginx -s reload')
UFW_ADD_RULE = os.environ.get('UFW_ADD_RULE', 'ufw deny from %s to any')
ILLEGALS = ['phpmyadmin', 'wp-login\.php', 'CoordinatorPortType', 'azenv\.php', '\.vscode', '\.git', '\.env', 'phpinfo']

def load_denied_ips():
    if not os.path.exists(NGINX_DENY_CONF):
        open(NGINX_DENY_CONF, 'w').write("# miniwaf\n")
    with open(NGINX_DENY_CONF, 'r') as f:
        return {m.group(1): 1 for m in (re.match(r'^deny (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3});', line) for line in f) if m}

def append_deny(ip: str, map_of_ips: dict, dry_run: bool):
    if ip and ip not in map_of_ips:
        map_of_ips[ip] = 1
        if not dry_run:
            with open(NGINX_DENY_CONF, 'a') as f:
                f.write(f"deny {ip};\n")
            subprocess.run(UFW_ADD_RULE % ip, shell=True, check=True)
        else:
            print(f"Would block IP: {ip}")

def judge(log: str, map_of_ips: dict, callback: Optional[Callable[[str], None]], dry_run: bool):
    match = re.search(r'client: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log)
    if match and match.group(1) not in map_of_ips:
        ip = match.group(1)
        if any(re.search(pattern, log, re.IGNORECASE) for pattern in ILLEGALS):
            if dry_run:
                print(f"Block reason: {next(pattern for pattern in ILLEGALS if re.search(pattern, log, re.IGNORECASE))}")
            append_deny(ip, map_of_ips, dry_run)
            if callback and not dry_run:
                callback(ip)
            return True
    return False

def process_log(file_path: str, map_of_ips: dict, dry_run: bool, callback: Optional[Callable[[str], None]] = None):
    try:
        with open(file_path, 'r') as f:
            return any(judge(line, map_of_ips, callback, dry_run) for line in f)
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False

def monitor_error_log(map_of_ips: dict):
    def reload_nginx(ip):
        try:
            subprocess.run(NGINX_RELOAD, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Nginx reload failed: {e}")

    with open(NGINX_ERROR_LOG, 'r') as f:
        f.seek(0, 2)
        while True:
            where = f.tell()
            line = f.readline()
            if not line:
                time.sleep(0.1)
                f.seek(where)
            else:
                judge(line, map_of_ips, reload_nginx, False)

def main():
    dry_run = 'dry_run' in os.sys.argv
    if dry_run:
        print("Starting in dry run mode")

    map_of_ips = load_denied_ips()

    if process_log(NGINX_ERROR_LOG, map_of_ips, dry_run) or process_log(f"{NGINX_ERROR_LOG}.1", map_of_ips, dry_run):
        if not dry_run:
            subprocess.run(NGINX_RELOAD, shell=True, check=True)

    if dry_run:
        print("Dry run finished")
    else:
        monitor_error_log(map_of_ips)

if __name__ == "__main__":
    main()
