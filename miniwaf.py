import os
import re
import subprocess
import time
import gzip
from typing import Callable, Optional
from glob import glob
import ipaddress

# Configuration
NGINX_ERROR_LOG = os.environ.get('NGINX_ERROR_LOG', '/var/log/nginx/error.log')
NGINX_DENY_CONF = os.environ.get('NGINX_DENY_CONF', '/etc/nginx/conf.d/deny.conf')
NGINX_RELOAD = os.environ.get('NGINX_RELOAD', 'nginx -s reload')
UFW_ADD_RULE = os.environ.get('UFW_ADD_RULE', 'ufw deny from %s to any')
ILLEGALS = ['phpmyadmin', 'wp-login.php', 'CoordinatorPortType', 'azenv.php', '.vscode', '.git', '.env', 'phpinfo']

# Global variable for storing denied IPs
map_of_ips = {}

def load_denied_ips():
    global map_of_ips
    if not os.path.exists(NGINX_DENY_CONF):
        open(NGINX_DENY_CONF, 'w').write("# miniwaf\n")
    with open(NGINX_DENY_CONF, 'r') as f:
        map_of_ips = {m.group(1): 1 for m in (re.match(r'^deny (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3});', line) for line in f) if m}

def save_denied_ips():
    global map_of_ips
    sorted_ips = sorted(map_of_ips.keys(), key=lambda ip: ipaddress.ip_address(ip))
    with open(NGINX_DENY_CONF, 'w') as f:
        f.write("# miniwaf\n")
        for ip in sorted_ips:
            f.write(f"deny {ip};\n")

def append_deny(ip: str, dry_run: bool):
    global map_of_ips
    if ip and ip not in map_of_ips:
        map_of_ips[ip] = 1
        if not dry_run:
            save_denied_ips()
            subprocess.run(UFW_ADD_RULE % ip, shell=True, check=True)
        else:
            print(f"Would block IP: {ip}")
        return True
    return False

def judge(log: str, callback: Optional[Callable[[str], None]], dry_run: bool):
    match = re.search(r'client: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log)
    if match and match.group(1) not in map_of_ips:
        ip = match.group(1)
        if any(re.search(pattern, log, re.IGNORECASE) for pattern in ILLEGALS):
            if dry_run:
                print(f"Block reason: {next(pattern for pattern in ILLEGALS if re.search(pattern, log, re.IGNORECASE))}")
            if append_deny(ip, dry_run):
                if callback and not dry_run:
                    callback(ip)
                return True
    return False

def process_log(file_path: str, dry_run: bool, callback: Optional[Callable[[str], None]] = None):
    changes_made = False
    try:
        if file_path.endswith('.gz'):
            with gzip.open(file_path, 'rt') as f:
                for line in f:
                    if judge(line, callback, dry_run):
                        changes_made = True
        else:
            with open(file_path, 'r') as f:
                for line in f:
                    if judge(line, callback, dry_run):
                        changes_made = True
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
    return changes_made

def monitor_error_log():
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
                judge(line, reload_nginx, False)

def main():
    global map_of_ips
    dry_run = 'dry_run' in os.sys.argv
    if dry_run:
        print("Starting in dry run mode")

    load_denied_ips()

    # Process all log files with the NGINX_ERROR_LOG prefix
    log_files = glob(f"{NGINX_ERROR_LOG}*")
    changes_made = False
    for log_file in log_files:
        if process_log(log_file, dry_run):
            changes_made = True
            print(f"Changes made while processing {log_file}")

    if changes_made and not dry_run:
        save_denied_ips()
        subprocess.run(NGINX_RELOAD, shell=True, check=True)

    if dry_run:
        print("Dry run finished")
    else:
        monitor_error_log()

if __name__ == "__main__":
    main()
