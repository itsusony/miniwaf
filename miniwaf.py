import os
import re
import subprocess
import time
import gzip
from typing import Callable, Optional
from glob import glob
import ipaddress
import sys
import asyncio
import aiofiles

# Configuration
NGINX_ERROR_LOG = os.environ.get('NGINX_ERROR_LOG', '/var/log/nginx/error.log')
NGINX_ACCESS_LOG = os.environ.get('NGINX_ACCESS_LOG', '/var/log/nginx/access.log')
NGINX_DENY_CONF = os.environ.get('NGINX_DENY_CONF', '/etc/nginx/conf.d/deny.conf')
NGINX_RELOAD = os.environ.get('NGINX_RELOAD', 'nginx -s reload')
UFW_ADD_RULE = os.environ.get('UFW_ADD_RULE', 'ufw deny from %s to any')
ILLEGALS = ['phpmyadmin', 'wp-login.php', 'CoordinatorPortType', 'azenv.php', '.vscode', '.git', '.env', 'phpinfo']
NGINX_RELOAD_INTERVAL = 5  # Minimum time between Nginx reloads in seconds

# Global variables
map_of_ips = set()
last_nginx_reload = 0
nginx_reload_needed = False

async def load_denied_ips():
    global map_of_ips
    if not os.path.exists(NGINX_DENY_CONF):
        async with aiofiles.open(NGINX_DENY_CONF, 'w') as f:
            await f.write("# miniwaf\n")
    async with aiofiles.open(NGINX_DENY_CONF, 'r') as f:
        content = await f.read()
        map_of_ips = set(re.findall(r'deny (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3});', content))

async def save_denied_ips():
    global map_of_ips
    sorted_ips = sorted(map_of_ips, key=lambda ip: ipaddress.ip_address(ip))
    async with aiofiles.open(NGINX_DENY_CONF, 'w') as f:
        await f.write("# miniwaf\n")
        for ip in sorted_ips:
            await f.write(f"deny {ip};\n")

async def append_deny(ip: str, dry_run: bool):
    global map_of_ips, nginx_reload_needed
    if ip and ip not in map_of_ips:
        map_of_ips.add(ip)
        if not dry_run:
            await save_denied_ips()
            proc = await asyncio.create_subprocess_shell(
                UFW_ADD_RULE % ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            nginx_reload_needed = True
        else:
            print(f"Would block IP: {ip}")
        return True
    return False

async def judge_log(log: str, is_error_log: bool, dry_run: bool):
    ip_pattern = r'client: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' if is_error_log else r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    match = re.search(ip_pattern, log)
    if match and match.group(1) not in map_of_ips:
        ip = match.group(1)
        if any(illegal.lower() in log.lower() for illegal in ILLEGALS):
            if dry_run:
                log_type = "error" if is_error_log else "access"
                print(f"Block reason ({log_type} log): {next(illegal for illegal in ILLEGALS if illegal.lower() in log.lower())}")
            if await append_deny(ip, dry_run):
                return True
    return False

async def process_log(file_path: str, is_error_log: bool, dry_run: bool):
    changes_made = False
    try:
        if file_path.endswith('.gz'):
            with gzip.open(file_path, 'rt') as f:
                for line in f:
                    if await judge_log(line, is_error_log, dry_run):
                        changes_made = True
        else:
            async with aiofiles.open(file_path, 'r') as f:
                async for line in f:
                    if await judge_log(line, is_error_log, dry_run):
                        changes_made = True
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
    return changes_made

async def reload_nginx_if_needed():
    global last_nginx_reload, nginx_reload_needed
    current_time = time.time()
    if nginx_reload_needed and (current_time - last_nginx_reload) >= NGINX_RELOAD_INTERVAL:
        try:
            proc = await asyncio.create_subprocess_shell(
                NGINX_RELOAD,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            print("Nginx reloaded successfully")
            last_nginx_reload = current_time
            nginx_reload_needed = False
        except Exception as e:
            print(f"Nginx reload failed: {e}")

async def monitor_logs():
    while True:
        async with aiofiles.open(NGINX_ERROR_LOG, 'r') as error_log, \
                   aiofiles.open(NGINX_ACCESS_LOG, 'r') as access_log:
            await error_log.seek(0, 2)
            await access_log.seek(0, 2)

            while True:
                error_line = await error_log.readline()
                access_line = await access_log.readline()

                if not error_line and not access_line:
                    await asyncio.sleep(0.1)
                else:
                    if error_line:
                        await judge_log(error_line, True, False)
                    if access_line:
                        await judge_log(access_line, False, False)

                if nginx_reload_needed:
                    await reload_nginx_if_needed()

async def main():
    global map_of_ips
    dry_run = 'dry_run' in sys.argv
    if dry_run:
        print("Starting in dry run mode")

    await load_denied_ips()

    error_log_files = glob(f"{NGINX_ERROR_LOG}*")
    access_log_files = glob(f"{NGINX_ACCESS_LOG}*")
    changes_made = False

    for log_file in error_log_files:
        if await process_log(log_file, True, dry_run):
            changes_made = True
            print(f"Changes made while processing error log: {log_file}")

    for log_file in access_log_files:
        if await process_log(log_file, False, dry_run):
            changes_made = True
            print(f"Changes made while processing access log: {log_file}")

    if changes_made and not dry_run:
        await save_denied_ips()
        await reload_nginx_if_needed()

    if dry_run:
        print("Dry run finished")
    else:
        await monitor_logs()

if __name__ == "__main__":
    asyncio.run(main())
