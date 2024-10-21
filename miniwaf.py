import os
import re
import subprocess
import asyncio
import sys
from typing import Set, List
import aiofiles
import gzip
from glob import glob

# Configuration
NGINX_ERROR_LOG = os.environ.get('NGINX_ERROR_LOG', '/var/log/nginx/error.log')
NGINX_ACCESS_LOG = os.environ.get('NGINX_ACCESS_LOG', '/var/log/nginx/access.log')
UFW_ADD_RULE = os.environ.get('UFW_ADD_RULE', 'ufw deny from %s to any')
ILLEGALS = ['phpmyadmin', 'wp-login.php', 'CoordinatorPortType', 'azenv.php', '.vscode', '.git', '.env', 'phpinfo', '/cdn-cgi/', '/cgi-bin/', 'paloaltonetworks.com', '/wp-config.php']
WHITELIST_FILE = os.environ.get('WHITELIST_FILE', '/etc/nginx/whitelist.txt')

# Global variables
blocked_ips: Set[str] = set()
whitelisted_ips: Set[str] = set()

async def load_blocked_ips():
    global blocked_ips
    try:
        proc = await asyncio.create_subprocess_shell(
            "ufw status | grep DENY | awk '{print $3}'",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        blocked_ips = set(stdout.decode().strip().split('\n'))
    except Exception as e:
        print(f"Error loading blocked IPs: {e}")

async def load_whitelisted_ips():
    global whitelisted_ips
    try:
        async with aiofiles.open(WHITELIST_FILE, mode='r') as f:
            content = await f.read()
            whitelisted_ips = set(ip.strip() for ip in content.split('\n') if ip.strip())
    except FileNotFoundError:
        print(f"Whitelist file not found: {WHITELIST_FILE}")
    except Exception as e:
        print(f"Error loading whitelisted IPs: {e}")

async def block_ip(ip: str, dry_run: bool):
    global blocked_ips
    if ip in whitelisted_ips:
        print(f"IP {ip} is whitelisted, not blocking")
        return False
    if ip and ip not in blocked_ips:
        if not dry_run:
            proc = await asyncio.create_subprocess_shell(
                UFW_ADD_RULE % ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            blocked_ips.add(ip)
            print(f"Blocked IP: {ip}")
        else:
            print(f"Would block IP: {ip}")
        return True
    return False

async def process_log_entry(log_entry: str, is_error_log: bool, dry_run: bool):
    ip_pattern = r'client: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' if is_error_log else r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    ip_match = re.search(ip_pattern, log_entry)
    if ip_match:
        ip = ip_match.group(1)
        if ip in whitelisted_ips:
            return False
        if any(illegal.lower() in log_entry.lower() for illegal in ILLEGALS):
            if dry_run:
                log_type = "error" if is_error_log else "access"
                print(f"Would block IP {ip} due to: {next(illegal for illegal in ILLEGALS if illegal.lower() in log_entry.lower())} (in {log_type} log)")
            return await block_ip(ip, dry_run)
    return False

async def process_log_file(file_path: str, is_error_log: bool, dry_run: bool):
    try:
        if file_path.endswith('.gz'):
            with gzip.open(file_path, 'rt') as f:
                for line in f:
                    await process_log_entry(line, is_error_log, dry_run)
        else:
            async with aiofiles.open(file_path, 'r') as f:
                async for line in f:
                    await process_log_entry(line, is_error_log, dry_run)
        print(f"Processed log file: {file_path}")
    except Exception as e:
        print(f"Error processing {file_path}: {e}")

async def get_log_files(base_log_path: str) -> List[str]:
    log_dir = os.path.dirname(base_log_path)
    log_name = os.path.basename(base_log_path)
    pattern = os.path.join(log_dir, f"{log_name}*")
    return sorted(glob(pattern), key=os.path.getmtime, reverse=True)

async def process_all_logs(dry_run: bool):
    error_logs = await get_log_files(NGINX_ERROR_LOG)
    access_logs = await get_log_files(NGINX_ACCESS_LOG)

    for log_file in error_logs:
        await process_log_file(log_file, True, dry_run)

    for log_file in access_logs:
        await process_log_file(log_file, False, dry_run)

async def monitor_logs(error_log: str, access_log: str, dry_run: bool):
    async with aiofiles.open(error_log, 'r') as error_file, \
               aiofiles.open(access_log, 'r') as access_file:

        # ファイルの末尾に移動
        await error_file.seek(0, 2)
        await access_file.seek(0, 2)

        while True:
            error_line = await error_file.readline()
            access_line = await access_file.readline()

            if not error_line and not access_line:
                await asyncio.sleep(0.1)
            else:
                if error_line:
                    await process_log_entry(error_line, True, dry_run)
                if access_line:
                    await process_log_entry(access_line, False, dry_run)

async def main():
    dry_run = 'dry_run' in sys.argv
    if dry_run:
        print("Starting in dry run mode")

    await load_blocked_ips()
    await load_whitelisted_ips()

    # 全ての既存ログファイルを処理
    await process_all_logs(dry_run)

    if dry_run:
        print("Dry run finished")
    else:
        print("Starting log monitoring")
        await monitor_logs(NGINX_ERROR_LOG, NGINX_ACCESS_LOG, dry_run)

if __name__ == "__main__":
    asyncio.run(main())
