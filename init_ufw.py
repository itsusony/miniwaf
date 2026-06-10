#!/usr/bin/env python3
"""
init_ufw.py - Analyze UFW state and recommend safe initial settings for miniwaf.

This script checks your current UFW configuration, warns about potential issues,
and optionally applies safe baseline settings (default allow incoming + SSH access)
so miniwaf can operate in blacklist mode.
"""

import subprocess
import sys
import argparse
import re


class C:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def c(text, color):
    return f"{color}{text}{C.RESET}"


def run(cmd, check=False):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\n{result.stderr.strip()}")
    return result.returncode, result.stdout, result.stderr


def check_installed():
    ret, _, _ = run("which ufw")
    return ret == 0


def get_status():
    ret, stdout, stderr = run("ufw status verbose")
    if ret != 0:
        # Try non-verbose fallback
        ret, stdout, stderr = run("ufw status")
        if ret != 0:
            return None, stderr
    return stdout, None


def parse_status(text):
    lines = text.strip().split('\n')
    data = {
        'active': False,
        'incoming': 'unknown',
        'outgoing': 'unknown',
        'routed': 'unknown',
        'rules': [],
        'allow_rules': [],
        'deny_rules': [],
    }

    for line in lines:
        line_stripped = line.strip()
        if line_stripped.startswith('Status:'):
            data['active'] = 'active' in line_stripped.lower()
        elif line_stripped.startswith('Default:'):
            # Default: deny (incoming), allow (outgoing), disabled (routed)
            m = re.search(r'(\w+)\s*\(incoming\)', line_stripped, re.I)
            if m:
                data['incoming'] = m.group(1).lower()
            m = re.search(r'(\w+)\s*\(outgoing\)', line_stripped, re.I)
            if m:
                data['outgoing'] = m.group(1).lower()
            m = re.search(r'(\w+)\s*\(routed\)', line_stripped, re.I)
            if m:
                data['routed'] = m.group(1).lower()

    # Parse rules
    in_rules = False
    for line in lines:
        ls = line.strip()
        if not ls:
            continue
        if ls.startswith('To ') and 'Action' in ls:
            in_rules = True
            continue
        if ls.startswith('--'):
            continue
        if in_rules:
            # Heuristic: rule lines contain ALLOW/DENY/REJECT/LIMIT
            if re.search(r'\b(ALLOW|DENY|REJECT|LIMIT)\b', ls, re.I):
                data['rules'].append(ls)
                if re.search(r'\bALLOW\b', ls, re.I):
                    data['allow_rules'].append(ls)
                elif re.search(r'\bDENY\b', ls, re.I):
                    data['deny_rules'].append(ls)

    return data


def has_ssh_rule(rules):
    """Check if there's any rule mentioning port 22 or 'ssh'."""
    for r in rules:
        upper = r.upper()
        if '22' in upper or 'SSH' in upper:
            return True
    return False


def find_subnet_allows(rules):
    """Find allow rules that target a subnet (potential conflict with deny rules)."""
    subnet_rules = []
    for r in rules:
        if not re.search(r'\bALLOW\b', r, re.I):
            continue
        # Look for CIDR notation like 10.0.0.0/8 or 192.168.0.0/16
        if re.search(r'\d+\.\d+\.\d+\.\d+/\d+', r) or re.search(r'[0-9a-fA-F:]+/\d+', r):
            # Skip trivial 0.0.0.0/0 and ::/0 (treated as Anywhere)
            if '0.0.0.0/0' not in r and '::/0' not in r:
                subnet_rules.append(r)
    return subnet_rules


def ask_yes_no(prompt, default_no=True, auto_yes=False):
    if auto_yes:
        print(f"{prompt} [Y/n]: Y (auto-accepted)")
        return True
    suffix = " [y/N]: " if default_no else " [Y/n]: "
    resp = input(prompt + suffix).strip().lower()
    if default_no:
        return resp in ('y', 'yes')
    return resp not in ('n', 'no')


def main():
    parser = argparse.ArgumentParser(
        description="Analyze UFW state and recommend safe settings for miniwaf"
    )
    parser.add_argument(
        '-y', '--yes',
        action='store_true',
        help='Auto-accept safe recommended changes without prompting'
    )
    args = parser.parse_args()

    print(c("=" * 56, C.BOLD))
    print(c("         miniwaf UFW Initializer", C.BOLD))
    print(c("=" * 56, C.BOLD))
    print()

    if not check_installed():
        print(c("[ERROR] UFW is not installed.", C.RED))
        print()
        print("Please install UFW first:")
        print("  Debian/Ubuntu:  sudo apt update && sudo apt install ufw")
        print("  RHEL/CentOS:    sudo yum install epel-release && sudo yum install ufw")
        print("  Arch:           sudo pacman -S ufw")
        sys.exit(1)

    stdout, err = get_status()
    if stdout is None:
        print(c(f"[ERROR] Failed to get UFW status: {err.strip()}", C.RED))
        sys.exit(1)

    data = parse_status(stdout)

    # Print report
    print(c("Current UFW State:", C.BOLD))
    status_str = "Active" if data['active'] else c("INACTIVE", C.YELLOW)
    print(f"  Status:          {status_str}")
    print(f"  Default Incoming: {data['incoming'].upper()}")
    print(f"  Default Outgoing: {data['outgoing'].upper()}")
    print(f"  Total Rules:     {len(data['rules'])}  "
          f"(allow: {len(data['allow_rules'])}, deny: {len(data['deny_rules'])})")

    # Analysis
    print()
    print(c("Analysis:", C.BOLD))

    recommendations = []
    warnings = []

    # 1. Active check
    if not data['active']:
        warnings.append(
            "UFW is currently INACTIVE. miniwaf can add deny rules, but they won't "
            "take effect until UFW is enabled."
        )
    else:
        recommendations.append("UFW is active.")

    # 2. SSH check (critical if inactive)
    ssh_ok = has_ssh_rule(data['rules'])
    if not ssh_ok:
        warnings.append(
            "No SSH (port 22) allow rule detected. Enabling UFW without SSH access "
            "may lock you out of the server."
        )
    else:
        recommendations.append("SSH access appears to be allowed.")

    # 3. Default policy
    if data['incoming'] == 'deny':
        recommendations.append(
            "Default incoming is DENY (whitelist mode). This is MORE secure than "
            "blacklist mode, but miniwaf deny rules will still work alongside it."
        )
    elif data['incoming'] == 'allow':
        recommendations.append(
            "Default incoming is ALLOW (blacklist mode). This is the typical setup "
            "for miniwaf."
        )
    else:
        warnings.append("Could not determine default incoming policy.")

    # 4. Subnet allow conflicts
    subnet_allows = find_subnet_allows(data['allow_rules'])
    if subnet_allows:
        warnings.append(
            f"Found {len(subnet_allows)} allow rule(s) for specific subnets. "
            "If miniwaf denies an IP inside these subnets, the allow rule may "
            "match first and the deny will not take effect."
        )

    for rec in recommendations:
        print(c(f"  ✓ {rec}", C.GREEN))
    for warn in warnings:
        print(c(f"  ⚠ {warn}", C.YELLOW))

    # Specific guidance
    print()
    print(c("Recommended Setup for miniwaf:", C.BOLD))

    if not data['active']:
        print()
        print("  Since UFW is inactive, here are the safe steps to enable it:")
        print()
        if not ssh_ok:
            print(c("  Step 1: Allow SSH (CRITICAL - do not skip)", C.YELLOW))
            print("          sudo ufw allow 22/tcp")
            print("          # or if you use a custom SSH port:")
            print("          # sudo ufw allow <your_port>/tcp")
        else:
            print(c("  Step 1: SSH is already allowed", C.GREEN))

        print()
        print("  Step 2: Set default incoming policy")
        if data['incoming'] != 'allow':
            print("          sudo ufw default allow incoming")
            print("          # This puts UFW in blacklist mode (allow all, deny specific).")
            print("          # If you prefer whitelist mode (deny all, allow specific), keep")
            print("          # the current policy and skip this step.")
        else:
            print("          (Already set to allow incoming)")

        print()
        print("  Step 3: Enable UFW")
        print("          sudo ufw enable")

    else:
        print()
        if data['incoming'] != 'allow':
            print("  If you want blacklist mode (recommended for miniwaf):")
            print("          sudo ufw default allow incoming")
            print()
        print("  UFW is already active. You can start miniwaf now.")

    if subnet_allows:
        print()
        print(c("  Note: Potential rule conflicts detected", C.YELLOW))
        print("  You have allow rules for subnets:")
        for r in subnet_allows[:5]:
            print(f"      {r}")
        if len(subnet_allows) > 5:
            print(f"      ... and {len(subnet_allows) - 5} more")
        print()
        print("  To ensure miniwaf deny rules take precedence, use:")
        print("      export UFW_ADD_RULE='ufw insert 1 deny from %s to any'")
        print("      ./miniwaf")

    # Interactive apply
    if not data['active']:
        print()
        print(c("Apply safe initial settings now?", C.BOLD))
        print("This will run:")
        if not ssh_ok:
            print("  - sudo ufw allow 22/tcp")
        if data['incoming'] != 'allow':
            print("  - sudo ufw default allow incoming")
        print("  - sudo ufw enable")
        print("Existing rules will NOT be removed or modified.")
        print()

        if ask_yes_no("Proceed", default_no=True, auto_yes=args.yes):
            try:
                if not ssh_ok:
                    print("  → Adding SSH allow rule...")
                    run("sudo ufw allow 22/tcp", check=True)
                    print(c("    Done.", C.GREEN))

                if data['incoming'] != 'allow':
                    print("  → Setting default incoming to allow...")
                    run("sudo ufw default allow incoming", check=True)
                    print(c("    Done.", C.GREEN))

                print("  → Enabling UFW...")
                run("sudo ufw enable", check=True)
                print(c("    Done.", C.GREEN))

                print()
                print(c("UFW is now active and configured for miniwaf.", C.GREEN))
                print("You can now run:")
                print("    sudo ./miniwaf")
            except RuntimeError as e:
                print()
                print(c(f"[ERROR] {e}", C.RED))
                sys.exit(1)
        else:
            print()
            print("Skipped. You can apply the settings manually using the commands above.")

    print()
    print(c("Done.", C.GREEN))


if __name__ == '__main__':
    main()
