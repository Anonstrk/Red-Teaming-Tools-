# SMB Password Spray Script

A simple Python tool for testing a single password against a list of usernames
over SMB, built on top of Impacket's `SMBConnection` class. Written as a
lightweight, transparent alternative to CrackMapExec/NetExec for lab and
authorized penetration-testing use.

## Requirements

- Python 3
- [Impacket](https://github.com/fortra/impacket) installed (`pip install impacket`)
- Network access to the target SMB service (port 445)

## Files

| File | Description |
|---|---|
| `smb_spray.py` | The spray script |
| `users_clean.txt` | Example username list (one username per line, no domain suffix) |

## Usage

```bash
python3 smb_spray.py <target_ip> <userlist_file> <password> [domain]
```

**Example:**
```bash
python3 smb_spray.py 172.16.231.138 users_clean.txt 'MyPassword2022' FRIENDS.local
```

### Arguments

- `target_ip` — IP address or hostname of the SMB server
- `userlist_file` — Path to a text file with one username per line
- `password` — The single password to spray across all users
- `domain` *(optional)* — Windows/AD domain name (NetBIOS or FQDN). Leave blank
  for local/workgroup accounts.

## Important: Username File Format

The userlist file must contain **bare usernames only** — no `@domain` suffix
and no blank/header lines:

```
cbing
pbuffay
mgeller
jtribbiani
```

Do **not** use `user@domain.local` format if you're also passing a `domain`
argument — the script would submit both, which fails authentication even with
a correct password.

## Output

```
[*] Target: 172.16.231.138  Domain: FRIENDS.local  Password: MyPassword2022
[*] Loaded 8 users from users_clean.txt

[+] SUCCESS: jtribbiani  (MyPassword2022)
[-] fail:    cbing       (STATUS_LOGON_FAILURE)
...

[*] Done. 1 valid login(s): ['jtribbiani']
```

- `[+] SUCCESS` — valid credential pair found
- `[-] fail` — login rejected; a short reason is shown (e.g. bad password,
  account disabled, account locked)

## How It Works

For each username in the list, the script opens an `SMBConnection` to the
target and calls `.login(username, password, domain)`. If no exception is
raised, the credentials are valid. This mirrors what CrackMapExec/NetExec do
internally, but without rate-limiting, threading, or output formatting — it's
meant to be easy to read and modify.

## Limitations / Ideas for Extension

- **Sequential only** — one login attempt at a time, no threading. For large
  user lists, consider adding a thread pool (e.g. `concurrent.futures`).
- **No lockout protection** — the script does not track failed attempts per
  user or add delays. On a real engagement, add a delay/jitter between
  attempts and stop spraying an account after one bad attempt to avoid
  lockouts.
- **Single password only** — for multiple passwords, wrap the script in an
  outer loop or extend it to accept a password list.
- **No output file** — successful hits are only printed to the console.
  Redirect output or add a `--outfile` option if you need to log results.

## Legal / Ethical Use

Only use this tool against systems you own or are explicitly authorized to
test (e.g. a lab environment, CTF, or a signed penetration-testing
engagement). Unauthorized access to computer systems is illegal in most
jurisdictions.
