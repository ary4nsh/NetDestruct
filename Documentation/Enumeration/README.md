# Enumeration

NetDestruct enumeration modules probe network services for misconfigurations, anonymous access, and weak credentials.

Implementation packages live under `libs/enumeration/`.

| Module | Section |
|--------|---------|
| SMB brute / enum | [SMB brute](#smb-brute-force---smb---brute), [SMB enum](#smb-enumeration---smb---enum) |
| FTP / bounce / TFTP | [FTP](#ftp-anonymous--features--brute---ftp), [Bounce](#ftp-bounce---bounce), [TFTP](#tftp-getput---tftp) |
| SSH | [Auth methods](#ssh-authentication-methods---ssh---auth-methods) … [Brute](#ssh-brute-force---ssh---brute) |
| SNMP | [Brute v2c](#snmp-community-brute-force---snmp---brute---v2c) … [Walk](#snmp-walk---snmp---walk) |
| Telnet | [Enum](#telnet-enumeration---telnet---enum), [Brute](#telnet-brute-force---telnet---brute) |
| Memcached get | [Memcached key get](#memcached-key-get---memcached---enum-key) |

---

## SMB brute force (`--smb --brute`)

Online SMB username/password guessing against a **single IPv4 host**. Each attempt opens a fresh TCP connection, negotiates SMB 2.0.2, and completes an NTLM session setup (NTLMv2 response).

SMB version and OS fingerprinting (`--smb --version`) is documented under [Intelligence Gathering](../Intelligence%20Gathering/README.md#smb-version-scan).

Implementation: `libs/enumeration/smb/` (orchestration) and `libs/intelligence-gathering/smbvers/` (`TryLogin`, shared SMB/NTLM stack).

### Usage

Default account check (no wordlists; built-in usernames, blank/username/reversed passwords):

```bash
./NetDestruct --smb --brute --target 192.168.109.160
```

Custom wordlists:

```bash
./NetDestruct --smb --brute --target 192.168.109.160 --userlist users.txt --passlist passwords.txt
```

Non-default SMB port (default **445**):

```bash
./NetDestruct --smb --brute --target 10.0.0.5 --port 139
```

### Flags

| Flag | Description |
|------|-------------|
| `--smb` | Enable SMB mode (required) |
| `--brute` | Run password guessing (mutually exclusive with `--version` and `--enum`) |
| `--target <ip>` | **Single** IPv4 address (no ranges, CIDR, or comma lists) |
| `--userlist <file>` | Optional username wordlist; if omitted, uses default SMB names (`administrator`, `guest`, …) |
| `--passlist <file>` | Optional password wordlist; if omitted with no `--userlist`, only blank / username / reversed tries; if `--userlist` is set, a short built-in common-password set is used |
| `--port` | Optional TCP port (default **445**). When set, NetDestruct does **not** fall back to 139 |

`--smb` requires exactly one of `--version`, `--brute`, or `--enum`. `--brute` cannot be used without `--smb`.

### Password order per user

For each username from `--userlist`, passwords are tried in this order (duplicates removed):

1. Blank password  
2. Password equal to the username  
3. Reversed username  
4. Every entry from `--passlist`

This matches the common smb-brute pattern of trying obvious defaults before the full wordlist.

### Outcomes and stopping rules

Authentication results follow NTSTATUS mapping:

| Result | Meaning |
|--------|---------|
| Valid credentials | Successful logon |
| Valid credentials, account granted guest access only | Password accepted; guest-only access |
| Valid credentials, account disabled / expired / locked / time or workstation restricted | Password is correct; logon blocked for another reason |
| (no line) | Wrong username/password |

Bullet labels: `valid`, `valid (disabled)`, `valid (locked)`, `valid (guest only)`, etc.

- One **bullet line** per user when a valid password is detected (wrong passwords produce no line).  
- The scan **continues** through the user list after lockout on one account.  
- Transient connection errors are reported on stderr; a short backoff is applied before continuing.

### Output color

- `[SMB]` is **yellow** (`\x1b[33m`); the user list and result bullets are plain text.

Example:

```text
[SMB] Target: 192.168.109.160:445
[SMB] Using built-in default account list
[SMB] Users: 10  Passwords: 0
Testing users: root, admin, administrator, webadmin, sysadmin, netadmin, guest, user, web, test

- administrator:<unknown> : valid (locked)
- guest:<blank> : valid (disabled)
```

### Requirements

- TCP reachability to the target on the chosen port (445 by default)
- No raw sockets or root required (unlike L2 CDP/DTP enumeration)
- Windows and Linux builds supported

### Notes

- Prefer small wordlists and watch for **account lockout** policies; the tool exits on lockout detection.  
- Domain logons are attempted with an empty domain unless you extend the `Bruter`/`TryLogin` wiring; workgroup and local accounts are the typical case.  
- For service/version context before brute forcing, run `--smb --version --target <ip>` first.

### Related enumeration

| Module | Path | CLI (examples) |
|--------|------|----------------|
| SSH | `libs/enumeration/ssh/` | `--ssh --auth-methods`, `--ssh --cipher-enum`, `--ssh --key-enum`, `--ssh --brute`; offline key crack: `--ssh --file` (see Authentication Cracking) |
| Telnet | `libs/enumeration/telnet/` | `--telnet --enum --target`, `--telnet --brute --target --userlist --passlist` |
| FTP | `libs/enumeration/ftp/` | `--ftp --anon`, `--features`, `--userlist` / `--passlist`, `--bounce` |
| TFTP | `libs/enumeration/tftp/` | `--tftp --get` / `--put` |
| SNMP | `libs/enumeration/snmp/` | `--snmp --enum --v2c`, `--snmp --walk --v2c`, `--snmp --brute --v2c --passlist`, `--snmp --brute --v3 --userlist --passlist`, bulk scan (`--file`) |

---

## FTP anonymous / features / brute (`--ftp`)

FTP control-channel enumeration over native TCP (RFC 959): anonymous login check, `FEAT` capability listing, and username/password brute force.

Implementation: `libs/enumeration/ftp/`

### Usage

```bash
./NetDestruct --ftp 192.168.1.50 --anon
./NetDestruct --ftp 192.168.1.50 --features
./NetDestruct --ftp 192.168.1.50 --anon --features
./NetDestruct --ftp 192.168.1.50 --userlist users.txt --passlist passwords.txt
./NetDestruct --ftp 192.168.1.50 --anon --port 2121
./NetDestruct --ftp 192.168.1.50:2121 --anon
```

### Flags

| Flag | Description |
|------|-------------|
| `--ftp <host>` | FTP server host, `host:port`, or domain name (default port **21**) |
| `--anon` | Check anonymous login (`USER anonymous` / `PASS anonymous@`) |
| `--features` | List server capabilities via `FEAT` |
| `--userlist <file>` | Username wordlist for brute force |
| `--passlist <file>` | Password wordlist for brute force |
| `--port` | Optional TCP control port when `--ftp` has no `:port` (default **21**) |

`--ftp` requires at least one of `--anon`, `--features`, `--userlist`, or `--passlist`. If either wordlist flag is set, both `--userlist` and `--passlist` are required (brute path).

### Behavior

**Anonymous / features**

1. TCP connect; require greeting **220**; print banner
2. `--anon`: try `anonymous` / `anonymous@`; on success print green `Anonymous login ALLOWED` and `PWD` when available
3. `--features`: send `FEAT`; on **211** list feature lines; on **500**/**502** report not supported

**Brute force**

1. Load both wordlists (blank lines skipped)
2. For each user, try each password on a fresh connection; stop that user after the first **230**
3. Print green `[+] user : pass` on hit; summary `Tried: N  Found: M`

### Example output

```
FTP server:   192.168.1.50:21
Banner:       220 (vsFTPd 3.0.3)

[+] Anonymous login ALLOWED
    Working directory: /

[+] Server features:
    EPSV
    PASV
    UTF8
```

### Output color

- Successful anonymous / credential hits are **green**

### Requirements

- TCP reachability to the FTP control port (default 21)
- No root required

---

## FTP bounce (`--bounce`)

FTP PORT bounce probe / port scan through a relay.

Implementation: `libs/enumeration/ftp/` (`bounce.go`)

### Usage

```bash
./NetDestruct --bounce "anonymous:anonymous@192.168.1.50 10.0.0.1"
./NetDestruct --bounce "anonymous:anonymous@192.168.1.50 10.0.0.1" --port 22,80,443
./NetDestruct --bounce "user:pass@192.168.1.50:2121 10.0.0.1" --port 21,22,445
```

### Flags

| Flag | Description |
|------|-------------|
| `--bounce <spec>` | Format: `user:password@relay-host <target-ip>` (space-separated target). Relay host may be IP, hostname, `host:port`, IPv4 CIDR, or last-octet range |
| `--port <list>` | Optional comma-separated TCP ports on the bounce **target** to probe |

`--bounce` is independent of `--ftp`.

### Behavior

1. Parse credentials and target; expand relay host to one or more FTP servers
2. Per relay: authenticate, then capability check
3. If `--port` is set: for each port, issue `PORT` then `LIST` → `open` / `closed` / `filtered` / `bounce-denied`

### Example output

```
FTP bounce scan
  Relay creds:  anonymous:***@192.168.1.50
  Target:       10.0.0.1
  Ports:        22,80,443

[192.168.1.50] bounce working!
[192.168.1.50] scanning 10.0.0.1 via bounce:
  22/tcp  open
  80/tcp  closed
  443/tcp  filtered
```

### Output color

- `bounce working!` and open ports: **green**
- Restricted capability / non-open states: **yellow**

### Requirements

- TCP reachability to the FTP relay; valid credentials; third-party `PORT` allowed
- Target must be IPv4 (or resolve to IPv4)
- No root required

---

## TFTP get/put (`--tftp`)

RFC 1350 TFTP client: probe/download remote files (`--get`) or upload local files (`--put`) over UDP (default port **69**).

Implementation: `libs/enumeration/tftp/`

### Usage

```bash
./NetDestruct --tftp 192.168.1.50 --get running-config,startup-config,passwd
./NetDestruct --tftp 192.168.1.50 --put ./payload.bin,./note.txt
./NetDestruct --tftp tftp.lab.local --get cisco.cfg --port 6969
./NetDestruct --tftp 192.168.1.50:6969 --get cisco.cfg
```

### Flags

| Flag | Description |
|------|-------------|
| `--tftp <host>` | TFTP server host, `host:port`, or domain name (default port **69**) |
| `--get <files>` | Comma-separated **remote** filenames to download/probe |
| `--put <files>` | Comma-separated **local** paths to upload (remote name = basename) |
| `--port` | Optional UDP port when `--tftp` has no `:port` (default **69**) |

`--tftp` requires exactly one of `--get` or `--put`.

### Behavior

**`--get`**

1. Send octet-mode RRQ per remote name; follow transfer TID; ACK data blocks
2. Outcomes: `FOUND (N bytes)` with inline content (capped), `not found`, or `EXISTS (access denied)` (error code 2)
3. Summary: `Found: X/Y`

**`--put`**

1. Read each local file; WRQ → ACK 0 → stream 512-byte DATA blocks
2. Print `uploaded` or error; summary `Uploaded: X/Y`

### Example output

```
TFTP server:  192.168.1.50:69
Downloading 3 file(s)...

  [+] running-config                   FOUND (842 bytes)
  [+] secret.txt                       EXISTS (access denied)
  [-] missing.cfg                      not found

Found: 2/3
```

### Output color

- `FOUND` / `uploaded`: **green**
- `EXISTS (access denied)`: **yellow**

### Requirements

- UDP reachability to the TFTP server (default **69**)
- No root required

---

## SSH authentication methods (`--ssh --auth-methods`)

Lists authentication methods a SSH server supports for a given username. Connects, completes the SSH handshake, sends `USERAUTH` method `none`, and prints the server’s “authentications that can continue” list (and optional pre-auth banner).

Implementation: `libs/enumeration/ssh/` — native Go only (`net`, `crypto/aes`, `crypto/ecdh`, `crypto/hmac`, `crypto/sha*`; no third-party SSH libraries).

### Usage

```bash
./NetDestruct --ssh --auth-methods --target 192.168.109.150 --username cisco
```

Custom port (default **22**):

```bash
./NetDestruct --ssh --auth-methods --target 10.0.0.1 --username admin --port 2222
```

### Flags

| Flag | Description |
|------|-------------|
| `--ssh` | Enable SSH mode (required) |
| `--auth-methods` | Enumerate supported authentication methods |
| `--target <ip>` | Target host IP or hostname |
| `--username <user>` | Username to probe (required; starts an auth attempt that may be logged) |
| `--port` | TCP port (optional, default **22**) |

`--ssh` requires exactly one of `--auth-methods`, `--cipher-enum`, `--key-enum`, `--brute`, or `--file`. `--auth-methods` requires `--ssh`.

### Behavior

1. TCP connect and grab the SSH identification string 
2. Complete SSH version exchange and key exchange (stdlib `crypto/*` only)  
3. Attempt `none` authentication for `--username` (RFC 4252)  
4. Capture and print the server’s allowed method list  
5. Print any pre-auth `USERAUTH` banner if the server sent one  

Typical methods: `publickey`, `password`, `keyboard-interactive`.

### Example output

```
[SSH] Target: 192.168.109.150:22  User: ubuntu-clone
[SSH] Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
      Supported authentication methods:
      - publickey
      - password
```

### Output color

- `[SSH]` is **yellow** (`\x1b[33m`)

### Requirements

- Reachable SSH TCP port (default 22)
- No root required 

---

## SSH cipher enumeration (`--ssh --cipher-enum`)

SSH2 discovery for targets. One command runs three scripts against `--target`:

- Parse server `SSH_MSG_KEXINIT` and list kex / host-key / encryption / MAC / compression algorithms (combines c2s+s2c when identical) 
- For each ssh-keyscan host-key family (`RSA` incl. `rsa-sha2-*`, `ECDSA`, `ED25519`, `ECDSA_SK`, `ED25519_SK`, `MLDSA44_ED25519`, plus legacy `DSA`), complete KEX and print MD5 + SHA256 fingerprints and the full public key
- Query-only `publickey` auth (RFC 4252) against known-bad static keys

Implementation: `libs/enumeration/ssh/cipher_enum.go` + stdlib SSH transport — native Go only (no `golang.org/x/crypto`).

### Usage

```bash
./NetDestruct --ssh --cipher-enum --target 192.168.109.150
```

Custom port (default **22**):

```bash
./NetDestruct --ssh --cipher-enum --target 10.0.0.1 --port 2222
```

### Flags

| Flag | Description |
|------|-------------|
| `--ssh` | Enable SSH mode (required) |
| `--cipher-enum` | Run algorithm + hostkey + known-bad publickey probes |
| `--target <ip>` | Target host IP or hostname |
| `--port` | TCP port (optional, default **22**) |

No `--username` is required. `--cipher-enum` cannot be combined with `--auth-methods`, `--brute`, or `--file` in the same run.

### Behavior

1. Banner grab (`SSH-2.0-…`)  
2. **ssh2-enum-algos** — version exchange + client `KEXINIT`, parse server algorithm lists, print each category with counts  
3. **ssh-hostkey** — one KEX per OpenSSH `ssh-keyscan` host-key family (`rsa-sha2-512,rsa-sha2-256,ssh-rsa`; ECDSA curves; `ssh-ed25519`; `sk-ecdsa-sha2-nistp256@openssh.com`; `sk-ssh-ed25519@openssh.com`; `ssh-mldsa44-ed25519`; legacy `ssh-dss`); print bits, MD5 (`aa:bb:…`), SHA256 (`SHA256:…`), and `type base64` full key  
4. **ssh-publickey-acceptance** — for each known-bad key: full KEX, then `USERAUTH` publickey query (`FALSE` signature); report accepted vendor static keys or “No public keys accepted”

### Example output

```
[SSH] Target: 192.168.109.150:22
[SSH] Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1

[SSH] SSH2 Algorithms:
      kex_algorithms (7)
          curve25519-sha256
          ...
      server_host_key_algorithms (4)
          rsa-sha2-512
          ssh-ed25519
          ...
      encryption_algorithms (6)
          aes128-ctr
          ...
      mac_algorithms (3)
          hmac-sha2-256
          ...
      compression_algorithms (1)
          none

[SSH] SSH Host Keys:
      256 aa:bb:cc:... (ED25519)
      256 SHA256:xxxx (ED25519)
      ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...
      2048 ...

[SSH] SSH Accepted Public Keys:
      Accepted Public Keys:
      - No public keys accepted
```

### Output color

- `[SSH]` is **yellow** (`\x1b[33m`)

### Requirements

- Reachable SSH TCP port (default 22)  
- No root required

---

## SSH public key acceptance (`--ssh --key-enum`)

Online SSH **public-key acceptance** probe. The SSH protocol reports whether a public key would be accepted **before** the client signs — so cleartext public keys and the public half of unencrypted private keys can be tested without completing a full signed login.

Implementation: `libs/enumeration/ssh/key_enum.go` — native Go only (stdlib `crypto/*`, `encoding/pem`; no third-party SSH libraries).

### Usage

Single username + key file:

```bash
./NetDestruct --ssh --key-enum --target 192.168.109.150 \
  --username cisco --file ./keys.pub
```

Directory of key files:

```bash
./NetDestruct --ssh --key-enum --target 10.0.0.1 \
  --userlist users.txt --file ./loot/ssh-keys/ --port 2222
```

### Flags

| Flag | Description |
|------|-------------|
| `--ssh` | Enable SSH mode (required) |
| `--key-enum` | Test whether keys are accepted for auth |
| `--target <ip>` | Target host IP or hostname |
| `--file <path>` | Key file **or directory** (required). File may contain concatenated public lines and/or PEM blocks |
| `--username <user>` | Single username to test (or use `--userlist`) |
| `--userlist <file>` | Username wordlist (one per line; `#` comments skipped) |
| `--port` | TCP port (optional, default **22**) |

Requires `--username` **or** `--userlist`. `--file` here is the key source (not offline `--ssh --file` crack). Cannot combine with `--auth-methods`, `--cipher-enum`, `--brute`, or offline `--file` crack in one run.

### Behavior

1. Banner grab (`SSH-2.0-…`)
2. Load cleartext keys from `--file` (file or directory):
   - OpenSSH public lines (`ssh-rsa`, `ssh-dss`, `ecdsa-sha2-*`, `ssh-ed25519`, …)
   - PEM RSA/DSA/EC/PKCS#8 private keys (**unencrypted only**; encrypted PEM skipped)
   - OpenSSH private keys with `cipher none` (public blob extracted without decrypt)
3. For each user × key: TCP connect, KEX, `USERAUTH` publickey query (`FALSE` — no signature)
4. Print accepted keys in **green** with MD5 fingerprint and whether a private key was present in the source 

### Example output

```
[SSH] Target: 192.168.109.150:22
[SSH] Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
[SSH] Trying 12 cleartext key(s) for 1 user(s)
- Public key accepted: 'cisco' with key 'aa:bb:cc:...' (Private Key: Yes) - cisco@lab
      Source: ./loot/id_rsa
      ssh-rsa AAAAB3NzaC1yc2E...
[SSH] Done: 1 accepted / 12 tried
```

### Output color

- `[SSH]` is **yellow** (`\x1b[33m`)
- Accepted key lines are **green**

### Requirements

- Reachable SSH TCP port (default 22)  
- Cleartext (unencrypted) keys in `--file`  
- No root required 

---

## SSH brute force (`--ssh --brute`)

Online SSH password guessing for a **single username**. Default **16** parallel tasks, max **64** (`MAXTASKS`). Each task keeps its own SSH session: reconnect + `userauth none` on errors, reuse the session after `AUTH_FAILURE` (same login). Tries `password` then `keyboard-interactive`. Timeout default **32s**.

Implementation: `libs/enumeration/ssh/brute.go` + stdlib SSH transport in `transport.go`.

### Usage

```bash
./NetDestruct --ssh --brute --target 192.168.109.150 --username cisco --passlist passwords.txt
```

Task count and custom port:

```bash
./NetDestruct --ssh --brute --target 10.0.0.1 --username admin \
  --passlist rockyou.txt --threads 16 --port 2222
```

### Flags

| Flag | Description |
|------|-------------|
| `--ssh` | Enable SSH mode (required) |
| `--brute` | Password guessing (mutually exclusive with `--auth-methods`) |
| `--target <ip>` | Target host IP or hostname |
| `--username <user>` | Username to attack (required) |
| `--passlist <file>` | Password wordlist (one per line; `#` comments skipped) |
| `--threads <n>` | Parallel tasks (optional, default **16**, max **64**) |
| `--port` | TCP port (optional, default **22**) |

### Behavior

1. Grab SSH identification banner
2. Probe once with `USERAUTH none` 
3. Abort if neither `password` nor `keyboard-interactive` is available  
4. Spawn N tasks; each pulls passwords from a shared queue  
5. Per task: on new session → connect, KEX, `none`, then try password / kbd-int; on soft failure → reuse session for the next password  
6. On success, print the credential pair in **green** and stop all tasks  
7. On connection/protocol errors, that task opens a new session 

### Example output

```
[SSH] Target: 192.168.109.150:22  User: cisco  Passwords: 50  Threads: 16
[SSH] Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
[SSH] Auth methods: publickey, password
- Found login/password pair: cisco / cisco
```

### Output color

- `[SSH]` is **yellow** (`\x1b[33m`)
- Found credential lines are **green**

### Requirements

- Reachable SSH TCP port (default 22)  
- Target must allow password and/or keyboard-interactive authentication  
- No root required  

---

## SSH private key crack (`--ssh --file`)

Offline extraction / cracking of encrypted SSH private key passphrases (`$sshng$` hashes) lives under authentication-cracking:

```bash
./NetDestruct --ssh --file id_rsa
./NetDestruct --ssh --file id_rsa --crack --wordlist rockyou.txt
```

Full documentation: [Authentication Cracking — SSH private key](../Authentication%20Cracking/README.md#ssh-private-key---ssh---file).

---

## SNMP community brute force (`--snmp --brute --v2c`)

Online SNMPv2c community string guessing against **one or more hosts** (IP, CIDR, or last-octet range). Each attempt sends an SNMPv2c GET for `sysDescr.0` (UDP). When a community is accepted, NetDestruct prints it in **green** and immediately runs an SNMPv2c **snmpwalk** (default **mib-2** subtree) with that community.

Implementation: `libs/enumeration/snmp/brute.go` (orchestration), SNMPv2c probe in `snmp.go`, walk output in `walk.go`.

### Usage

Single host:

```bash
./NetDestruct --snmp --brute --v2c --passlist communities.txt --target 192.168.1.10
```

CIDR or last-octet range:

```bash
./NetDestruct --snmp --brute --v2c --passlist communities.txt --target 192.168.109.0/24
./NetDestruct --snmp --brute --v2c --passlist communities.txt --target 192.168.1.1-50
```

Non-default UDP port (default **161**):

```bash
./NetDestruct --snmp --brute --v2c --passlist communities.txt --target 10.0.0.5 --port 1161
```

Rate limit between probes (default **100** ms, shared `--rate-limit`):

```bash
./NetDestruct --snmp --brute --v2c --passlist communities.txt --target 192.168.1.10 --rate-limit 50
```

### Flags

| Flag | Description |
|------|-------------|
| `--snmp` | Enable SNMP mode (required) |
| `--brute` | Run community string guessing (mutually exclusive with `--enum`, `--walk`, and `--file` scan mode) |
| `--v2c` | Use SNMPv2c (required with `--snmp --brute --v2c`; mutually exclusive with `--v3`) |
| `--passlist <file>` | Community wordlist (one string per line; `#` comments skipped) |
| `--target <ip\|range>` | IPv4 address, hostname, CIDR (e.g. `10.0.0.0/24`), or last-octet range (e.g. `192.168.1.1-50`) |
| `--port` | Optional UDP port (default **161**) |
| `--rate-limit` | Milliseconds to wait between probes (default **100**) |

`--passlist` and `--v2c` require `--snmp --brute`. For SNMPv3 credential brute force, use [`--snmp --brute --v3`](#snmpv3-brute-force---snmp-brute-v3) instead. `--file`, `--community`, and `--oid` are **not** used in brute mode.

### Probe behavior

1. Resolve `--target` to one or more host addresses (same rules as `--snmp --file` bulk scan).  
2. Read unique community strings from `--passlist`.  
3. For each host and community, send SNMPv2c GET `1.3.6.1.2.1.1.1.0` (sysDescr).  
4. Treat SNMP **noError** responses as valid communities.  
5. On success, print `- Found string: <community>` in **green** (with `[ip]` when scanning multiple hosts), then run snmpwalk (see [SNMP walk](#snmp-walk---snmp-walk)).  
6. Continue through the full wordlist and all targets.

### Output color

- `- Found string: …` is **green** (`\x1b[32m`).  
- `[SNMP]` status and walk lines are **yellow** (`\x1b[33m`).

Example:

```text
[SNMP] Target: 192.168.1.10:161  Communities: 4  RateLimit: 100ms
- Found string: public
[SNMP] Target: 192.168.1.10:161  Community: public  Version: SNMPv2c
[SNMP] Walking 1 subtree(s)
[SNMP] Subtree mib-2
[SNMP] system.sysDescr.0 = STRING: "Cisco IOS Software..."
[SNMP] system.sysObjectID.0 = OID: enterprises.9
[SNMP] Done (42 variables)

- Found string: private
[SNMP] Target: 192.168.1.10:161  Community: private  Version: SNMPv2c
...
```

### Requirements

- UDP reachability to the target on port **161** (or `--port`)
- No root privileges required

### Notes

- Start with a short list (`public`, `private`, `cisco`, `manager`) before large wordlists.  
- Valid communities often grant read-only MIB data useful for version, interfaces, and routing hints.  
- For a known community, use [`--snmp --enum`](#snmp-enumeration---snmp-enum) for users/shares or [`--snmp --walk`](#snmp-walk---snmp-walk) for a full MIB walk.  
- Bulk multi-host scanning without walk remains available via `--snmp --file` (no `--brute`).

---

## SNMPv3 brute force (`--snmp --brute --v3`)

Online SNMPv3 username and password guessing against a **single host**. The scan runs in **four phases**: enumerate valid users first, then test **noAuthNoPriv**, **authNoPriv**, and **authPriv** only against those users.

Implementation: `libs/enumeration/snmp/brute_v3.go`, `v3_client.go`, `v3_usm.go` (native Go SNMPv3 USM; standard library crypto only).

### Usage

```bash
./NetDestruct --snmp --brute --v3 --userlist users.txt --passlist passwords.txt --target 192.168.1.10
```

Non-default UDP port (default **161**):

```bash
./NetDestruct --snmp --brute --v3 --userlist users.txt --passlist passwords.txt --target 10.0.0.5 --port 1161
```

Rate limit is **not** applied to SNMPv3 brute. The shared `--rate-limit` flag applies to SNMPv2c brute only.

### Flags

| Flag | Description |
|------|-------------|
| `--snmp` | Enable SNMP mode (required) |
| `--brute` | Run credential guessing (mutually exclusive with `--enum`, `--walk`, and `--file` scan mode) |
| `--v3` | Use SNMPv3 (required with `--snmp --brute --v3`; mutually exclusive with `--v2c`) |
| `--userlist <file>` | SNMPv3 username wordlist (one name per line; `#` comments skipped) |
| `--passlist <file>` | Password wordlist for auth and priv passphrases (one per line) |
| `--target <ip>` | **Single** IPv4 address or resolvable hostname |
| `--port` | Optional UDP port (default **161**) |

`--userlist`, `--passlist`, and `--v3` require `--snmp --brute`. `--v2c` and `--v3` cannot be combined. `--file`, `--community`, and `--oid` are **not** used in brute mode.

Probe timeout is **300 ms** per UDP exchange. Engine ID/boots/time are learned once up front, then a single UDP session is reused for the whole run. Localized USM keys are cached in memory.

### Phases

1. **Enumerate users** — per username: engine discovery probe, then `GetRequest` for `sysDescr.0`.
2. **noAuthNoPriv** — test each found user without a passphrase.  
3. **authNoPriv** — for each auth protocol (MD5, SHA, SHA-224, SHA-256, SHA-384, SHA-512) × each password ≥ 8 chars.  
4. **authPriv** — for each auth × priv (DES, AES, AES-192, AES-256) × auth password × priv password (both ≥ 8 chars).

### Security levels and algorithms tested

| Response | Action |
|----------|--------|
| Successful GET (sysDescr) | **Found user** (green); included in later phases |
| GetResponse `authorizationError` (errStatus **16**) | **Found user** (green); included in later phases |
| USM Report `unsupportedSecurityLevels` or `notInTimeWindow` | **Found user** (green); user exists but needs auth |
| USM Report `unknownUserNames` | Skip silently |

Each password attempt sends SNMPv3 GET `1.3.6.1.2.1.1.1.0` (sysDescr). A **noError** response with sysDescr indicates valid credentials.

### Output color

- `- Found user: …` and `- Found credentials: …` are **green** (`\x1b[32m`).  
- `[SNMP]` status, phase headers, POC lines, and sysDescr are **yellow** (`\x1b[33m`).

Example:

```text
[SNMP] Target: 192.168.1.10:161  Users: 50  Passwords: 12  Timeout: 300ms  Version: SNMPv3

[SNMP] Enumerating SNMPv3 users...
- Found user: admin [192.168.1.10]
- Found user: guest [192.168.1.10]

[SNMP] Testing authentication passphrases (authNoPriv)...

[SNMP] Testing privacy passphrases (authPriv)...
- Found credentials: user=admin level=authPriv auth=SHA priv=AES authPass=password123 privPass=password123
[SNMP]   POC: snmpwalk -v3 -u admin -A password123 -a SHA -X password123 -x AES 192.168.1.10 -l authPriv iso.3.6.1.2.1.1.1.0
[SNMP]   sysDescr: Cisco IOS Software, C2900 Software...
```

### Requirements

- UDP reachability to the target on port **161** (or `--port`)  
- SNMPv3 USM enabled on the agent  
- No root privileges required  

### Notes

- Cisco routers often ship with SNMPv3 users such as `initial` or `admin` — try lab wordlists before full cartesian brute force.
- Passwords under 8 characters are never tried for auth/priv modes; include longer candidates in `--passlist`.
- The attempt count grows quickly: per user ≈ `1 + 6×passwords + 6×4×passwords²` for authPriv (6 auth × 4 priv × password pairs).
- On success, run the printed **POC** `snmpwalk` line for deeper enumeration.
- For SNMPv2c targets, use [`--snmp --brute --v2c`](#snmp-community-brute-force---snmp-brute-v2c) instead.

---

## SNMP enumeration (`--snmp --enum`)

Comprehensive SNMP host enumeration against a **single host**. Collects system, network, routing, TCP/UDP, storage, software, and process information via SNMPv2c. On Windows targets, also enumerates domain, user accounts, network services, SMB shares, and IIS statistics when the OIDs are exposed.

Implementation: `libs/enumeration/snmp/enum.go`, `enum_helpers.go`, shared client in `client.go`.

### Usage

```bash
./NetDestruct --snmp --enum --v2c --community public --target 192.168.1.10
```

Non-default UDP port (default **161**):

```bash
./NetDestruct --snmp --enum --v2c --community private --target 10.0.0.5 --port 1161
```

### Flags

| Flag | Description |
|------|-------------|
| `--snmp` | Enable SNMP mode (required) |
| `--enum` | Run host enumeration (mutually exclusive with `--walk`, `--brute`, and `--file` scan) |
| `--v2c` | Use SNMPv2c (required with `--snmp --enum`) |
| `--community <string>` | SNMP community string (required) |
| `--target <ip>` | **Single** IPv4 address or resolvable hostname |
| `--port` | Optional UDP port (default **161**) |

`--oid` is **not** used in enum mode (use [`--snmp --walk`](#snmp-walk---snmp-walk) for custom OID walks).

### Collected sections

| Section | OIDs / source | Notes |
|---------|---------------|-------|
| System information | `sysName`, `sysDescr`, `sysContact`, `sysLocation`, `sysUpTime`, HOST-RESOURCES-MIB uptime/date | Always attempted |
| User accounts | LanManager `1.3.6.1.4.1.77.1.2.25.*` | Windows only |
| Domain | `1.3.6.1.4.1.77.1.4.1.0` | Windows only |
| Network information | IP/TCP scalar stats (`ipForwarding`, TTL, segment counters) | When available |
| Network interfaces | IF-MIB `ifTable` columns | MAC, type, speed, MTU, octets |
| Network IP | `ipAddrTable` | Address, netmask, broadcast |
| Routing information | `ipRouteTable` | Destination, next hop, mask, metric |
| TCP connections | `tcpConnTable` | Local/remote addr/port, state |
| Listening UDP ports | `udpTable` | Local addr/port |
| Network services | LanManager services | Windows only |
| Share | LanManager share table | Windows only |
| IIS server information | Microsoft IIS SNMP OIDs | Windows + IIS when exposed |
| Storage information | HOST-RESOURCES-MIB storage table | Human-readable sizes |
| File system information | HOST-RESOURCES-MIB filesystem scalars | When present |
| Device information | HOST-RESOURCES-MIB device table | Type, status, description |
| Software components | HOST-RESOURCES-MIB software table | Installed software names |
| Processes | HOST-RESOURCES-MIB process table | PID, status, name, path, parameters |

Sections with no data are omitted. Unsupported platforms still receive system and network data (useful for **Cisco IOS** and other SNMP agents).

### Output color

- `[SNMP]` is **yellow** (`\x1b[33m`); all section headers and field lines use the same tag.

Example:

```text
[SNMP] 192.168.1.10, Connected.

[SNMP] === System information ===
[SNMP]   Host IP                      : 192.168.1.10
[SNMP]   Hostname                     : router1
[SNMP]   Description                  : Cisco IOS Software, C2900 Software...
[SNMP]   Contact                      : admin@example.com
[SNMP]   Location                     : Server Room
[SNMP]   Uptime system                : 5:12:34
[SNMP]   Uptime snmp                  : -
[SNMP]   System date                  : -

[SNMP] === Network interfaces ===
[SNMP]   Interface                  : [ up ] GigabitEthernet0/0
[SNMP]   Id                         : 1
[SNMP]   Mac Address                : 00:1a:2b:3c:4d:5e
...

[SNMP] === Routing information ===
[SNMP]   Destination      Next Hop         Mask             Metric
[SNMP]   0.0.0.0          192.168.1.1      0.0.0.0          1
```

### Requirements

- UDP reachability on port **161** (or `--port`)  
- SNMPv2c community with read access to the queried MIB branches  
- No root privileges required  

### Notes

- Cisco routers/switches often expose `sysDescr`, interfaces, IP addresses, and routing via SNMP — high value even without Windows LanManager OIDs.  
- Pair with [`--snmp --brute`](#snmp-community-brute-force---snmp-brute) when the community is unknown.  
- Use [`--snmp --walk`](#snmp-walk---snmp-walk) for vendor-specific subtrees (e.g. `1.3.6.1.4.1.9` Cisco MIB) not covered by enum.

---

## SNMP walk (`--snmp --walk`)

SNMPv2c GET-NEXT walk against a **single host**. Each step sends a GET-NEXT request for the last returned OID and prints the next variable binding until the subtree is exhausted, an SNMP exception is returned, or a timeout occurs.

Implementation: `libs/enumeration/snmp/` (`walk.go`, `oid.go`, `value.go`). User/share enumeration uses `--snmp --enum`; community brute-force uses `--snmp --brute --passlist`; bulk multi-host scanning uses `--snmp --file`.

### Usage

Default walk (entire **mib-2** subtree `1.3.6.1.2.1`):

```bash
./NetDestruct --snmp --walk --v2c --community public --target 192.168.1.10
```

Walk a specific OID:

```bash
./NetDestruct --snmp --walk --v2c --community private --target 10.0.0.5 --oid 1.3.6.1.2.1.1
```

Multiple comma-separated subtrees:

```bash
./NetDestruct --snmp --walk --v2c --community public --target 192.168.1.10 --oid 1.3.6.1.2.1.1,1.3.6.1.2.1.2
```

Non-default UDP port (default **161**):

```bash
./NetDestruct --snmp --walk --v2c --community public --target 192.168.1.10 --port 1161
```

### Flags

| Flag | Description |
|------|-------------|
| `--snmp` | Enable SNMP mode (required) |
| `--walk` | Run GET-NEXT walk (mutually exclusive with `--enum` and `--brute`) |
| `--v2c` | Use SNMPv2c (required with `--snmp --walk`) |
| `--community <string>` | SNMP community string (required) |
| `--target <ip>` | Target IPv4 address or resolvable hostname |
| `--oid <oid>` | Optional walk root OID(s), comma-separated; default **1.3.6.1.2.1** (mib-2) |
| `--port` | Optional UDP port (default **161**) |

`--v2c`, `--community`, and `--oid` require `--snmp --walk`. `--file` is **not** used in walk mode.

Bulk community scan (separate mode, no `--walk`):

```bash
./NetDestruct --snmp --target 192.168.1.0/24 --file communities.txt
```

### Walk behavior

For each root OID (from `--oid` or the default):

1. Send SNMPv2c **GET-NEXT** (UDP) with the given community.  
2. Print each returned binding as `{symbolic-name} = {type}: {value}` (MIB names from standard MIBs, e.g. `system.sysDescr.0`).  
3. Advance the request OID to the last response OID and repeat.  
4. Stop when the response OID is outside the subtree (snmpwalk end-bound), when the agent returns **NoSuchObject**, **NoSuchInstance**, or **EndOfMibView**, on UDP timeout, or after **8192** steps per subtree.

Supported value types include INTEGER, STRING, OID, IpAddress, Counter32, Gauge32, Timeticks, Counter64, Opaque, and SNMPv2 exception tags.

### Symbolic OID names

Walk output uses **MIB symbolic names** instead of numeric OIDs (e.g. `system.sysDescr.0` rather than `1.3.6.1.2.1.1.1.0`). Names are loaded from the standard MIB corpus (722 OIDs in `mib_names_gen.go`, built from `tools/genmibnames`). Unrecognized suffixes remain numeric (table indices, vendor-private branches without a loaded MIB).

Regenerate after adding MIB files:

```bash
go run ./tools/genmibnames /path/to/mibs libs/enumeration/snmp/mib_names_gen.go
```

### Output color

- `[SNMP]` is **yellow** (`\x1b[33m`); OID lines and status messages use the same tag prefix.

Example:

```text
[SNMP] Target: 192.168.1.10:161  Community: public  Version: SNMPv2c
[SNMP] Walking 1 subtree(s)
[SNMP] Subtree mib-2
[SNMP] system.sysDescr.0 = STRING: "Linux router 4.19"
[SNMP] system.sysObjectID.0 = OID: enterprises.9
[SNMP] system.sysUpTime.0 = Timeticks: (123456) 0:20:34
[SNMP] system.sysContact.0 = STRING: "admin@example.com"
[SNMP] Done (42 variables)
```

### Requirements

- UDP reachability to the target on port **161** (or `--port`)  
- A valid SNMPv2c community string on the agent  
- No root privileges required  

### Notes

- Try common communities (`public`, `private`, `cisco`) with `--snmp --file` first if the community is unknown; then enumerate with `--snmp --enum` or walk with `--snmp --walk --v2c --community <found>`.  
- Start with `--oid 1.3.6.1.2.1.1` (system MIB) for quick sysDescr, sysObjectID, and uptime.  
- Cisco devices often expose useful data under `1.3.6.1.4.1.9` (ciscoMgmt); walk that subtree when you have a working community.  
- Walk output can be large; narrow `--oid` to the branch you need.

---

## SMB enumeration (`--smb --enum`)

SMB reconnaissance against a **single IPv4 host**. Combines unauthenticated SMB/NTLM discovery with MS-RPC over named pipes (SAMR, SRVSVC) when null or guest IPC$ access is allowed.

Implementation: `libs/enumeration/smb/enum.go` (CLI orchestration) and `libs/intelligence-gathering/smbvers/` (SMB2 session, DCE/RPC, SAMR/SRVSVC calls).

### Usage

```bash
./NetDestruct --smb --enum --target 192.168.109.160
```

Non-default port:

```bash
./NetDestruct --smb --enum --target 10.0.0.5 --port 445
```

Authenticated enumeration (skips null/guest probes; uses supplied credentials for RPC):

```bash
./NetDestruct --smb --enum --target 192.168.109.160 --username administrator --password 'Secret123!'
```

Domain account (`DOMAIN\user` or `DOMAIN/user`):

```bash
./NetDestruct --smb --enum --target 10.0.0.5 --username 'CORP\jsmith' --password 'Secret123!'
```

`--username` without `--password` is allowed (blank password attempt).

### Flags

| Flag | Description |
|------|-------------|
| `--smb` | Enable SMB mode (required) |
| `--enum` | Run enumeration (use with `--smb`; also used by `--cdp`, `--dtp`, etc.) |
| `--target <ip>` | **Single** IPv4 address |
| `--port` | Optional TCP port (default **445**) |
| `--username <name>` | Optional account for authenticated enum (`DOMAIN\\user`, `DOMAIN/user`, or local user) |
| `--password <pass>` | Optional password (requires `--username`) |

`--smb` requires exactly one of `--version`, `--brute`, or `--enum`.

### Modules

| Section | Source | Notes |
|---------|--------|-------|
| SMB dialect check | SMB2 negotiate | Preferred dialect, signing mode |
| Domain information | NTLM target info / session setup | NetBIOS names, DNS domain, FQDN, workgroup vs domain |
| RPC session check | Null + random-user guest probe | Reports whether IPC$/SAMR RPC is reachable |
| OS information | SMB1/SMB2 + discovery | Native OS, LAN manager, system time |
| Share enumeration | SRVSVC `NetrShareEnumAll` | Requires working RPC session |
| Password policy | SAMR `SamrQueryInformationDomain` | Min length, lockout threshold, etc. |
| User enumeration | SAMR `SamrEnumerateUsersInDomain` | `user:[name] rid:[0x…]` lines |
| Group enumeration | SAMR `SamrEnumerateGroupsInDomain` | `group:[name] rid:[0x…]` lines |
| Server info | SRVSVC `NetrServerGetInfo` (level 101) | Platform ID, OS version, server type string |

### Output color

- `[SMB]` status lines are **yellow** (`\x1b[33m`); section bodies use plain text with `=== heading ===` blocks.

Example (RPC blocked; unauthenticated data still collected):

```text
[SMB] Target: 192.168.109.160:445

=== SMB dialect check ===
[SMB] Preferred dialect: SMB 3.1.1
[SMB] SMB signing: enabled (not required)

=== Domain information (unauthenticated SMB) ===
  NetBIOS computer name:       WIN-E31P99E3C3J
  NetBIOS domain name:         WIN-E31P99E3C3J
  Derived membership:          workgroup member
  Derived domain:              WIN-E31P99E3C3J

=== RPC session check ===
[SMB] Null session: Denied
[SMB] Guest session (nx_48b3af05): Denied

=== OS information ===
  OS:                          Windows Server 2022 Standard 20348
  Native LAN manager:          Windows Server 2022 Standard 6.3
  System time:                 2026-07-22T05:25:58Z
[SMB] Skipping RPC enumeration: no RPC session available
```

When RPC succeeds (typical older Samba / misconfigured Windows), users, groups, shares, and password policy sections are populated.

### Requirements

- TCP **445** (or `--port`) reachable on the target  
- No root required  
- RPC sections need null session, guest mapping, or **valid credentials** (`--username` / `--password`) the target accepts for IPC$  

### Notes

- Run `--smb --enum` first on unknown hosts; unauthenticated sections often yield hostnames and OS hints even when RPC is denied.  
- Follow with `--smb --brute` if guest/null fails but weak passwords are likely.  
- Compare with `--smb --version` for detailed dialect/capability fingerprinting ([Intelligence Gathering](../Intelligence%20Gathering/README.md#smb-version-scan)).  
- Modern Windows defaults block anonymous SAMR; targets with `RestrictAnonymous = 0` or Samba often return full user/share lists.

---

## Telnet enumeration (`--telnet --enum`)

Telnet discovery. Prints a banner first, then encryption support and any MS-TNAP / NTLM challenge metadata.

Implementation: `libs/enumeration/telnet/` — native Go only (`net`; no third-party Telnet/NTLM libraries).

### Usage

```bash
./NetDestruct --telnet --enum --target 192.168.109.1
```

Custom port (default **23**):

```bash
./NetDestruct --telnet --enum --target 10.0.0.1 --port 2323
```

### Flags

| Flag | Description |
|------|-------------|
| `--telnet` | Enable Telnet mode (required) |
| `--enum` | Run banner + encryption + NTLM probes |
| `--target <ip>` | Target host IP or hostname |
| `--port` | TCP port (optional, default **23**) |

`--telnet` requires exactly one of `--enum` or `--brute`.

### Behavior

1. **Banner** — TCP connect, read initial data, strip Telnet IAC option bytes, print printable greeting (Cisco “User Access Verification”, login prompts, etc.)
2. **telnet-encryption** — send `IAC DO ENCRYPT` + `IAC WILL ENCRYPT` (`FF FD 26 FF FB 26`); if the server replies `WILL`/`DO` for option `0x26`, report encryption supported
3. **telnet-ntlm-info** — send MS-TNAP Auth IS / NTLM Type 1 negotiate (null credentials); if an `NTLMSSP` Type 2 challenge is returned (terminated with `IAC SE`), decode Target Name, NetBIOS/DNS names, and product version

### Example output

```
[TELNET] Target: 192.168.109.1:23
[TELNET] Banner: User Access Verification | Password:

[TELNET] Telnet Encryption:
      Telnet server does not support encryption

[TELNET] Telnet NTLM Information:
      (no NTLM challenge / MS-TNAP info)
```

Windows Telnet with NTLM may look like:

```
[TELNET] Telnet NTLM Information:
      Target_Name: ACTIVETELNET
      NetBIOS_Domain_Name: ACTIVETELNET
      NetBIOS_Computer_Name: HOST-TEST2
      DNS_Domain_Name: somedomain.com
      DNS_Computer_Name: host-test2.somedomain.com
      Product_Version: 5.1.2600
```

### Output color

- `[TELNET]` is **dark green** (`\x1b[32m`)

### Requirements

- Reachable Telnet TCP port (default 23)  
- No root required   

### Notes

- Classic Cisco IOS Telnet often shows a password/login banner and **no** encryption / NTLM — still useful for service confirmation.  
- Encryption “supported” does not mean the FreeBSD/krb5 telnetd root bug is present.  
- NTLM info is mainly relevant to Microsoft Telnet (MS-TNAP).

---

## Telnet brute force (`--telnet --brute`)

Online Telnet credential guessing. Tries each username from `--userlist` against each password from `--passlist`. On success for a user, advances to the next user (first matching password wins per user).

Implementation: `libs/enumeration/telnet/brute.go` — native Go only.

### Usage

```bash
./NetDestruct --telnet --brute --target 192.168.109.1 \
  --userlist users.txt --passlist passwords.txt
```

Custom port (default **23**):

```bash
./NetDestruct --telnet --brute --target 10.0.0.1 --port 2323 \
  --userlist users.txt --passlist passwords.txt
```

### Flags

| Flag | Description |
|------|-------------|
| `--telnet` | Enable Telnet mode (required) |
| `--brute` | Online password guessing |
| `--target <ip>` | Target host IP or hostname |
| `--userlist <file>` | Username wordlist (one per line; `#` comments skipped) |
| `--passlist <file>` | Password wordlist (one per line; `#` comments skipped) |
| `--threads <n>` | Parallel tasks (optional, default **16**, max **64**) |
| `--port` | TCP port (optional, default **23**) |

### Behavior

1. Spawn N parallel tasks (default 16, max 64); each task opens its own Telnet TCP session
2. Distribute user×password pairs across tasks from a shared queue
3. Per attempt: negotiate like a typical client (SGA / ECHO / terminal type / NAWS), wait for login or password prompt
4. Send credentials with NVT `CRLF`; detect **password-only** vs username+password
5. After password, wait up to ~35s for slow Ubuntu MOTDs; success if banner has `Welcome to` / `Last login`, a shell prompt (`$` `#` `>` `%`, including ANSI-colored prompts), or `id` returns `uid=`
6. On success for a user, skip remaining passwords for that login and print the pair in **green**

Handles “press ENTER” banners and Cisco “User Access Verification” as a username-mode cue. On hosts with slow `update-motd` scripts, prefer `--threads 1`–`4` so logins are not starved.

### Example output

```
[TELNET] Target: 192.168.109.1:23  Users: 3  Passwords: 50  Threads: 16
- Found login/password pair: cisco / cisco
[TELNET] Done: 1 found / 28 tried
```

### Example with custom task count

```bash
./NetDestruct --telnet --brute --target 192.168.109.1 \
  --userlist users.txt --passlist passwords.txt --threads 8
```

### Output color

- `[TELNET]` is **dark green** (`\x1b[32m`)
- Found credential lines are **green**

### Requirements

- Reachable Telnet TCP port (default 23)  
- No root required  

### Notes

- Prefer small lists; watch for lockouts (`too many attempts` / `% Bad passwords`).  
- For password-only servers, still provide `--userlist`; a single blank or dummy username line is fine if the device never asks for a user.  
- Success detection relies on a trailing shell prompt; exotic banners may need manual verification of hits.

---

## Memcached key get (`--memcached --enum <key>`)

Retrieve a single key/value from Memcached. Full documentation (flags, examples, color) lives under [Intelligence Gathering — Memcached Key Retrieval](../Intelligence%20Gathering/README.md#memcached-key-retrieval).

```bash
./NetDestruct --memcached --enum session_token --target 192.168.1.10
```

Implementation: `libs/enumeration/memcached/`

