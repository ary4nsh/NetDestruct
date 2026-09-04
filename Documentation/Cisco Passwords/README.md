# Cisco Passwords

NetDestruct Cisco password modules crack or decrypt **enable secrets** and **username secrets** from Cisco IOS configuration files or direct hash values.

Implementation: `libs/cisco-passwords/`

---

## Common workflow

All modes are **offline** — no network interface or root privileges required.

1. Enable Cisco password mode with `--cisco-pass`
2. Choose exactly **one** hash type: `--type4`, `--type5`, `--type7`, `--type8`, or `--type9`
3. Provide input via **either**:
   - `--file <config>` — scan a Cisco running-config or startup-config for matching hashes/passwords
   - `--hash <value>` — crack or decrypt a single hash directly
4. For dictionary types (`--type4`, `--type5`, `--type8`, `--type9`): add `--wordlist <file>`

| Flag | Description |
|------|-------------|
| `--cisco-pass` | Enable Cisco password cracking/decryption mode |
| `--file <path>` | Cisco config file to scan for hashes (cannot combine with `--hash`) |
| `--hash <value>` | Single hash or Type 7 ciphertext to process directly |
| `--wordlist <file>` | Dictionary for Type 4, 5, 8, and 9 (not used for Type 7) |
| `--type4` | Cisco Type 4 — raw SHA (enable secret 4) |
| `--type5` | Cisco Type 5 — md5crypt (enable secret 5) |
| `--type7` | Cisco Type 7 — XOR cipher decrypt (enable password/secret 7) |
| `--type8` | Cisco Type 8 — PBKDF2 (enable secret 8) |
| `--type9` | Cisco Type 9 — scrypt (enable secret 9) |

### Restrictions

- `--file` and `--hash` cannot be combined
- `--cisco-pass` requires `--file` or `--hash`
- Exactly one `--typeN` flag per run
- `--type4`, `--type5`, `--type8`, and `--type9` require `--wordlist`
- `--type7` does **not** require a wordlist (instant XOR decryption)
- `--file` is also used by SNMP enumeration (`--snmp`); use `--cisco-pass` to select config-file mode here

### Output

- Found hashes/passwords are listed with context (`enable secret`, `username <name>`, etc.)
- Successful cracks and decryptions print in **green**
- Dictionary modes report progress every 100,000 candidates (Type 9: every 100 — scrypt is slow)
- Final summary: passwords tried, cracked count

---

## Type 4 — Raw SHA (`--type4`)

Cisco **Type 4** (`enable secret 4`) stores a single-pass SHA digest of the password encoded in **crypt base64** (`./0-9A-Za-z`, MSB-first). No salt.

### Usage

```bash
./NetDestruct --cisco-pass --type4 --file running-config.txt --wordlist rockyou.txt
./NetDestruct --cisco-pass --type4 --hash "JAHhGd0I9qKKOCUccpoYpyPwP4Iqv2q0F9IEAbU3bMUk" --wordlist rockyou.txt
```

### Config patterns

- `enable secret 4 <hash>`
- `username <name> secret 4 <hash>`
- Optional privilege level between `secret` and `4`

### Hash variants (auto-detected by encoded length)

| Encoded length | Algorithm |
|----------------|-----------|
| 27 chars | SHA-1 |
| 38 chars | SHA-224 |
| 43 chars | SHA-256 or SHA3-256 (both tried) |
| 64 chars | SHA-384 |
| 86 chars | SHA-512 |

### Behavior

- Parses all matching Type 4 lines from config, or validates a direct `--hash`
- Displays detected SHA variant per hash
- Dictionary attack: `crypt_base64(SHA(password)) == stored_hash`
- SHA3-256 uses an embedded Keccak-f[1600] implementation when SHA-256 does not match

---

## Type 5 — md5crypt (`--type5`)

Cisco **Type 5** (`enable secret 5`) uses Unix-style **md5crypt** (`$1$salt$hash`) — 1000 MD5 rounds with Cisco/FreeBSD-compatible salting.

### Usage

```bash
./NetDestruct --cisco-pass --type5 --file running-config.txt --wordlist rockyou.txt
./NetDestruct --cisco-pass --type5 --hash '$1$salt$hash' --wordlist rockyou.txt
```

### Config patterns

- `enable secret 5 $1$...`
- `username <name> secret 5 $1$...`

### Behavior

- Extracts `$1$salt$hash` from config lines or validates direct `--hash`
- Displays salt per hash
- Dictionary attack using full md5crypt algorithm (FreeBSD-compatible)
- Hash format: `$1$<salt>$<22-char-crypt-base64-digest>`

---

## Type 7 — XOR cipher (`--type7`)

Cisco **Type 7** is a **reversible XOR cipher**, not a one-way hash. No wordlist is needed — decryption is immediate.

Used for `enable password 7`, `enable secret 7`, `username password 7`, line passwords, SNMP passwords, and similar config lines.

### Usage

```bash
./NetDestruct --cisco-pass --type7 --file running-config.txt
./NetDestruct --cisco-pass --type7 --hash 104D000A0618
```

### Config patterns

Broad match on any line containing `password 7` or `secret 7` followed by hex:

- `enable password 7 <hex>`
- `enable secret 7 <hex>`
- `username <name> password 7 <hex>`
- `line vty 0 4` / `password 7 <hex>`
- `snmp-server community ... password 7 <hex>`
- Other `password 7` / `secret 7` variants

### Ciphertext format

- First **2 decimal digits** = starting index into the 53-byte XOR key table (0–50)
- Remaining bytes = hex-encoded ciphertext
- Key index wraps at 51 back to 0

### Behavior

- Scans config for all Type 7 entries and decrypts each in place
- Direct `--hash` decrypts a single ciphertext
- Reports context: `enable secret`, `enable password`, `username <name>`, or generic `password`
- No brute force — decryption only

---

## Type 8 — PBKDF2 (`--type8`)

Cisco **Type 8** (`enable secret 8`) uses **PBKDF2-HMAC** with per-hash salt. Standard Cisco `$8$` hashes use SHA-256.

### Usage

```bash
./NetDestruct --cisco-pass --type8 --file running-config.txt --wordlist rockyou.txt
./NetDestruct --cisco-pass --type8 --hash '$8$salt$encoded' --wordlist rockyou.txt
```

### Config patterns

- `enable secret 8 $8$...`
- `username <name> secret 8 $8$...`

### Hash format

`$8$<salt>$<crypt-base64-hash>`

### PBKDF2 parameters

- **20,000 iterations**
- SHA variant auto-detected from encoded hash length:

| Encoded length | PBKDF2 PRF |
|----------------|------------|
| 27 chars | HMAC-SHA1 (20-byte output) |
| 43 chars | HMAC-SHA256 (32-byte output) — standard Cisco |
| 86 chars | HMAC-SHA512 (64-byte output) |

### Behavior

- Extracts salt and encoded digest from config or `--hash`
- Dictionary attack: `crypt_base64(PBKDF2(password, salt, 20000)) == stored_hash`

---

## Type 9 — scrypt (`--type9`)

Cisco **Type 9** (`enable secret 9`) uses **scrypt** (RFC 7914) with fixed parameters designed to resist GPU cracking.

### Usage

```bash
./NetDestruct --cisco-pass --type9 --file running-config.txt --wordlist rockyou.txt
./NetDestruct --cisco-pass --type9 --hash '$9$salt$encoded' --wordlist rockyou.txt
```

### Config patterns

- `enable secret 9 $9$...`
- `username <name> secret 9 $9$...`

### Hash format

`$9$<salt>$<43-char-crypt-base64-hash>`

### scrypt parameters

- **N = 16384**, **r = 1**, **p = 1**
- Output key length: **32 bytes**
- ~2 MB RAM and ~65K Salsa20/8 rounds per candidate (slow by design)

### Behavior

- Full RFC 7914 scrypt: PBKDF2-SHA256 → ROMix (Salsa20/8 BlockMix) → PBKDF2-SHA256
- Progress reported every 100 passwords (scrypt is computationally expensive)
- Dictionary attack: `crypt_base64(scrypt(password, salt)) == stored_hash`

---

## Module summary

| Type | Flag | Wordlist | Input | Algorithm | IOS command |
|------|------|----------|-------|-----------|-------------|
| 4 | `--type4` | Required | Config or hash | SHA-1/224/256/3-256/384/512 + crypt base64 | `enable secret 4` |
| 5 | `--type5` | Required | Config or hash | md5crypt `$1$` (1000 rounds) | `enable secret 5` |
| 7 | `--type7` | Not used | Config or hash | XOR cipher (reversible) | `password 7` / `secret 7` |
| 8 | `--type8` | Required | Config or hash | PBKDF2-HMAC (20,000 iter) | `enable secret 8` |
| 9 | `--type9` | Required | Config or hash | scrypt N=16384 r=1 p=1 | `enable secret 9` |

---

## Examples

### Crack all Type 5 secrets in a config

```bash
./NetDestruct --cisco-pass --type5 --file router.cfg --wordlist rockyou.txt
```

Example output:

```
Found 2 Type 5 hash(es):

=== Type 5 Hash #1 ===
- Context: enable secret
- Hash:    $1$mERr$hx5erVt.GGMzlSo/poE3f0
- Salt:    mERr

Cracking with: rockyou.txt

[+] Hash #1 (enable secret) cracked: "cisco123"

Tried: 15234  Cracked: 1/2
```

### Decrypt Type 7 passwords from config

```bash
./NetDestruct --cisco-pass --type7 --file router.cfg
```

### Crack a single Type 9 hash

```bash
./NetDestruct --cisco-pass --type9 \
  --hash '$9$6JwdRJKG$VAu6Lj7jlZ2Do7OQIWXX/SpqPhPoSYyyp4fF.prRF6g' \
  --wordlist rockyou.txt
```

---

## Requirements

- A Cisco IOS configuration file (`show running-config` output) or a known hash value
- Wordlist file for Type 4, 5, 8, and 9 dictionary attacks
- No network access or elevated privileges required

---

## Related modules

| Module | Documentation | Purpose |
|--------|---------------|---------|
| Protocol hash extraction | [Authentication Cracking](../Authentication%20Cracking/README.md) | Extract MD5/HMAC hashes from pcap captures (OSPF, HSRP, VTP, etc.) |
| SNMP community scan | [Intelligence Gathering](../Intelligence%20Gathering/README.md) | Uses `--file` as community wordlist with `--snmp` (separate from `--cisco-pass`) |
