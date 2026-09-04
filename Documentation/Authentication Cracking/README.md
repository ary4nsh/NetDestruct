# Authentication Cracking

NetDestruct authentication-cracking modules extract protocol authentication material from **pcap/pcapng** captures and optionally run an inline dictionary attack.

All modules live under `libs/authentication-cracking/`.

---

## Common workflow

Every protocol follows the same two-step pattern:

1. **Extract** — parse the capture (or SSH key file), print details, write hash lines to a `*-hashes.txt` file in the current directory
2. **Crack** (optional) — add `--crack --wordlist <file>` to run a built-in dictionary attack against extracted hashes

No network interface is required. Authentication cracking is **offline** analysis of a capture or key file.

| Flag | Description |
|------|-------------|
| `--capture <file>` | Pcap or pcapng file to analyse (required for protocol modes below) |
| `--file <path>` | Encrypted SSH private key (use with `--ssh`) |
| `--crack` | Run dictionary attack after extraction |
| `--wordlist <file>` | Wordlist for `--crack` (required when `--crack` is set) |

### Restrictions

- Choose **one protocol per run** — `--ospf`, `--hsrp`, `--eigrp`, `--vrrp`, `--glbp`, `--ntp`, `--bfd`, `--vtp`, `--rsvp`, `--is-is`, `--tacacs-plus`, and `--ssh --file` cannot be combined with each other
- `--ospf`, `--hsrp`, `--eigrp`, and `--vrrp` also support live attack modes (blackhole, hijack, injection) documented elsewhere; **only `--capture` mode** is authentication cracking
- `--vtp` also supports VLAN DoS/tampering with `-I`; **only `--vtp --capture`** is authentication cracking (see [Vlan Tampering](../Vlan%20Tampering/README.md) and [Denial of Service](../Denial%20of%20Service/README.md))
- `--ssh --file` is mutually exclusive with live `--ssh --auth-methods` / `--ssh --brute` (see [Enumeration](../Enumeration/README.md))

### Output colors

| Tag | Color | Protocol |
|-----|-------|----------|
| `[OSPF]` | White | OSPF |
| `[HSRP]` | Yellow | HSRP |
| `[EIGRP]` | Cyan | EIGRP |
| `[VRRP]` | Purple | VRRP |
| `[GLBP]` | Green | GLBP |
| `[NTP]` | Magenta | NTP |
| `[BFD]` | Green | BFD |
| `[VTP]` | Purple | VTP |
| `[RSVP]` | Yellow | RSVP |
| `[IS-IS]` | Gray | IS-IS |
| `[TACACS+]` | Gray | TACACS+ |
| `[SSH]` | Yellow | SSH private key |
---

## SSH private key (`--ssh --file`)

Extract **`$sshng$` hashes** from encrypted SSH private keys (traditional PEM RSA/DSA/EC and OpenSSH `openssh-key-v1` with bcrypt_pbkdf), then optionally dictionary-crack them.

Implementation: `libs/authentication-cracking/ssh/` — Go standard library only, plus an in-tree Blowfish implementation under `ssh/blowfish/` (no third-party modules).

This is **offline** analysis of a key file (not live SSH). For online auth-methods / password brute, see [Enumeration](../Enumeration/README.md).

### Usage

```bash
./NetDestruct --ssh --file id_rsa
./NetDestruct --ssh --file id_ed25519 --crack --wordlist rockyou.txt
```

### Flags

| Flag | Description |
|------|-------------|
| `--ssh` | Enable SSH mode (required) |
| `--file <path>` | Encrypted private key (PEM or OpenSSH) |
| `--crack` | Run dictionary attack after hash extract |
| `--wordlist <file>` | Wordlist for `--crack` |

`--ssh` offline mode is mutually exclusive with `--auth-methods` and `--brute`.

### Behavior

1. Parse `BEGIN … PRIVATE KEY` blocks (RSA, DSA, EC, OPENSSH)  
2. Skip unencrypted keys  
3. Print type, cipher, salt, rounds (OpenSSH), and the `$sshng$…` line  
4. Write hashes to `ssh-hashes.txt`  
5. With `--crack --wordlist`: try each password (PEM: EVP_BytesToKey+AES/3DES; OpenSSH: bcrypt_pbkdf + AES-256-CBC/CTR checkints)

### Example output

```
[SSH] Reading id_rsa

=== SSH Private Key #1 ===
- File:    id_rsa
- Type:    OPENSSH
- Cipher:  AES-256-CTR
- Salt:    a1b2c3d4e5f60718293a4b5c6d7e8f90
- Rounds:  16 (bcrypt_pbkdf)
- Format:  $sshng$6$
- Hash:    id_rsa:$sshng$6$16$...$16$123

=== SUMMARY ===
Encrypted keys found: 1
Hashes written to ssh-hashes.txt: 1

[SSH] Starting dictionary attack on 1 hash(es) using rockyou.txt...

[SSH] [+] CRACKED: "password"
    Hash #1 (OPENSSH / AES-256-CTR): id_rsa
```

### Manual crack

```bash
john ssh-hashes.txt --format=sshng --wordlist=rockyou.txt
```

---

## OSPF MD5 (`--ospf`)

Extract OSPFv2 packets authenticated with **MD5** (auth type 2) and produce `$netmd5$` hashes.

Implementation: `libs/authentication-cracking/ospf/`

### Usage

```bash
./NetDestruct --ospf --capture ospf.pcap
./NetDestruct --ospf --capture ospf.pcapng --crack --wordlist rockyou.txt
```

### Behavior

- Supports legacy pcap and pcapng (Ethernet, Linux cooked capture, and common link types)
- Prints OSPFv2 packet details: version, area ID, auth type, packet type, router ID, network mask, checksum status
- Extracts MD5-authenticated packets only (skips null and plain-text auth)
- Writes crackable hashes to `ospf-hashes.txt`
- Cracking: `MD5(salt || password_null_padded_to_16)` where salt is the raw OSPF packet bytes

### Manual crack

```bash
john ospf-hashes.txt --format=net-md5 --wordlist=rockyou.txt
```

---

## HSRP MD5 (`--hsrp`)

Extract **HSRP v1 and v2** hello packets with **MD5 authentication** and produce `$hsrp$` hashes.

Implementation: `libs/authentication-cracking/hsrp/`

### Usage

```bash
./NetDestruct --hsrp --capture hsrp.pcap
./NetDestruct --hsrp --capture hsrp.pcap --crack --wordlist rockyou.txt
```

### Behavior

- Decodes HSRP version, opcode, state, hellotime, holdtime, priority, group, authentication type, virtual IP
- Handles both HSRP v1 and v2 packet layouts
- Writes MD5 hashes to `hsrp-hashes.txt`

### Manual crack

```bash
john hsrp-hashes.txt --wordlist=rockyou.txt --rules
```

---

## EIGRP MD5 / HMAC-SHA-256 (`--eigrp`)

Extract **EIGRP** packets with **MD5** or **HMAC-SHA-256** authentication and produce `$eigrp$` hashes.

Implementation: `libs/authentication-cracking/eigrp/`

### Usage

```bash
./NetDestruct --eigrp --capture eigrp.pcap
./NetDestruct --eigrp --capture eigrp.pcapng --crack --wordlist rockyou.txt
```

### Behavior

- Prints EIGRP packet details: opcode, flags, sequence, AS number, authentication type
- Supports MD5 auth (algo 2) and SHA-256 HMAC auth (algo 5)
- Hash format: `$eigrp$<algo>$<salt_hex>$<have_extra>$<extra_or_x>$1$<src_ip>$<digest_hex>`
- Writes hashes to `eigrp-hashes.txt`
- MD5 crack: `MD5(salt || password_padded_to_16 || extra_salt)`
- SHA-256 crack: `HMAC-SHA256(key='\n'+password+src_ip, data=salt)[:16]`

### Manual crack

```bash
john eigrp-hashes.txt --wordlist=rockyou.txt --rules
```

---

## VRRP MD5 (`--vrrp`)

Extract **VRRPv2** packets with **MD5 authentication** (auth type 254). Uses the same format and algorithm as HSRP/GLBP.

Implementation: `libs/authentication-cracking/vrrp/`

### Usage

```bash
./NetDestruct --vrrp --capture vrrp.pcap
./NetDestruct --vrrp --capture vrrp.pcap --crack --wordlist rockyou.txt
```

### Behavior

- Prints VRRP version, type, virtual router ID, priority, auth type, advertisement interval, master address, checksum
- Salt: first 20 bytes of VRRP payload with checksum zeroed
- Digest: last 16 bytes of VRRP payload
- Writes hashes to `vrrp-hashes.txt`

### Manual crack

```bash
john vrrp-hashes.txt --wordlist=rockyou.txt --rules
```

---

## GLBP MD5 (`--glbp`)

Extract **GLBP** hello packets with MD5 authentication TLVs. Supports **MD5 string** (algo 2) and **MD5 chain** (algo 3) variants.

Implementation: `libs/authentication-cracking/glbp/`

### Usage

```bash
./NetDestruct --glbp --capture glbp.pcap
./NetDestruct --glbp --capture glbp.pcap --crack --wordlist rockyou.txt
```

### Behavior

- Decodes GLBP version, VRID, virtual forwarder states, hello/hold timers, priority, addresses
- Auth TLV algo 2 (MD5 string): 16-byte digest, 16-byte salt prefix + src IP + padding + extra TLVs
- Auth TLV algo 3 (MD5 chain): 20-byte digest, 20-byte salt prefix + src IP + padding + extra TLVs
- Writes `$hsrp$` hashes to `glbp-hashes.txt`

### Manual crack

```bash
john glbp-hashes.txt --wordlist=rockyou.txt --rules
```

---

## NTP MD5 / SHA (`--ntp`)

Extract **NTP** control/mode packets with MAC authentication. Supports MD5, SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512 digests.

Implementation: `libs/authentication-cracking/ntp/`

### Usage

```bash
./NetDestruct --ntp --capture ntp.pcap
./NetDestruct --ntp --capture ntp.pcapng --crack --wordlist rockyou.txt
```

### Behavior

- Prints NTP version, mode, stratum, poll, precision, root delay/dispersion, reference ID, timestamps
- Salt: NTP payload bytes `[0:48]` (full header through Transmit Timestamp)
- Digest length determines algorithm (`dynamic_2001` for MD5 through `dynamic_82` for SHA-512)
- Writes hashes to `ntp-hashes.txt`
- Cracking: `hash_function(password || salt)` for each algorithm

### Manual crack

```bash
john ntp-hashes.txt --wordlist=rockyou.txt --rules
```

---

## BFD Keyed-MD5 / Keyed-SHA1 (`--bfd`)

Extract **BFD** session packets with keyed authentication (RFC 5880 types 2–5).

Implementation: `libs/authentication-cracking/bfd/`

### Usage

```bash
./NetDestruct --bfd --capture bfd.pcap
./NetDestruct --bfd --capture bfd.pcap --crack --wordlist rockyou.txt
```

### Behavior

- Prints BFD version, diagnostic, state, flags, detect multiplier, length, my/your discriminator, auth type
- Supported auth types:
  - Type 2 — Keyed MD5 → `$netmd5$`
  - Type 3 — Meticulous Keyed MD5 → `$netmd5$`
  - Type 4 — Keyed SHA1 → `$netsha1$`
  - Type 5 — Meticulous Keyed SHA1 → `$netsha1$`
- Salt: BFD payload `[0:32]`; digest: last 16 bytes (MD5) or last 20 bytes (SHA1)
- Writes hashes to `bfd-hashes.txt`

### Manual crack

```bash
john bfd-hashes.txt --wordlist=rockyou.txt --rules
```

---

## VTP MD5 (`--vtp --capture`)

Extract **VTP** password-protected domain hashes. Requires **cross-packet matching**: a Summary Advertisement (MD5 digest) paired with a Subset Advertisement (VLAN data) sharing the same revision number.

Implementation: `libs/authentication-cracking/vtp/`

### Usage

```bash
./NetDestruct --vtp --capture vtp.pcap
./NetDestruct --vtp --capture vtp.pcapng --crack --wordlist rockyou.txt
```

### Behavior

- Parses VTP Summary, Subset, Request, and Join advertisements with full VLAN TLV decode
- Matches Summary + Subset pairs by revision; no crackable hash without both in the capture
- Hash format: `$vtp$<version>$<vlans_len>$<vlans_hex>$<salt_len>$<salt_hex>$<hash_hex>`
- Writes hashes to `vtp-hashes.txt`
- Cracking: derives 16-byte secret from password via cyclic MD5 expansion, then `MD5(secret ‖ normalised_summary ‖ vlans_data ‖ secret)`

### Manual crack

```bash
john vtp-hashes.txt --wordlist=rockyou.txt --rules
```

---

## RSVP HMAC (`--rsvp`)

Extract **RSVP** INTEGRITY object authentication (RFC 2747) from IP protocol 46 packets.

Implementation: `libs/authentication-cracking/rsvp/`

### Usage

```bash
./NetDestruct --rsvp --capture rsvp.pcap
./NetDestruct --rsvp --capture rsvp.pcap --crack --wordlist rockyou.txt
```

### Behavior

- Decodes RSVP common header and walks typed objects (SESSION, RSVP_HOP, INTEGRITY, etc.)
- INTEGRITY object (class 4, C-Type 1): extracts key ID, sequence number, keyed digest
- Salt: full RSVP payload with digest bytes zeroed
- Supports HMAC-MD5, HMAC-SHA1, and extended SHA variants in hash files
- Hash format: `$rsvp$<algo>$<salt_hex>$<hash_hex>`
- Writes hashes to `rsvp-hashes.txt`

### Manual crack

```bash
john rsvp-hashes.txt --wordlist=rockyou.txt --rules
```

---

## IS-IS HMAC (`--is-is`)

Extract **IS-IS** Authentication TLV (type 0x0A) hashes from 802.3 Ethernet frames (LLC `0xFE/0xFE/0x03`, discriminator `0x83`). Supports dot1q-tagged frames.

Implementation: `libs/authentication-cracking/isis/`

### Usage

```bash
./NetDestruct --is-is --capture isis.pcap
./NetDestruct --is-is --capture isis.pcapng --crack --wordlist rockyou.txt
```

### Behavior

- Handles all PDU types: P2P/LAN Hello, LSP, CSNP, PSNP (L1 and L2)
- Authentication TLV variants:
  - **HMAC-MD5** (RFC 5304, auth type 0x36) — hash zeroed in salt, `$rsvp$1$` format
  - **HMAC-SHA1** (RFC 5310) — hash removed from salt, `$ospf$1$` format
  - **HMAC-SHA256** (RFC 5310) — hash removed from salt, `$ospf$2$` format
- For LSP PDUs, Remaining Lifetime and Checksum fields are zeroed per RFC 5304 before salt computation
- Writes hashes to `isis-hashes.txt`

### Manual crack

```bash
john isis-hashes.txt --wordlist=rockyou.txt --rules
```

---

## TACACS+ (`--tacacs-plus`)

Extract and decrypt **TACACS+** (TCP port 49) authentication sessions from a capture. Cracks the shared secret by validating decrypted AUTHEN_REPLY packets.

Implementation: `libs/authentication-cracking/tacacs/`

### Usage

```bash
./NetDestruct --tacacs-plus --capture tacacs.pcap
./NetDestruct --tacacs-plus --capture tacacs.pcapng --crack --wordlist rockyou.txt
```

### Behavior

- Reassembles TACACS+ sessions by session ID across TCP streams
- Prints packet type (AUTHEN, AUTHOR, ACCT), sequence, flags, body length, authentication method
- Decryption pad: `MD5(session_id ‖ secret ‖ version ‖ seq_no)` chained per RFC 8907
- Writes hashes to `tacacs-plus-hashes.txt`: `$tacacs-plus$0$<session_id_hex>$<ciphertext_hex>$<version_hex><seq_no_hex>`
- `--crack` tries each wordlist candidate as the shared secret; a valid decrypt has status in `[0x01..0x07] ∪ {0x21}` with consistent body lengths

### Manual crack

```bash
john tacacs-plus-hashes.txt --wordlist=rockyou.txt
```

---

## Module summary

| Protocol | Flag | Hash file | Auth types |
|----------|------|-----------|------------|
| OSPF | `--ospf` | `ospf-hashes.txt` | MD5 |
| HSRP | `--hsrp` | `hsrp-hashes.txt` | MD5 (v1/v2) |
| EIGRP | `--eigrp` | `eigrp-hashes.txt` | MD5, HMAC-SHA-256 |
| VRRP | `--vrrp` | `vrrp-hashes.txt` | MD5 |
| GLBP | `--glbp` | `glbp-hashes.txt` | MD5 string/chain |
| NTP | `--ntp` | `ntp-hashes.txt` | MD5, SHA-1/224/256/384/512 |
| BFD | `--bfd` | `bfd-hashes.txt` | Keyed MD5/SHA1 |
| VTP | `--vtp --capture` | `vtp-hashes.txt` | MD5 (password domain) |
| RSVP | `--rsvp` | `rsvp-hashes.txt` | HMAC-MD5/SHA* |
| IS-IS | `--is-is` | `isis-hashes.txt` | HMAC-MD5/SHA1/SHA256 |
| TACACS+ | `--tacacs-plus` | `tacacs-plus-hashes.txt` | XOR pad (MD5-derived) |
| SSH | `--ssh --file` | `ssh-hashes.txt` | `$sshng$` (PEM / OpenSSH) |

---

## Requirements

- A capture file containing authenticated protocol traffic (pcap or pcapng), **or** an encrypted SSH private key (`--ssh --file`)
- For `--crack`: a wordlist file with candidate passwords/secrets
- No root privileges required (offline file analysis)

Hash extraction output is compatible with [John the Ripper jumbo](https://github.com/openwall/john) for external cracking when `--crack` is not used.

---

## Related modules

| Module | Documentation | Purpose |
|--------|---------------|---------|
| Cisco enable secrets | [Cisco Passwords](../Cisco%20Passwords/README.md) | Offline crack Type 4/5/7/8/9 hashes from config or `--hash` |
| SSH online enum/brute | [Enumeration](../Enumeration/README.md) | Live `--ssh --auth-methods` / `--ssh --brute` |
| VTP live attacks | [Denial of Service](../Denial%20of%20Service/README.md), [Vlan Tampering](../Vlan%20Tampering/README.md) | VLAN delete/add/crash (not hash extraction) |
| FHRP hijacking | [Man-in-the-middle](../Man-in-the-middle/README.md) | Live HSRP/VRRP takeover (not hash extraction) |
