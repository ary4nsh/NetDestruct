# Data Manipulation

NetDestruct data-manipulation modules change application or cache state on targets.

---

## SNMP Set (v1 / v2c)

Issue an SNMP SET request against a target, similar to `snmpset`. Use this to write OID values (for example updating `sysLocation` or other writable MIB objects).

Implementation: `libs/data-manipulation/snmp/` (uses ASN.1 helpers from `libs/enumeration/snmp/`)

### Usage

SNMPv2c with numeric OID (iso-prefixed form):

```bash
./NetDestruct --snmp --set --v2c --community private --target 192.168.109.150 \
  --oid iso.3.6.1.2.1.1.6.0 --value "Random string"
```

SNMPv1 with dotted-decimal OID and integer value:

```bash
./NetDestruct --snmp --set --v1 --community public --target 10.0.0.1 \
  --oid 1.3.6.1.2.1.1.6.0 --value 42
```

Symbolic OID (resolved from embedded MIB names):

```bash
./NetDestruct --snmp --set --v2c --community private --target 192.168.1.1 \
  --oid sysLocation.0 --value "Building A"
```

Custom UDP port:

```bash
./NetDestruct --snmp --set --v2c --community private --target 192.168.1.1 \
  --oid 1.3.6.1.2.1.1.6.0 --value "lab" --port 161
```

Multiple targets from a text file (one IP per line):

```bash
./NetDestruct --snmp --set --v2c --community private --target targets.txt \
  --oid sysLocation.0 --value "Building A"
```

File paths are auto-detected when `--target` points to an existing file. Use `@targets.txt` to force file mode. Lines may contain single IPs, CIDRs, ranges, or comma-separated entries. Empty lines and `#` comments are ignored.

```text
# targets.txt
192.168.109.150
192.168.109.151
192.168.1.10-12
```

### Flags

| Flag | Description |
|------|-------------|
| `--snmp` | Enable SNMP mode |
| `--set` | SET mode (no argument; bare `--set` activates SNMP SET when paired with `--snmp`) |
| `--v1` | Use SNMPv1 (mutually exclusive with `--v2c`) |
| `--v2c` | Use SNMPv2c (mutually exclusive with `--v1`) |
| `--community` | Community string (required, like `snmpset -c`) |
| `--target` | Target IP, hostname, CIDR, range, comma list, or text file (one address per line; `#` comments allowed). Use `@file.txt` to force file mode |
| `--oid` | Numeric OID (`1.3.6.1…`, `iso.3.6.1…`) or symbolic MIB name (`sysLocation.0`) |
| `--value` | Value to write: integer if numeric, OCTET STRING if quoted (`"..."`) or non-numeric |
| `--port` | UDP port (optional, default **161**) |

`--snmp --set` requires `--v1` or `--v2c`, plus `--community`, `--target`, `--oid`, and `--value`. It cannot be combined with `--walk`, `--enum`, or `--brute`.

### Behavior

- Builds an SNMP SET PDU (`0xa3`) and sends it over UDP
- Parses the GetResponse PDU; reports SNMP error status on failure (`noSuchName`, `notWritable`, etc.)
- Numeric `--value` is encoded as INTEGER; quoted strings and other non-integer values are encoded as OCTET STRING
- `--oid` accepts dotted-decimal OIDs, `iso`-prefixed forms (`iso.3.6.1…` ≡ `1.3.6.1…`), and symbolic names from the embedded MIB database

### Example output

```
[SNMP] Target: 192.168.109.150:161  Community: private  Version: SNMPv2c
[SNMP] SET system.sysLocation.0 = "Random string"
[+] SET successful
[SNMP] Response: system.sysLocation.0 = "Random string"
```

### Output color

- `[SNMP]` is **yellow**
- `[+]` success lines are **green**

### Requirements

- Network reachability to the target UDP port (default 161)
- A community string with write access on the target OID
- No root required

---

## Memcached Set / Delete

Write or remove keys on an exposed Memcached instance over the unauthenticated text protocol. Pair with key retrieval (`--memcached --enum <key>`) under [Intelligence Gathering](../Intelligence%20Gathering/README.md#memcached-key-retrieval).

Implementation: `libs/data-manipulation/memcached/`

### Usage — set

With separate value flag:

```bash
./NetDestruct --memcached --set session_token --value "a1b2c3d4" --target 192.168.1.10
```

Inline `key=value` form:

```bash
./NetDestruct --memcached --set value=1234abcd --target 192.168.1.10
```

Custom port:

```bash
./NetDestruct --memcached --set note --value "hello" --target 192.168.1.10 --port 11211
```

### Usage — delete

```bash
./NetDestruct --memcached --delete session_token --target 192.168.1.10
```

### Flags

| Flag | Description |
|------|-------------|
| `--memcached` | Enable Memcached mode |
| `--set <key>` | Store a key (requires `--value`, or use `--set key=value`) |
| `--value <data>` | Payload for `--set` (optional if `--set` uses `key=value`) |
| `--delete <key>` | Delete a key |
| `--target` | Target IP or hostname |
| `--port` | TCP port (optional, default **11211**) |

`--memcached` requires exactly one of `--enum [key]`, `--flush-all`, `--set`, or `--delete`.

### Behavior — set

- Issues `set <key> 0 0 <bytes>\r\n<data>\r\n` (flags=0, no expiry)
- Expects `STORED`; reports `NOT_STORED` / protocol errors on failure
- Key names cannot contain spaces or newlines

### Behavior — delete

- Issues `delete <key>\r\n`
- `DELETED` on success; `NOT_FOUND` is reported without failing the process exit for a missing key path that returns cleanly

### Example output

```
[MEMCACHED] Target: 192.168.1.10:11211  Timeout: 5s
[MEMCACHED] Setting key "session_token" (8 bytes)
[MEMCACHED] Connected to 192.168.1.10:11211
[+] STORED key "session_token" (8 bytes)
```

```
[MEMCACHED] Target: 192.168.1.10:11211  Timeout: 5s
[MEMCACHED] Deleting key "session_token"
[MEMCACHED] Connected to 192.168.1.10:11211
[+] DELETED key "session_token"
```

### Output color

- `[MEMCACHED]` is **gray**

### Requirements

- Network reachability to the target TCP port (default 11211)
- No root required
