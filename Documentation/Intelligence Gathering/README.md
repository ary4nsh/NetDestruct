# Intelligence Gathering

NetDestruct intelligence-gathering modules.

| Module | Section |
|--------|---------|
| ARP scan | [ARP scan](#arp-scan---arp-scan) |
| CDP / DTP | [CDP](#cdp-enumeration), [DTP](#dtp-enumeration) |
| DHCP | [DHCP and DHCPv6](#dhcp-and-dhcpv6-enumeration) |
| 802.1Q / 802.1X | [802.1Q](#8021q-enumeration), [802.1X](#8021x-enumeration) |
| SMB version | [SMB Version Scan](#smb-version-scan) |
| Memcached | [Recon](#memcached-reconnaissance), [Key get](#memcached-key-retrieval) |

---

## ARP scan (`--arp-scan`)

Active and passive ARP host discovery on the local segment. Uses `AF_PACKET` / `SOCK_RAW` / `ETH_P_ARP` (no pcap). Distinct from MitM `--arp --scan`.

### Usage

```bash
sudo ./NetDestruct --arp-scan --active -I eth0
sudo ./NetDestruct --arp-scan --active -I eth0 --range 192.168.1.0/24
sudo ./NetDestruct --arp-scan --passive -I eth0
```

### Flags

| Flag | Description |
|------|-------------|
| `--arp-scan` | Enable ARP host discovery (required) |
| `--active` | Send ARP who-has requests and collect replies |
| `--passive` | Sniff ARP traffic only (no injection) |
| `-I` / `--interface` | Interface to bind the raw ARP socket to (required) |
| `--range <cidr>` | Optional IPv4 CIDR for active mode; default: auto-detect from the interface |

`--arp-scan` requires exactly one of `--active` or `--passive`. `-I` is required.

### Behavior

**Active (`--active`)**

- Resolves `--range`, or derives the interface IPv4 network; fails if no IPv4 and no `--range`
- Enumerates usable hosts only (excludes network/broadcast); prefix must be **/30 or wider**; IPv4 only
- Injects one Ethernet-broadcast ARP who-has per host (1 ms gap), sniffs replies
- Dedupes by sender IP + MAC; skips own interface MAC
- After all requests: waits **2 seconds** for trailing replies, prints `Scan finished.`

**Passive (`--passive`)**

- Sniffs indefinitely; prints each new sender IP/MAC as `ARP Request` or `ARP Reply`
- Ctrl+C prints `Passive scan stopped.`

### Example output

```
[ARP] Active scan: 192.168.1.0/24 on eth0 (254 hosts). Ctrl+C to stop.
[ARP]  IP                MAC Address
[ARP]  --------------------------------------------
[ARP]  192.168.1.1       aa:bb:cc:dd:ee:ff
[ARP]  192.168.1.10      11:22:33:44:55:66
[ARP] Scan finished.
```

### Output color

- `[ARP]` is **orange**

### Requirements

- Linux with root or `CAP_NET_RAW`
- L2 adjacency on `-I`
- Active mode: interface IPv4 address, or `--range`

Implementation: `libs/intelligence-gathering/arpscan/`

---

## CDP Enumeration

Send a CDP probe frame and decode received Cisco Discovery Protocol advertisements on the local segment.

### Usage

```bash
sudo ./NetDestruct --cdp --enum -I eth0
```

With custom source MAC:

```bash
sudo ./NetDestruct --cdp --enum -I eth0 --src-mac 02:11:22:33:44:55
```

### Flags

| Flag | Description |
|------|-------------|
| `--cdp` | Enable CDP intelligence-gathering mode |
| `--enum` | Required with `--cdp` |
| `-I` / `--interface` | Interface to send/sniff CDP on |
| `--src-mac` | Optional source MAC override; defaults to interface MAC |

### Behavior

- Sends one IEEE 802.3 LLC/SNAP CDP frame to multicast `01:00:0c:cc:cc:cc`
- Sniffs incoming CDP frames on the same interface
- Prints decoded details including version, TTL, checksum status, and common TLVs:
  Device ID, Software Version, Platform, Addresses, Port ID, Capabilities, VTP domain, Native VLAN, Duplex, Trust Bitmap, Untrusted CoS, Management Addresses
- Runs until Ctrl+C

### Output color

- `[CDP]` is **blue**

### Requirements

- Linux with root or `CAP_NET_RAW`
- L2 adjacency to Cisco CDP-speaking devices

Implementation: `libs/intelligence-gathering/cdpenum/`

---

## DTP Enumeration

Send a DTP probe frame and decode received Dynamic Trunking Protocol advertisements on the local segment.

### Usage

```bash
sudo ./NetDestruct --dtp --enum -I eth0
```

With custom source MAC:

```bash
sudo ./NetDestruct --dtp --enum -I eth0 --src-mac 02:11:22:33:44:55
```

### Flags

| Flag | Description |
|------|-------------|
| `--dtp` | Enable DTP intelligence-gathering mode |
| `--enum` | Required with `--dtp` |
| `-I` / `--interface` | Interface to send/sniff DTP on |
| `--src-mac` | Optional source MAC override; defaults to interface MAC |

### Behavior

- Sends DTP frames (LLC/SNAP Cisco PID `0x2004`) to multicast `01:00:0c:cc:cc:cc`
- Sniffs incoming DTP frames on the same interface
- Prints each packet as:
  - `[DTP] Recieved DTP data from <mac>:`
  - `DTP Data`
  - parsed DTP details, followed by a blank line
- Parses common TLVs and unknown TLVs so different DTP packet forms are displayed
- Runs until Ctrl+C

### Output color

- `[DTP]` is **orange**

### Requirements

- Linux with root or `CAP_NET_RAW`
- L2 adjacency to DTP-speaking Cisco switch ports

Implementation: `libs/intelligence-gathering/dtpenum/`

---

## DHCP and DHCPv6 Enumeration

Broadcast DHCPv4 DISCOVER and multicast DHCPv6 SOLICIT probes, then decode server OFFER/ACK and Advertise/Reply responses on the local segment.

### Usage

```bash
sudo ./NetDestruct --dhcp --enum -I eth0
```

### Flags

| Flag | Description |
|------|-------------|
| `--dhcp` | Enable DHCP/DHCPv6 intelligence-gathering mode |
| `--enum` | Required with `--dhcp` |
| `-I` / `--interface` | Interface to send/sniff on |

### Behavior

- Sends a DHCPv4 DISCOVER broadcast (Ethernet source = interface MAC; DHCP `chaddr` = `de:ad:c0:de:ca:fe` to avoid exhausting the server pool)
- Sends a DHCPv6 SOLICIT to multicast `ff02::1:2` when the interface has (or can derive) an IPv6 link-local address
- Listens for DHCPv4 OFFER, ACK, and NAK on UDP destination port 68
- Listens for DHCPv6 Advertise and Reply on UDP destination port 546
- Matches responses to the current probe transaction ID
- Re-sends probes every 30 seconds
- Prints each new response as indented key/value lines (no pipe characters)
- Decodes DHCP and DHCPv6 options with option names and values (subnet mask, routers, DNS, lease time, parameter request list, IA_NA, DUID, domain search, relay agent info, vendor-specific data, and more)
- Runs until Ctrl+C

### Example output

```
[DHCP] Sent DHCPv4 DISCOVER on eth0 (xid 0x1a2b3c4d, chaddr de:ad:c0:de:ca:fe)
[DHCP6] Sent DHCPv6 SOLICIT on eth0 (trid 0x112233, src fe80::211:22ff:fe33:4455)
[DHCP] Recieved DHCPv4 data from 192.168.1.1:
  Interface: eth0
  Transaction ID: 0x1a2b3c4d
  Your IP Address (yiaddr): 192.168.1.114
  DHCP Server: 192.168.1.1
  DHCP Options:
    Option 53 (DHCP Message Type): DHCPOFFER
    Option 54 (DHCP Server Identifier): 192.168.1.1
    Option 1 (Subnet Mask): 255.255.255.0
    Option 3 (Router): 192.168.1.1
    Option 6 (Domain Name Server): 192.168.1.1
    Option 51 (IP Address Lease Time): 86400 seconds

[DHCP6] Recieved DHCPv6 data from fe80::1:
  Interface: eth0
  Message Type: Advertise
  Transaction ID: 0x112233
  Server Address: fe80::1
  DHCPv6 Options:
    Option 2 (Server Identifier): DUID-LL hw-type 1 00:11:22:33:44:55
    Option 3 (Identity Association for Non-temporary Address):
      IAID: 0x01020304
      T1: 200 seconds
      T2: 250 seconds
      IA Address: 2001:db8::100 (preferred 300, valid 300)
    Option 23 (DNS recursive name server): 2001:db8::1
```

### Output color

- `[DHCP]` and `[DHCP6]` are **purple**

### Requirements

- Linux with root or `CAP_NET_RAW`
- L2 adjacency to a DHCPv4 server or relay, and optionally DHCPv6 on the same segment
- IPv6 link-local on the interface (or derivable from the interface MAC) for DHCPv6 probing

Implementation: `libs/intelligence-gathering/dhcpenum/`

---

## 802.1Q Enumeration

Send an 802.1Q-tagged ICMP probe and print received VLAN-tagged IP packets on the local segment.

### Usage

```bash
sudo ./NetDestruct --802.1q --enum -I eth0
```

With custom source MAC:

```bash
sudo ./NetDestruct --802.1q --enum -I eth0 --src-mac 02:11:22:33:44:55
```

With custom ICMP payload:

```bash
sudo ./NetDestruct --802.1q --enum -I eth0 --payload "mamad"
```

### Flags

| Flag | Description |
|------|-------------|
| `--802.1q` | Enable 802.1Q intelligence-gathering mode (use with `--enum`; for VLAN bypass see Vlan Bypassing docs; for ARP poison MitM see Man-in-the-middle docs) |
| `--enum` | Required with `--802.1q` |
| `-I` / `--interface` | Interface to send/sniff on |
| `--src-mac` | Optional source MAC override; defaults to interface MAC |
| `--payload` | Optional ICMP echo payload string in probe; defaults to `Cisco Production` |

### Behavior

- Sends 802.1Q-tagged ICMP echo requests (VLAN 1, priority 7) to broadcast
- Default ICMP payload is `Cisco Production`; override with `--payload`
- Re-sends the probe every 30 seconds
- Sniffs incoming frames on the same interface (promiscuous mode)
- Prints each received 802.1Q packet with a colored header:
  - `[802.1Q] Recieved data from <src-mac>:` for tagged non-ICMP traffic
  - `[ICMP] Recieved 802.1Q ICMP data from <src-mac> to <dst-mac>:` for tagged ICMP/ICMPv6 traffic
- Followed by these lines:
  - `Linux cooked capture v1`
  - `802.1Q Virtual LAN, PRI: [n], DEI: [n] and ID: [n]`
  - `Internet Protocol Version [n], Src: [ip], Dst: [ip]` (when present)
- Double-tagged (QinQ) frames print one 802.1Q line per tag
- A blank line separates each packet
- Runs until Ctrl+C

### Output color

- `[802.1Q]` is **white**
- `[ICMP]` is **blue**

### Requirements

- Linux with root or `CAP_NET_RAW`
- Interface with an IPv4 address (used as ICMP source in probes)
- L2 adjacency to VLAN-tagged traffic

Implementation: `libs/intelligence-gathering/dot1qenum/`

---

## 802.1X Enumeration

Send an 802.1X EAP Identity Response probe and decode received EAPOL/EAP frames on the local segment.

### Usage

```bash
sudo ./NetDestruct --802.1x --enum -I eth0
```

With custom source MAC:

```bash
sudo ./NetDestruct --802.1x --enum -I eth0 --src-mac 02:11:22:33:44:55
```

With custom EAP Identity string:

```bash
sudo ./NetDestruct --802.1x --enum -I eth0 --eapinfo "mamad"
```

### Flags

| Flag | Description |
|------|-------------|
| `--802.1x` | Enable 802.1X intelligence-gathering mode (`--enum`) or MitM (`--mitm`; see Man-in-the-middle docs) |
| `--enum` | Required with `--802.1x` |
| `-I` / `--interface` | Interface to send/sniff on |
| `--src-mac` | Optional source MAC override; defaults to interface MAC |
| `--eapinfo` | Optional EAP Identity string in the probe; defaults to `Cisco Production` |

### Behavior

- Sends an EAP Identity Response (802.1X-2001, type EAP) to P802.1X group address `01:80:c2:00:00:03`
- Default EAP Identity payload is `Cisco Production`; override with `--eapinfo`
- Re-sends the probe every 30 seconds
- Sniffs incoming 802.1X (`0x888e`) frames on the same interface (promiscuous mode)
- Prints each packet as:
  - `[802.1X] Recieved 802.1X data from <src-mac>:`
  - Decode including Linux cooked capture, 802.1X Authentication, and EAP fields
- Decodes common EAPOL types (EAP, Start, Logoff, Key) and EAP codes/types (Request, Response, Success, Failure, Identity, Notification, NAK, MD5, TLS, LEAP, PEAP, TTLS, Expanded, and unknown types as hex)
- A blank line separates each packet
- Runs until Ctrl+C

### Output color

- `[802.1X]` is **cream**

### Requirements

- Linux with root or `CAP_NET_RAW`
- L2 adjacency to an 802.1X-enabled switch port or authenticator

Implementation: `libs/intelligence-gathering/dot1xenum/`

---

## SMB Version Scan

Fingerprint SMB servers over TCP: dialect, signing policy, server GUID, and SMB1 native OS strings when available.

### Usage

```bash
./NetDestruct --smb --version --target 192.168.1.10
```

Multiple targets:

```bash
./NetDestruct --smb --version --target 192.168.1.10,192.168.1.20
```

Last-octet range:

```bash
./NetDestruct --smb --version --target 192.168.1.100-110
```

CIDR (up to 65536 addresses):

```bash
./NetDestruct --smb --version --target 192.168.1.0/24
```

### Flags

| Flag | Description |
|------|-------------|
| `--smb` | Enable SMB intelligence-gathering mode |
| `--version` | Required with `--smb` — run SMB version scan |
| `--target` | Single IP, comma-separated list, CIDR, or IPv4 last-octet range |
| `--port` | TCP port to scan (optional, default **445**; use **139** for NetBIOS session SMB) |

### Behavior

- For each target, connects to **TCP `--port`** (default **445**)
- Sends SMB2 **NEGOTIATE** with dialects 3.1.1, 3.0.2, 3.0, 2.1, and 2.0.2
- Opens a second connection for SMB1 **NEGOTIATE** when possible to read **Native OS** and **Native LAN Manager** strings
- Adds **SMB Protocols**, **SMB2 Capabilities**, and **SMB OS Discovery** sections (dialect list, per-dialect SMB2 capability flags, OS/domain/workgroup/system time)
- Prints dialect, SMB version numbers, signing (Required / Enabled / Disabled), server GUID, and SMB1 native OS strings when available
- Reports hosts with no SMB on the chosen port as closed or filtered

### Example output

```
[SMB] Scanning 3 target(s) for SMB version...
[SMB] 192.168.1.10 no SMB service (port 445 closed or filtered)
[SMB] SMB Detected on 192.168.1.20:445:
- Versions: 1, 2, 3
- Preferred dialect: SMB 3.1.1
- Signatures: Enabled
- Host is running: Windows Server 2019 Standard 6.3
- Native OS: Windows Server 2019 Standard 9600
- Native LAN Manager: Windows Server 2019 Standard 6.3
- Server GUID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
- SMB Signing: Enabled

SMB Protocols:
- SMBv1
- 2.0.2
- 2.1
- 3.1.1

SMB2 Capabilities:
- 2.0.2:
  - DFS
- 2.1:
  - DFS
  - LEASING
  - LARGE MTU
- 3.0.2:
  - DFS
  - LEASING
  - LARGE MTU

SMB OS Discovery:
- OS: Windows Server 2022 Standard (Windows Server 2022 10.0)
- OS CPE: cpe:/o:microsoft:windows_server_2022::-
- Computer name: WINHOST
- System time: 2026-07-21 13:14:24Z
```

### Output color

- `[SMB]` is **yellow**

### Requirements

- Network reachability to the target TCP port (default 445)
- No root required (standard TCP client)

Implementation: `libs/intelligence-gathering/smbvers/`

---

## Memcached Reconnaissance

Probe an exposed Memcached instance over its unauthenticated text protocol and dump server metadata. Memcached has no authentication by default, so any reachable instance leaks its version and internal statistics.

### Usage

```bash
./NetDestruct --memcached --enum --target 192.168.1.10
```

Custom port:

```bash
./NetDestruct --memcached --enum --target 192.168.1.10 --port 11211
```

### Flags

| Flag | Description |
|------|-------------|
| `--memcached` | Enable Memcached intelligence-gathering mode |
| `--enum` | Required with `--memcached` |
| `--target` | Target IP or hostname of the Memcached server |
| `--port` | TCP port (optional, default **11211**) |

### Behavior

- Opens a single TCP connection to the target and reuses it for every command
- Issues the following text-protocol commands in order, printing each response under its own banner:
  - `version`
  - `stats`
  - `stats slabs`
  - `stats items`
  - `stats settings`
  - `stats sizes`
- Reads each response until the protocol terminator (`END`, the `VERSION` line, or an `ERROR` / `CLIENT_ERROR` / `SERVER_ERROR` reply)
- Renders `STAT key value` lines as `key: value`
- Extracts a one-line `version` / `uptime` summary from the `stats` output
- A command the server rejects (e.g. `stats sizes` when size tracking is disabled) is reported and skipped without aborting the run
- After TCP recon, runs a **UDP amplification test** (CVE-2018-1000115):
  - Builds an 8-byte Memcached UDP frame header plus `stats\r\n`
  - Sends the probe to the same host/port over **UDP**
  - Collects response datagrams that contain `\r\nSTAT `
  - Computes packet and bandwidth amplification (response larger than request ⇒ vulnerable)
  - Reports vulnerable / not vulnerable; a closed or filtered UDP port is treated as not vulnerable and does not fail the overall enum
- Default connection timeout is 5 seconds

### Example output

```
[MEMCACHED] Target: 192.168.1.10:11211  Timeout: 5s
[MEMCACHED] Running reconnaissance
[MEMCACHED] Connected to 192.168.1.10:11211

 ===================================
|    Version @ 192.168.1.10:11211    |
 ===================================
- 1.6.21

 =================================
|    Stats @ 192.168.1.10:11211    |
 =================================
- pid: 1234
- version: 1.6.21
- uptime: 90061
- curr_connections: 5
- cmd_get: 100
[+] Memcached 1.6.21 (uptime 1 days, 1 hours, 1 minutes)

 =======================================
|    Stats Settings @ 192.168.1.10:11211    |
 =======================================
- maxbytes: 67108864
- maxconns: 1024
- tcpport: 11211

 =====================================================
|    Amplification Test @ 192.168.1.10:11211/udp    |
 =====================================================
[*] Sending Memcached UDP stats probe (CVE-2018-1000115)
- Probe size: 15 bytes
- Response datagrams: 1
- Response size: 1178 bytes
[+] 192.168.1.10:11211 - Vulnerable to memcached stats amplification: No packet amplification and a 78x, 1163-byte bandwidth amplification
```

### Output color

- `[MEMCACHED]` is **gray**

### Requirements

- Network reachability to the target TCP port (default 11211)
- UDP reachability to the same port for the amplification check (optional; closed UDP is reported as not vulnerable)
- No root required (standard TCP/UDP client)

Implementation: `libs/intelligence-gathering/memcachedenum/`

---

## Memcached Key Retrieval

Fetch the value of a **known key** from an exposed Memcached instance over the unauthenticated text protocol. Use this when recon (`--memcached --enum`) or reveal interesting key names.

Implementation: `libs/enumeration/memcached/`

### Usage

```bash
./NetDestruct --memcached --enum session_token --target 192.168.1.10
```

Equivalent forms: `--enum=session_token` or `--enum "session_token"`.

Custom port:

```bash
./NetDestruct --memcached --enum "flag" --target 192.168.1.10 --port 11211
```

Bare `--enum` (no key) still runs full reconnaissance + amplification (see [Memcached Reconnaissance](#memcached-reconnaissance) above).

### Flags

| Flag | Description |
|------|-------------|
| `--memcached` | Enable Memcached mode |
| `--enum <key>` | Required — Memcached key to `get` |
| `--target` | Target IP or hostname |
| `--port` | TCP port (optional, default **11211**) |

`--memcached` requires exactly one of `--enum [key]`, `--flush-all`, `--set`, or `--delete`.

### Behavior

- Opens a TCP connection and issues `get <key>\r\n`
- On hit, prints key, flags, byte length, and the value (Go-quoted)
- On miss, reports key not found (does not treat as a hard failure)
- Key names cannot contain spaces or newlines (Memcached protocol rule)

### Example output

```
[MEMCACHED] Target: 192.168.1.10:11211  Key: session_token  Timeout: 5s
[MEMCACHED] Connected to 192.168.1.10:11211
[+] Key found
- key: session_token
- flags: 0
- bytes: 32
- value: "a1b2c3d4e5f67890a1b2c3d4e5f67890"
```

### Output color

- `[MEMCACHED]` is **gray**

### Requirements

- Network reachability to the target TCP port (default 11211)
- No root required

