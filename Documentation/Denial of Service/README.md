# Denial of Service

Layer 2, 3, and protocol-level DoS attacks.

| Module | Section |
|--------|---------|
| STP conf / TCN flood | [STP Configuration BPDU Flood](#stp-configuration-bpdu-flood-dos), [STP TCN](#stp-tcn-bpdu-flood-dos) |
| DHCP DISCOVER / RELEASE | [DHCP DISCOVER Flood](#dhcp-discover-flood-dos), [DHCP RELEASE Flood](#dhcp-release-flood-dos) |
| VTP delete / Catalyst ZD | [VTP Delete All](#vtp-delete-all-vlans-dos), [VTP Delete One](#vtp-delete-one-vlan-dos), [Catalyst Zero Day](#vtp-catalyst-zero-day-dos) |
| Memcached flush | [Memcached flush_all](#memcached-flush_all-dos) |
| Shared flood knobs | [Shared Flood Flags](#shared-flood-flags) |
| MAC / CDP / ARP cage | [MAC Flood](#mac-flood--cam-overflow-dos), [CDP Flood](#cdp-neighbor-table-flood-dos), [ARP Cage](#arp-cage-dos) |
| ICMP / TCP / UDP | [ICMP](#icmp-echo-flood-dos), [TCP](#tcp-floods-dos), [UDP](#udp-floods-dos) |
| HTTP DoS | [HTTP DoS](#http-dos) |
| EIGRP / OSPF | [EIGRP Blackhole](#eigrp-blackhole-dos), [OSPF Blackhole](#ospf-blackhole-dos) |

STP / HSRP / VRRP **hijack** (non-flood MitM) is documented under [Man-in-the-middle](../Man-in-the-middle/README.md).

---

## STP Configuration BPDU Flood (DoS)

Flood the segment with forged **STP Configuration BPDUs** carrying the **Topology Change** flag and random bridge/root IDs.

Implementation: `libs/dos/stpflood/`

### Usage

```bash
sudo ./NetDestruct --stp --flood-conf -I eth0
sudo ./NetDestruct --stp --flood-conf -I eth0 --flood-rate 500
sudo ./NetDestruct --stp --flood-conf -I eth0 --flood-count 10000 --flood-rate 200
```

### Flags

| Flag | Description |
|------|-------------|
| `--stp` | Enable STP mode |
| `--flood-conf` | Configuration BPDU flood DoS |
| `-I` / `--interface` | Interface on the STP segment |
| `--flood-rate` | Optional packets per second (default: full speed) |
| `--flood-count` | Optional number of unique source MACs to pre-generate (default: `0` = fresh random MAC per packet) |

Note: `--stp --flood-conf` and `--stp --flood-tcn` cannot be combined with each other, `--hijack`, or `--rstp`. Root hijacking remains `--stp --hijack -I --mac` (see [Man-in-the-middle](../Man-in-the-middle/README.md)).

### Behavior

1. Opens a raw L2 socket on `-I`
2. For each conf BPDU:
   - Destination MAC `01:80:C2:00:00:00` (STP multicast)
   - Random locally-administered source MAC (unique per frame or from pre-generated pool)
   - IEEE 802.3 LLC (`0x42 0x42 0x03`) + 35-byte Configuration BPDU
   - BPDU Type: Configuration (0x00), Flags: **Topology Change** (0x01)
   - Random root/bridge priorities with source MAC embedded in Root ID and Bridge ID
   - Root Path Cost: 0; Port ID: 0x8002; timers: max age 20s, hello 2s, forward delay 15s
3. Floods continuously until Ctrl+C
4. Prints live stats with yellow `[STP]` tag

Forces STP topology recalculation churn on adjacent switches, causing CPU load and potential instability on legacy Catalyst platforms.

### Output color

| Tag | Color | Meaning |
|-----|-------|---------|
| `[STP]` | Yellow | STP conf BPDU flood status |

### Example

```
$ sudo ./NetDestruct --stp --flood-conf -I eth0 --flood-rate 300
[STP] Flooding conf BPDUs on eth0 at 300 pps — press Ctrl+C to stop.
[STP] Total: 15234        Rate: 300      pps
```

### Requirements

- Linux with root or `CAP_NET_RAW`
- L2 adjacency to STP-speaking switches

---

## STP TCN BPDU Flood (DoS)

Flood the segment with forged **STP Topology Change Notification (TCN) BPDUs**.

Implementation: `libs/dos/stpflood/`

### Usage

```bash
sudo ./NetDestruct --stp --flood-tcn -I eth0
sudo ./NetDestruct --stp --flood-tcn -I eth0 --flood-rate 500
sudo ./NetDestruct --stp --flood-tcn -I eth0 --flood-count 10000 --flood-rate 200
```

### Flags

| Flag | Description |
|------|-------------|
| `--stp` | Enable STP mode |
| `--flood-tcn` | TCN BPDU flood DoS |
| `-I` / `--interface` | Interface on the STP segment |
| `--flood-rate` | Optional packets per second (default: full speed) |
| `--flood-count` | Optional number of unique source MACs to pre-generate (default: `0` = fresh random MAC per packet) |

Note: `--stp` DoS modes require exactly one of `--flood-conf` or `--flood-tcn` per run.

### Behavior

1. Opens a raw L2 socket on `-I`
2. For each TCN BPDU:
   - Destination MAC `01:80:C2:00:00:00` (STP multicast)
   - Random locally-administered source MAC (unique per frame or from pre-generated pool)
   - IEEE 802.3 LLC (`0x42 0x42 0x03`) + 4-byte TCN BPDU
   - Protocol ID: 0x0000, Version: 0, BPDU Type: **TCN** (0x80)
3. Floods continuously until Ctrl+C
4. Prints live stats with yellow `[STP]` tag

TCN BPDUs signal topology changes to the root bridge, forcing MAC table flush propagation and STP processing load across the domain.

### Output color

| Tag | Color | Meaning |
|-----|-------|---------|
| `[STP]` | Yellow | STP TCN BPDU flood status |

### Example

```
$ sudo ./NetDestruct --stp --flood-tcn -I eth0 --flood-rate 300
[STP] Flooding TCN BPDUs on eth0 at 300 pps — press Ctrl+C to stop.
[STP] Total: 15234        Rate: 300      pps
```

### Requirements

- Linux with root or `CAP_NET_RAW`
- L2 adjacency to STP-speaking switches

---

## DHCP DISCOVER Flood (DoS)

Exhaust a DHCP pool by flooding **DHCPDISCOVER** requests with random client MACs and cycling **Requested IP** (Option 50) through the target range.

Implementation: `libs/dos/dhcpflood/`

### Usage

```bash
sudo ./NetDestruct --dhcp-flood --discover -I eth0 --dhcp-pool 192.168.100.2-254
sudo ./NetDestruct --dhcp-flood --discover -I eth0 --dhcp-pool 192.168.100.2-254 --dhcp-rate 500
```

### Flags

| Flag | Description |
|------|-------------|
| `--dhcp-flood` | Enable DHCP DoS mode |
| `--discover` | DISCOVER pool exhaustion attack |
| `-I` / `--interface` | Interface on the DHCP segment |
| `--dhcp-pool` | Target IP range (`A.B.C.D-E` or `A.B.C.D-A.B.C.E`, e.g. `192.168.100.2-254`) |
| `--dhcp-rate` | Optional packets per second (default: full speed) |

### Behavior

1. Opens a raw L2 socket on `-I`
2. For each iteration:
   - Generates a random locally-administered unicast source MAC
   - Sends **DHCPDISCOVER** broadcast (`0.0.0.0` → `255.255.255.255`, UDP 68→67)
   - Sets Option 53 (Message Type) = DISCOVER and Option 50 (Requested IP) to the next address in `--dhcp-pool`
3. Cycles the pool range continuously until Ctrl+C
4. Prints live stats with purple `[DHCP]` tag

The server reserves one lease per unique DISCOVER/chaddr, starving legitimate clients.

### Output color

| Tag | Color | Meaning |
|-----|-------|---------|
| `[DHCP]` | Purple | DHCP DoS status and statistics |

---

## DHCP RELEASE Flood (DoS)

Cancel active DHCP leases by forging **DHCPRELEASE** packets for each IP in the pool.

### Usage

```bash
sudo ./NetDestruct --dhcp-flood --release -I eth0 --dhcp-pool 192.168.100.2-254
sudo ./NetDestruct --dhcp-flood --release -I eth0 --dhcp-pool 192.168.100.2-254 --dhcp-rate 100
```

### Flags

| Flag | Description |
|------|-------------|
| `--dhcp-flood` | Enable DHCP DoS mode |
| `--release` | RELEASE lease cancellation attack |
| `-I` / `--interface` | Interface on the DHCP segment (must have an IPv4 address) |
| `--dhcp-pool` | Victim IP range to release (`192.168.100.2-254`) |
| `--dhcp-rate` | Optional RELEASE attempts per second (default: full speed) |

Note: `--dhcp-flood` requires exactly one of `--discover` or `--release` per run.

### Behavior

1. Derives DHCP server IP as **x.x.x.1** from the pool subnet (e.g. `192.168.100.1` for pool `192.168.100.2-254`)
2. Sends ARP to learn the server MAC address
3. For each IP in `--dhcp-pool`:
   - Sends ARP who-has for the victim IP
   - On ARP reply, forges **DHCPRELEASE** unicast to the server:
     - Ethernet: server MAC ← victim MAC
     - IPv4: victim IP (ciaddr) → server IP
     - DHCP options: Message Type RELEASE + Server Identifier (Option 54)
4. Skips IPs with no ARP reply (no active lease on segment)
5. Cycles the pool continuously until Ctrl+C
6. Prints RELEASE count, skip count, and rate with purple `[DHCP]` tag

### Requirements

- Linux with root or `CAP_NET_RAW`
- L2 adjacency to DHCP server and leased clients
- Interface `-I` must have an IPv4 address on the target subnet (used as ARP sender)
- Active leases must respond to ARP for RELEASE to be sent

### Example

```
$ sudo ./NetDestruct --dhcp-flood --release -I eth0 --dhcp-pool 192.168.100.2-254
[DHCP] Learned DHCP server 192.168.100.1 at 0c:d4:08:34:00:01
[DHCP] Sending DHCP RELEASE for 192.168.100.2–192.168.100.254 via server 192.168.100.1 on eth0 — press Ctrl+C to stop.
[DHCP] RELEASE: 42         skipped: 18         rate: 12       pps
```

---

## VTP Delete All VLANs (DoS)

Delete all VTP VLANs on a Cisco switch domain by forging Summary and Subset advertisements with delete-all VLAN blob.

### Usage

```bash
sudo ./NetDestruct --vtp --delete-all-vlans -I eth0
sudo ./NetDestruct --vtp --delete-all-vlans -I eth0 --revision-number 50
```

### Flags

| Flag | Description |
|------|-------------|
| `--vtp` | Enable VTP mode |
| `--delete-all-vlans` | Required with `--vtp` for delete-all VLANs DoS |
| `-I` / `--interface` | Interface on the VTP segment (trunk/access with VTP traffic) |
| `--revision-number` | Optional forged Configuration Revision (default: learned revision + 1) |
| `--src-mac` | Optional source MAC override (default: MAC of `-I` interface) |

Note: `--vtp --capture` is a separate authentication-cracking mode; use exactly one of `--capture`, `--delete-all-vlans`, `--delete-vlan`, `--dos --catalyst-zero-day`, or `--add-vlan` (Vlan Tampering) per run.

### Behavior

1. Sniffs for incoming **VTP Summary** or **Subset** advertisements on the segment
2. Learns management domain, revision, and version from the observed switch
3. Computes MD5 digest (unauthenticated domain) with the delete-all blob
4. Sends forged **Summary Advertisement** (revision+1 by default, or `--revision-number`, followers=1)
5. Sends forged **Subset Advertisement** (seq=1) containing the delete-all VLAN blob
6. Continues sniffing and printing received **VTP** and **DTP** packets until Ctrl+C

---

## VTP Delete One VLAN (DoS)

Delete a single VLAN from a VTP domain by learning the current Subset advertisement, removing the target VLAN entry from the learned blob, and forging updated Summary/Subset advertisements.

### Usage

```bash
sudo ./NetDestruct --vtp --delete-vlan -I eth0 --dst-vlan 100
sudo ./NetDestruct --vtp --delete-vlan -I eth0 --dst-vlan 30 --revision-number 25
```

### Flags

| Flag | Description |
|------|-------------|
| `--vtp` | Enable VTP mode |
| `--delete-vlan` | Required with `--vtp` for single-VLAN delete DoS |
| `-I` / `--interface` | Interface on the VTP segment |
| `--dst-vlan` | Target VLAN ID to remove from the domain (1–4094) |
| `--revision-number` | Optional forged Configuration Revision (default: learned revision + 1) |
| `--src-mac` | Optional source MAC override (default: MAC of `-I` interface) |

### Behavior

1. Sniffs and prints all received **VTP** and **DTP** frames on the segment
2. On **Summary Advertisement** with zero followers, sends a **VTP Advertisement Request** to prompt the server to send Subset data
3. On **Subset Advertisement**, parses the learned VLAN information blocks
4. Removes the VLAN entry matching `--dst-vlan` from the blob (`vtp_del_vlan`)
5. Computes MD5 digest with the modified VLAN blob
6. Sends forged **Summary Advertisement** (revision+1 by default, or `--revision-number`, followers=1)
7. Sends forged **Subset Advertisement** (seq=1) with the VLAN removed
8. Continues sniffing and printing until Ctrl+C

If the target VLAN is not present in a received Subset, the tool logs the miss and keeps waiting for another Subset.

### Requirements

- Linux with root or `CAP_NET_RAW`
- L2 adjacency to a VTP-speaking Cisco switch
- Works best when the switch is already sending VTP Summary/Subset advertisements
- Target VLAN must exist in the learned Subset blob

---

## VTP Catalyst Zero Day (DoS)

Crash a vulnerable Catalyst switch by forging VTP Summary and Subset advertisements with the Catalyst crash VLAN blob.

### Usage

```bash
sudo ./NetDestruct --vtp --dos --catalyst-zero-day -I eth0
sudo ./NetDestruct --vtp --dos --catalyst-zero-day -I eth0 --revision-number 37
```

### Flags

| Flag | Description |
|------|-------------|
| `--vtp` | Enable VTP mode |
| `--dos` | Required DoS gate with `--catalyst-zero-day` |
| `--catalyst-zero-day` | Required with `--vtp --dos` for Catalyst crash DoS |
| `-I` / `--interface` | Interface on the VTP segment |
| `--revision-number` | Optional forged Configuration Revision (default: learned revision + 1) |
| `--src-mac` | Optional source MAC override (default: MAC of `-I` interface) |

### Behavior

1. Sniffs and prints all received **VTP** and **DTP** frames on the segment
2. On **Summary Advertisement** or **Subset Advertisement**, learns management domain, revision, and version
3. Computes MD5 digest (unauthenticated domain) with the `vlan_cisco` crash blob (188-byte malformed VLAN database)
4. Sends forged **Summary Advertisement** (revision+1 by default, or `--revision-number`, followers=1)
5. Sends forged **Subset Advertisement** (seq=1) containing the crash VLAN blob
6. Continues sniffing and printing until Ctrl+C; re-forges only when a higher revision is observed

The crash blob includes oversized/malformed VLAN information entries designed to trigger memory corruption on legacy Catalyst VTP implementations.

### Requirements

- Linux with root or `CAP_NET_RAW`
- L2 adjacency to a VTP-speaking Cisco switch
- Target platform must be vulnerable to the legacy VTP crash condition (older Catalyst IOS; many modern/iosv images are patched or unaffected)

### Example

```
$ sudo ./NetDestruct --vtp --dos --catalyst-zero-day -I eth0
[VTP] Waiting for VTP Summary/Subset on eth0 (Catalyst zero day)... (Ctrl+C to stop)
[VTP] Listening for VTP and DTP packets...
[VTP] Recieved data from 0c:d4:08:34:00:00:
VLAN Trunking Protocol
    Version: 1
    Code: Summary Advertisement (0x01)
    ...
[VTP] Learned domain "GNS3LAB" revision 36 — sending Catalyst zero day as 0c:7c:e8:46:ba:58
[VTP] Sent VTP Summary Advertisement (Catalyst zero day)
[VTP] Sent VTP Subset Advertisement (Catalyst crash VLAN blob)
```

Implementation: `libs/dos/vtpcrash/`

---

## VTP / DTP Output

VTP DoS modes (delete-all, delete-vlan, Catalyst zero day) print received protocol data in Wireshark-style decode.

### Output colors

| Tag | Color | Meaning |
|-----|-------|---------|
| `[VTP]` | Purple | VTP advertisements and requests |
| `[DTP]` | Orange | DTP frames on the same segment |

### Printed decode

Wireshark-style decode for every received VTP frame:

- Frame summary line with byte count and interface name
- IEEE 802.3 Ethernet and Logical-Link Control headers
- Full VTP field tree (Summary / Subset / Request / Join)
- VLAN Information blocks with nested TLVs (STP type, ring/bridge numbers, parent VLAN, etc.)
- Full DTP TLV decode when DTP is present

### Example — delete all VLANs

```
$ sudo ./NetDestruct --vtp --delete-all-vlans -I eth0
[VTP] Waiting for VTP Summary/Subset on eth0... (Ctrl+C to stop)
[VTP] Listening for VTP and DTP packets...
[VTP] Recieved data from 0c:d4:08:34:00:00:
VLAN Trunking Protocol
    Version: 1
    Code: Summary Advertisement (0x01)
    ...
[VTP] Learned domain "default" revision 5 — sending delete-all VLANs
[VTP] Sent VTP Summary Advertisement (delete-all)
[VTP] Sent VTP Subset Advertisement (delete-all VLAN blob)
```

### Example — delete one VLAN

```
$ sudo ./NetDestruct --vtp --delete-vlan -I eth0 --dst-vlan 100
[VTP] Waiting for VTP Subset on eth0 to delete VLAN 100... (Ctrl+C to stop)
[VTP] Listening for VTP and DTP packets...
[VTP] Recieved data from 0c:d4:08:34:00:00:
VLAN Trunking Protocol
    Version: 1
    Code: Summary Advertisement (0x01)
    Followers: 0
    ...
[VTP] No followers on Summary — sent VTP Advertisement Request
[VTP] Recieved data from 0c:d4:08:34:00:00:
VLAN Trunking Protocol
    Version: 1
    Code: Subset Advertisement (0x02)
    ...
[VTP] Learned domain "default" revision 5 — sending delete VLAN 100
[VTP] Sent VTP Summary Advertisement (delete VLAN 100)
[VTP] Sent VTP Subset Advertisement (VLAN 100 removed)
```

Implementation: `libs/dos/vtpdelete/` (delete-all, delete-vlan); `libs/dos/vtpcrash/` (Catalyst zero day)

---

## Memcached flush_all (DoS)

Invalidate **every** key on an exposed Memcached server with a single unauthenticated `flush_all` command. Useful when the objective is to wipe cache state or force application backend reloads.

Implementation: `libs/dos/memcached/`

### Usage

```bash
./NetDestruct --memcached --flush-all --target 192.168.1.10
```

Custom port:

```bash
./NetDestruct --memcached --flush-all --target 192.168.1.10 --port 11211
```

### Flags

| Flag | Description |
|------|-------------|
| `--memcached` | Enable Memcached mode |
| `--flush-all` | Required — send `flush_all` |
| `--target` | Target IP or hostname |
| `--port` | TCP port (optional, default **11211**) |

`--memcached` requires exactly one of `--enum [key]`, `--flush-all`, `--set`, or `--delete`.

### Behavior

1. Connects to the target over TCP
2. Sends `flush_all\r\n`
3. Expects `OK` from the server
4. All existing items are marked expired / invalidated (server-side)

Does not require root. Destructive on any writable Memcached instance.

### Example output

```
[MEMCACHED] Target: 192.168.1.10:11211  Timeout: 5s
[MEMCACHED] Sending flush_all
[MEMCACHED] Connected to 192.168.1.10:11211
[+] flush_all succeeded — all keys invalidated
```

### Output color

| Tag | Color | Meaning |
|-----|-------|---------|
| `[MEMCACHED]` | Gray | Memcached DoS status |

### Requirements

- Network reachability to the target TCP port (default 11211)
- No root required

---

## Shared Flood Flags

Common knobs used by L2/L3 flood modes. Semantics differ slightly by attack.

| Flag | Description |
|------|-------------|
| `--ip` | Target IPv4 (or hostname) for ICMP/TCP/UDP/HTTP floods. First comma-separated value is used when multiple are given. |
| `--port` | Destination port for TCP/UDP/HTTP floods (required for TCP/UDP; optional for HTTP with protocol defaults) |
| `--flood-count` | **MAC flood:** unique source MACs to pre-generate (default **20000** when `0`). **STP:** unique MAC pool (`0` = fresh random MAC per packet). **ICMP/TCP/UDP:** total packets to send (`0` = unlimited). **HTTP:** worker/connection concurrency (`0` = mode default). |
| `--flood-rate` | Packets (or HTTP ops) per second (`0` = full speed). Not used by CDP (see `--cdp-rate`) or ARP cage. |
| `--random-source` | Spoof a random IPv4 source address on every packet (ICMP/TCP/UDP floods only) |
| `-I` / `--interface` | Required for all raw-socket floods on this page (including HTTP DoS, which still passes through the interface gate) |

---

## MAC Flood / CAM Overflow (DoS)

Exhaust a switch **CAM / MAC address table** by flooding frames with thousands of distinct unicast source MACs, forcing fail-open hub-like flooding so traffic becomes visible on the attacker port.

Implementation: `libs/dos/macflood/`

### Usage

```bash
sudo ./NetDestruct --mac-flood -I eth0
sudo ./NetDestruct --mac-flood -I eth0 --flood-count 50000
sudo ./NetDestruct --mac-flood -I eth0 --flood-count 20000 --flood-rate 1000
```

### Flags

| Flag | Description |
|------|-------------|
| `--mac-flood` | Enable MAC/CAM overflow flood |
| `-I` / `--interface` | Interface facing the switch |
| `--flood-count` | Unique source MACs to pre-generate (default **20000** when unset/`0`) |
| `--flood-rate` | Optional packets per second (default: full speed) |

### Behavior

1. Opens a raw L2 (`AF_PACKET`) socket on `-I`
2. Pre-generates N frames (default 20000), each with a unique locally-administered unicast source MAC
3. Each frame is Ethernet/IPv4/**TCP RST** (66 bytes) to the broadcast MAC, with random src/dst IPs, random ephemeral ports (32768–60099), and a TCP Timestamp option
4. Cycles the pre-generated pool continuously until Ctrl+C
5. Prints live totals with white `[MAC]` tag

When the CAM table is full, the switch floods unknown unicast frames to all ports.

### Output color

| Tag | Color | Meaning |
|-----|-------|---------|
| `[MAC]` | White | MAC flood status and statistics |

### Example

```
$ sudo ./NetDestruct --mac-flood -I eth0 --flood-rate 500
[MAC] Pre-generating 20000 frames with unique unicast source MACs...
[MAC] Flooding interface eth0 at 500 pps — press Ctrl+C to stop.
[MAC] Total: 15234        Rate: 500      pps
```

### Requirements

- Linux with root or `CAP_NET_RAW`
- L2 adjacency to the target switch

---

## CDP Neighbor Table Flood (DoS)

Overflow a Cisco switch **CDP neighbor table** by flooding forged CDP advertisements, each with a unique Device ID and random source MAC.

Implementation: `libs/dos/cdpflood/`

### Usage

```bash
sudo ./NetDestruct --cdp-flood -I eth0
sudo ./NetDestruct --cdp-flood -I eth0 --cdp-rate 200
```

### Flags

| Flag | Description |
|------|-------------|
| `--cdp-flood` | Enable CDP neighbor-table overflow |
| `-I` / `--interface` | Interface on the CDP segment |
| `--cdp-rate` | Optional packets per second (default: full speed) |

Note: CDP flood uses `--cdp-rate`, not `--flood-rate`.

### Behavior

1. Opens a raw L2 socket on `-I`
2. For each frame:
   - Destination MAC `01:00:0C:CC:CC:CC` (CDP multicast)
   - Random locally-administered unicast source MAC
   - IEEE 802.3 + LLC/SNAP (`AA AA 03` / OUI `00:00:0C` / PID `0x2000`)
   - CDP v2, TTL 255, checksummed PDU
   - TLVs: random 8-char Device ID, random IPv4 Address, Port-ID `GigabitEthernet0/1`, random Capabilities, fixed Software Version / Platform strings
3. Floods continuously until Ctrl+C
4. Prints live stats with blue `[CDP]` tag

Exhausts neighbor-table capacity so the switch can no longer track legitimate CDP peers.

### Output color

| Tag | Color | Meaning |
|-----|-------|---------|
| `[CDP]` | Blue | CDP flood status and statistics |

### Example

```
$ sudo ./NetDestruct --cdp-flood -I eth0 --cdp-rate 100
[CDP] Flooding CDP neighbor table on eth0 at 100 pps — press Ctrl+C to stop.
[CDP] Total: 8421         Rate: 100      pps
```

### Requirements

- Linux with root or `CAP_NET_RAW`
- L2 adjacency to CDP-speaking Cisco gear

---

## ARP Cage (DoS)

Discover live hosts on `--subnet`, then **cage** `--target` by continuously poisoning its ARP/NDP cache: every other neighbor IP is advertised with a **random MAC**, breaking L2 reachability (isolation DoS, not classic MitM).

Implementation: `libs/dos/arp/`

### Usage

```bash
sudo ./NetDestruct --arp --cage -I eth0 --subnet 192.168.1.0/24 --target 192.168.1.50
sudo ./NetDestruct --arp --cage -I eth0 --subnet 192.168.1.0/24 --target 192.168.1.50-60
```

### Flags

| Flag | Description |
|------|-------------|
| `--arp` | Enable ARP/NDP mode |
| `--cage` | Cage DoS (mutually exclusive with `--scan` / `--poison`) |
| `-I` / `--interface` | Interface on the target segment |
| `--subnet` | CIDR to probe for live neighbors (IPv4 or IPv6 with prefix ≥ `/112`) |
| `--target` | Host(s) to cage: IP, hostname, last-octet range, or comma list (host routes only) |

Note: `--arp` requires exactly one of `--scan`, `--poison`, or `--cage` per run.

### Behavior

1. Parses `--subnet` and expands `--target` via `libs/dos/routing`
2. Probes every address in the subnet (ARP who-has for IPv4; Neighbor Solicitation for IPv6)
3. Builds a neighbor map of live IP → MAC; fails if no hosts, target missing, or only the target is alive (`no clients`)
4. For each cage target, loops over every other discovered neighbor:
   - **IPv4:** forged ARP Reply to the target MAC claiming `neighborIP is-at <random MAC>`
   - **IPv6:** forged Neighbor Advertisement for `neighborIP` with random Target Link-Layer Address
5. Sleeps **250 ms** between poison frames; continues until Ctrl+C
6. Prints orange `[ARP]` progress (`target <--> neighbor spoofed-mac`)

Unlike `--arp --poison` (MitM toward the attacker), cage deliberately maps neighbors to garbage MACs so the victim cannot talk to the LAN.

### Output color

| Tag | Color | Meaning |
|-----|-------|---------|
| `[ARP]` | Orange | Probe / cage status |

### Example

```
$ sudo ./NetDestruct --arp --cage -I eth0 --subnet 192.168.1.0/24 --target 192.168.1.50
[ARP] Probing 192.168.1.1
[ARP] 192.168.1.1 aa:bb:cc:dd:ee:01
...
[ARP] Caging 192.168.1.50 (aa:bb:cc:dd:ee:50) on eth0
[ARP] Press Ctrl+C to stop.
[ARP] 192.168.1.50 <--> 192.168.1.1 02:11:22:33:44:55
```

### Requirements

- Linux with root or `CAP_NET_RAW`
- L2 adjacency; subnet must contain at least one live neighbor besides the target
- IPv6 discovery limited to prefixes ≥ `/112` (max 4096 hosts probed)

---

## ICMP Echo Flood (DoS)

Flood a host with **ICMP Echo Request** (ping) packets via a raw IPv4 socket.

Implementation: `libs/dos/icmpflood/`

### Usage

```bash
sudo ./NetDestruct --icmp-flood -I eth0 --ip 192.168.1.10
sudo ./NetDestruct --icmp-flood -I eth0 --ip 192.168.1.10 --flood-rate 1000
sudo ./NetDestruct --icmp-flood -I eth0 --ip 192.168.1.10 --flood-count 100000 --random-source
```

### Flags

| Flag | Description |
|------|-------------|
| `--icmp-flood` | Enable ICMP Echo Request flood |
| `-I` / `--interface` | Outgoing interface (source IP taken from here unless `--random-source`) |
| `--ip` | Target IPv4 or hostname (required) |
| `--flood-count` | Total packets (`0` = unlimited) |
| `--flood-rate` | Optional packets per second (default: full speed) |
| `--random-source` | Spoof a new random source IP every packet |

### Behavior

1. Resolves `--ip` to IPv4; opens `AF_INET`/`SOCK_RAW`/`IPPROTO_RAW` toward the target
2. Builds 84-byte IPv4 + ICMP Echo Request packets (type 8, code 0, 56-byte zero payload)
3. Fixed random session identifier; incrementing sequence number
4. Source IP = first IPv4 on `-I`, or random when `--random-source` is set
5. Stops after `--flood-count` or on Ctrl+C; prints bright-blue `[ICMP]` stats

### Output color

| Tag | Color | Meaning |
|-----|-------|---------|
| `[ICMP]` | Bright blue | ICMP flood status and statistics |

### Example

```
$ sudo ./NetDestruct --icmp-flood -I eth0 --ip 192.168.1.10 --flood-rate 500
[ICMP] Flooding 192.168.1.10 with ICMP Echo Requests (fixed source) — press Ctrl+C to stop.
[ICMP] Total: 12000       Rate: 500      pps
```

### Requirements

- Linux with root or `CAP_NET_RAW`
- `-I` must have an IPv4 address unless `--random-source` is used
- IPv4 targets only

---

## TCP Floods (DoS)

Nine raw TCP flood modes sharing the same socket path and rate/count controls. Each mode differs only in TCP flags / window / sequence semantics.

Implementation: `libs/dos/tcpflood/`

### Modes

| Flag | Mode | Packet shape |
|------|------|--------------|
| `--tcp-syn-flood` | SYN | SYN, ack=0 — half-open backlog exhaustion |
| `--tcp-ack-flood` | ACK | ACK only — stateful firewall / filter stress |
| `--tcp-rst-flood` | RST | RST, ack=0 — disrupt flows |
| `--tcp-push-flood` | PSH+ACK | PSH\|ACK — processing overhead |
| `--tcp-zero-window-flood` | SYN+ZeroWindow | SYN, window=0 — hold data forever |
| `--tcp-null-flood` | NULL | No flags — confuse stateful inspection |
| `--tcp-out-of-order-flood` | OutOfOrder PSH+ACK | PSH\|ACK with random seq/ack — reassembly stress |
| `--tcp-xmas-tree-flood` | Xmas | FIN\|PSH\|URG |
| `--tcp-fin-flood` | FIN | FIN, ack=0 — half-closed state churn |

### Usage

```bash
sudo ./NetDestruct --tcp-syn-flood -I eth0 --ip 192.168.1.10 --port 80
sudo ./NetDestruct --tcp-ack-flood -I eth0 --ip 192.168.1.10 --port 443 --flood-rate 2000
sudo ./NetDestruct --tcp-rst-flood -I eth0 --ip 192.168.1.10 --port 22 --random-source
sudo ./NetDestruct --tcp-push-flood -I eth0 --ip 192.168.1.10 --port 80 --flood-count 50000
sudo ./NetDestruct --tcp-zero-window-flood -I eth0 --ip 192.168.1.10 --port 443
sudo ./NetDestruct --tcp-null-flood -I eth0 --ip 192.168.1.10 --port 80
sudo ./NetDestruct --tcp-out-of-order-flood -I eth0 --ip 192.168.1.10 --port 80
sudo ./NetDestruct --tcp-xmas-tree-flood -I eth0 --ip 192.168.1.10 --port 80
sudo ./NetDestruct --tcp-fin-flood -I eth0 --ip 192.168.1.10 --port 80
```

### Flags

| Flag | Description |
|------|-------------|
| `--tcp-*-flood` | Exactly one TCP flood mode per run |
| `-I` / `--interface` | Outgoing interface |
| `--ip` | Target IPv4 or hostname (required) |
| `--port` | Destination TCP port (required) |
| `--flood-count` | Total packets (`0` = unlimited) |
| `--flood-rate` | Optional packets per second (default: full speed) |
| `--random-source` | Spoof a random source IP per packet |

### Behavior

1. Resolves target; opens raw IPv4 socket (`IPPROTO_RAW`)
2. Each packet: 20-byte IPv4 + 20-byte TCP (no options); random ephemeral source port (32768–60999); random sequence (and usually random ack unless mode forces 0)
3. Default window **8192** except zero-window mode (`0`)
4. Source IP from `-I`, or random with `--random-source`
5. Floods until count or Ctrl+C; yellow `[TCP]` live stats

### Output color

| Tag | Color | Meaning |
|-----|-------|---------|
| `[TCP]` | Yellow | TCP flood status and statistics |

### Example

```
$ sudo ./NetDestruct --tcp-syn-flood -I eth0 --ip 192.168.1.10 --port 80 --flood-rate 1000
[TCP] Flooding 192.168.1.10:80 with TCP SYN (fixed source) — press Ctrl+C to stop.
[TCP] Total: 25000        Rate: 1000     pps
```

### Requirements

- Linux with root or `CAP_NET_RAW`
- `-I` must have IPv4 unless `--random-source`
- IPv4 targets only

---

## UDP Floods (DoS)

Four raw UDP flood variants with the same rate/count/`--random-source` controls.

Implementation: `libs/dos/udpflood/`

### Modes

| Flag | Mode | Packet shape |
|------|------|--------------|
| `--udp-normal-flood` | Normal | 16-byte random payload; correct UDP checksum |
| `--udp-zero-length-flood` | ZeroLength | 8-byte UDP header only (length=8, no payload); correct checksum |
| `--udp-random-checksum-flood` | RandomChecksum | 16-byte payload; **random (bad)** checksum |
| `--udp-zero-checksum-flood` | ZeroChecksum | 16-byte payload; checksum `0x0000` (RFC 768 disabled) |

### Usage

```bash
sudo ./NetDestruct --udp-normal-flood -I eth0 --ip 192.168.1.10 --port 53
sudo ./NetDestruct --udp-zero-length-flood -I eth0 --ip 192.168.1.10 --port 53 --flood-rate 5000
sudo ./NetDestruct --udp-random-checksum-flood -I eth0 --ip 192.168.1.10 --port 161 --random-source
sudo ./NetDestruct --udp-zero-checksum-flood -I eth0 --ip 192.168.1.10 --port 123 --flood-count 100000
```

### Flags

| Flag | Description |
|------|-------------|
| `--udp-*-flood` | Exactly one UDP flood mode per run |
| `-I` / `--interface` | Outgoing interface |
| `--ip` | Target IPv4 or hostname (required) |
| `--port` | Destination UDP port (required) |
| `--flood-count` | Total packets (`0` = unlimited) |
| `--flood-rate` | Optional packets per second (default: full speed) |
| `--random-source` | Spoof a random source IP per packet |

### Behavior

1. Resolves target; opens raw IPv4 socket
2. Builds IPv4 + UDP with random ephemeral source port; checksum rules follow the selected mode
3. Source IP from `-I`, or random with `--random-source`
4. Floods until count or Ctrl+C; magenta `[UDP]` live stats

### Output color

| Tag | Color | Meaning |
|-----|-------|---------|
| `[UDP]` | Magenta | UDP flood status and statistics |

### Example

```
$ sudo ./NetDestruct --udp-normal-flood -I eth0 --ip 192.168.1.10 --port 53 --flood-rate 2000
[UDP] Flooding 192.168.1.10:53 with UDP Normal (fixed source) — press Ctrl+C to stop.
[UDP] Total: 40000        Rate: 2000     pps
```

### Requirements

- Linux with root or `CAP_NET_RAW`
- `-I` must have IPv4 unless `--random-source`
- IPv4 targets only

---

## HTTP DoS

Application-layer HTTP denial-of-service: connection flood, Slowloris, HTTP/2 Rapid Reset, and HTTP/3 QUIC Initial flood.

Implementation: `libs/dos/httpflood/`

### Modes

| Flag | Technique | Default port | Default `--flood-count` (concurrency) |
|------|-----------|--------------|----------------------------------------|
| `--http1.0-dos` | HTTP/1.0 rapid reconnect GET flood | **80** | **64** workers |
| `--http1.1-dos` | Slowloris — partial headers, drip-feed keep-alives | **80** | **500** open connections |
| `--http2-dos` | HTTP/2 Rapid Reset (CVE-2023-44487) HEADERS+RST_STREAM over TLS | **443** | **16** workers |
| `--http3-dos` | QUIC v1 Initial packets with unique DCIDs (UDP) | **443** | **32** workers |

### Usage

```bash
sudo ./NetDestruct --http1.0-dos -I eth0 --ip 192.168.1.10
sudo ./NetDestruct --http1.1-dos -I eth0 --ip 192.168.1.10 --flood-count 1000
sudo ./NetDestruct --http2-dos -I eth0 --ip 192.168.1.10 --port 443 --flood-rate 5000
sudo ./NetDestruct --http3-dos -I eth0 --ip 192.168.1.10 --port 443
```

### Flags

| Flag | Description |
|------|-------------|
| `--http1.0-dos` / `--http1.1-dos` / `--http2-dos` / `--http3-dos` | Exactly one HTTP DoS mode |
| `-I` / `--interface` | Required by the CLI interface gate (attack uses OS TCP/UDP dial) |
| `--ip` | Target host or IP (required; used as Host / TLS SNI / :authority) |
| `--port` | Optional; defaults **80** (1.0/1.1) or **443** (2/3) |
| `--flood-count` | Worker/connection concurrency (`0` = mode default above) |
| `--flood-rate` | Global ops/s across workers (`0` = full speed). **Not applied** to Slowloris (`--http1.1-dos`) |

### Behavior

**HTTP/1.0:** each worker dials TCP, sends `GET / HTTP/1.0` with randomized User-Agent, reads until close, reconnects immediately.

**HTTP/1.1 Slowloris:** maintains up to N open sockets; sends incomplete headers (`Content-Length: 65536` without final blank line); every **10 s** drip-feeds `X-a:` keep-alive lines; refills closed sockets.

**HTTP/2:** each worker opens TLS with ALPN `h2` (`InsecureSkipVerify`), sends client preface + SETTINGS, then floods HEADERS (HPACK GET `/`) + RST_STREAM (CANCEL) on odd stream IDs.

**HTTP/3:** each worker dials UDP and sends ≥1200-byte QUIC v1 Initial packets with a new random 8-byte Destination Connection ID per packet (CRYPTO + PADDING).

Stats print every second with red `[HTTP]` tag until Ctrl+C / SIGTERM.

### Output color

| Tag | Color | Meaning |
|-----|-------|---------|
| `[HTTP]` | Red | HTTP DoS status (req/s, open conns, RST-pairs/s, or QUIC-pkts/s) |

### Example

```
$ sudo ./NetDestruct --http1.0-dos -I eth0 --ip 192.168.1.10 --port 80
[HTTP] 192.168.1.10:80       128 req/s  total=3840
```

### Requirements

- Network reachability to the target port
- `-I` required by CLI (even though dial uses the OS stack)
- HTTP/2 needs a TLS/`h2`-capable listener; HTTP/3 needs QUIC on UDP
- No raw-socket privileges strictly required for the dial path, but the binary still expects `-I` on this code path

---

## EIGRP Blackhole (DoS)

Inject forged **EIGRP external Update** routes (Candidate Default) so peers install attacker-controlled next hops and blackhole traffic for `--target` prefixes.

Implementation: `libs/dos/eigrp/`

### Usage

```bash
sudo ./NetDestruct --eigrp --blackhole -I eth0 --as 100 --src 192.168.1.99 --target 10.0.0.0/8
sudo ./NetDestruct --eigrp --blackhole -I eth0 --as 100 --src 192.168.1.99 --target 10.1.1.0/24,10.2.2.0/24
```

### Flags

| Flag | Description |
|------|-------------|
| `--eigrp` | Enable EIGRP mode |
| `--blackhole` | External-route blackhole injection |
| `-I` / `--interface` | Interface on the EIGRP segment |
| `--as` | Autonomous System number (required, non-zero) |
| `--src` | Spoofed EIGRP source / origin router IP (required) |
| `--target` | Prefix(es) to advertise: IP, CIDR, range, hostname, or comma list (required) |

Note: live `--eigrp` injection requires exactly one of `--blackhole`, `--table-overflow`, `--fake-neighbors`, or `--reset-neighbors`. `--eigrp --capture` is authentication cracking (separate).

### Behavior

1. Expands `--target` into route list via `libs/dos/routing`
2. Builds EIGRP Update (opcode 1) with IPv4 external route TLV `0x0103` (or IPv6 `0x0403`)
3. Sets Candidate Default flag (`0x02`); next-hop / origin derived from `--src`
4. Multicasts to `224.0.0.10` (L2 `01:00:5E:00:00:0A`) or `ff02::a` for IPv6
5. Retransmits each route every **10 ms** in a loop until Ctrl+C
6. Prints blue `[EIGRP]` status

### Output color

| Tag | Color | Meaning |
|-----|-------|---------|
| `[EIGRP]` | Blue | EIGRP injection status |

### Requirements

- Linux with root or `CAP_NET_RAW`
- L2 adjacency to EIGRP routers in the given AS (typically unauthenticated / MD5-absent )

---

## EIGRP Table Overflow (DoS)

Flood the peer **EIGRP topology / routing table** with a continuous stream of random external Updates.

Implementation: `libs/dos/eigrp/`

### Usage

```bash
sudo ./NetDestruct --eigrp --table-overflow -I eth0 --as 100 --src 192.168.1.99
sudo ./NetDestruct --eigrp --table-overflow -I eth0 --as 100 --src 192.168.1.99 --target 10.0.0.0/8
```

### Flags

| Flag | Description |
|------|-------------|
| `--eigrp` | Enable EIGRP mode |
| `--table-overflow` | Random external-route flood |
| `-I` / `--interface` | Interface on the EIGRP segment |
| `--as` | Autonomous System number (required) |
| `--src` | Spoofed IPv4 source / origin (required; IPv4 only) |
| `--target` | Optional pool: constrain random destinations to this CIDR/IP/range list |

### Behavior

1. Opens raw L2 socket; requires IPv4 `--src`
2. Each iteration picks a random destination:
   - Without `--target`: random IPv4 with prefix **/24**
   - With `--target`: random host/prefix from the expanded pool
3. Sends EIGRP external Update (ext flags `0`) to `224.0.0.10` at full speed until Ctrl+C
4. Prints blue `[EIGRP]` totals on stop

### Output color

| Tag | Color | Meaning |
|-----|-------|---------|
| `[EIGRP]` | Blue | EIGRP overflow status |

### Requirements

- Linux with root or `CAP_NET_RAW`
- IPv4 `--src`; L2 adjacency to EIGRP speakers

---

## EIGRP Fake Neighbors (DoS)

Flood **EIGRP Hello** packets with rotating source IPs drawn from `--target`, exhausting neighbor state / CPU on peering routers.

Implementation: `libs/dos/eigrp/`

### Usage

```bash
sudo ./NetDestruct --eigrp --fake-neighbors -I eth0 --as 100 --target 192.168.1.0/24
sudo ./NetDestruct --eigrp --fake-neighbors -I eth0 --as 100 --target 192.168.1.10-50
```

### Flags

| Flag | Description |
|------|-------------|
| `--eigrp` | Enable EIGRP mode |
| `--fake-neighbors` | Fake Hello flood |
| `-I` / `--interface` | Interface on the EIGRP segment |
| `--as` | Autonomous System number (required) |
| `--target` | Pool of source IPs/subnets for spoofed Hellos (required) |

Note: `--src` is **not** used for this mode (source IPs come from `--target`).

### Behavior

1. Expands `--target` into an address pool
2. Builds a minimal EIGRP Hello (opcode 5) for `--as`
3. Each packet picks a random source IP from the pool and multicasts Hello to `224.0.0.10` / `ff02::a` (TTL/hop limit **1**)
4. Floods at full speed until Ctrl+C
5. Prints blue `[EIGRP]` Hello count on stop

### Output color

| Tag | Color | Meaning |
|-----|-------|---------|
| `[EIGRP]` | Blue | Fake-neighbor flood status |

### Requirements

- Linux with root or `CAP_NET_RAW`
- L2 adjacency to EIGRP routers

---

## EIGRP Reset Neighbors (DoS)

Force EIGRP neighborship resets by spoofing **Hello** packets with **invalid K-values** (all 255) from `--src`.

Implementation: `libs/dos/eigrp/`

### Usage

```bash
sudo ./NetDestruct --eigrp --reset-neighbors -I eth0 --as 100 --src 192.168.1.1 --target 192.168.1.2
sudo ./NetDestruct --eigrp --reset-neighbors -I eth0 --as 100 --src 192.168.1.1 --target 192.168.1.2,192.168.1.3
```

### Flags

| Flag | Description |
|------|-------------|
| `--eigrp` | Enable EIGRP mode |
| `--reset-neighbors` | K-value mismatch reset attack |
| `-I` / `--interface` | Interface on the EIGRP segment |
| `--as` | Autonomous System number (required) |
| `--src` | Spoofed neighbor source IP (required) |
| `--target` | Peer host IP(s) for unicast Hellos (required; host routes `/32` or `/128`) |

### Behavior

1. Builds Hello with Parameter TLV (K1–K5 = 255, K6 = 0, hold time 15) and Software Version TLV (IOS 12.0 / EIGRP 1.2)
2. Every **3 seconds**:
   - Sends multicast Hello from `--src` to the EIGRP multicast group
   - Sends unicast Hello (L2 broadcast MAC) to each host `/32`/`/128` in `--target`
3. Continues until Ctrl+C; blue `[EIGRP]` reset packet count

Mismatched K-values cause Cisco peers to tear down adjacency with the spoofed neighbor identity.

### Output color

| Tag | Color | Meaning |
|-----|-------|---------|
| `[EIGRP]` | Blue | Neighbor-reset status |

### Requirements

- Linux with root or `CAP_NET_RAW`
- `--src` should match a real peer identity the targets accept as a neighbor

---

## OSPF Blackhole (DoS)

Live OSPF DoS: without `--capture`, `--ospf -I` injects forged **Type-5 AS-External LSAs** so routers install attacker-controlled external routes (blackhole / traffic diversion).

Implementation: `libs/dos/ospf/`

### Usage

```bash
sudo ./NetDestruct --ospf -I eth0 --src 192.168.1.99 --target 10.0.0.0/8
sudo ./NetDestruct --ospf -I eth0 --src 192.168.1.99 --target 10.1.1.0/24,192.168.100.0/24
```

### Flags

| Flag | Description |
|------|-------------|
| `--ospf` | Enable OSPF mode |
| `-I` / `--interface` | Interface on the OSPF segment (live blackhole path) |
| `--src` | Spoofed router-ID / advertising router IPv4 (required) |
| `--target` | IPv4 prefix(es) to inject (required; IPv6 targets rejected) |

Note: `--ospf --capture <pcap>` is authentication cracking (separate). Live DoS is **automatic** when `-I` is set — there is no `--blackhole` flag for OSPF (unlike EIGRP). Cannot combine with `--eigrp` live injection in the same run.

### Behavior

1. Expands `--target`; keeps IPv4 routes only
2. Builds OSPFv2 LS Update (type 4) for area `0.0.0.0` with null auth
3. Each LSA: Type-5 external, age 1, sequence `0x80000001`, E-bit set, metric 1, forwarding address = `--src`
4. Multicasts to `224.0.0.5` (L2 `01:00:5E:00:00:05`), IP TTL **1**
5. Retransmits each route every **10 ms** until Ctrl+C
6. Prints white `[OSPF]` status

### Output color

| Tag | Color | Meaning |
|-----|-------|---------|
| `[OSPF]` | White | OSPF LSA injection status |

### Example

```
$ sudo ./NetDestruct --ospf -I eth0 --src 192.168.1.99 --target 10.0.0.0/8
[OSPF] Injecting external LSAs on eth0 (router-id 192.168.1.99, routes 1)
[OSPF] Press Ctrl+C to stop.
```

### Requirements

- Linux with root or `CAP_NET_RAW`
- L2 adjacency to OSPF routers (typically area 0 / unauthenticated )
- IPv4 `--src` and IPv4 `--target` only

