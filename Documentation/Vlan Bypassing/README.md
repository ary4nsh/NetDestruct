# Vlan Bypassing

NetDestruct VLAN bypassing modules forge Layer-2 control-plane or tagged frames to escape or traverse VLAN boundaries on misconfigured Cisco switches.

| Module | Section |
|--------|---------|
| CDP virtual device | [CDP Injection](#cdp-injection-virtual-device-setup) |
| DTP enable trunk | [DTP Enable Trunk](#dtp-enable-trunk-non-dos) |
| 802.1Q double-tag | [802.1Q Double-Tag VLAN Bypass](#8021q-double-tag-vlan-bypass) |

## CDP Injection (Virtual Device Setup)

Inject crafted CDP advertisements ("Setting up a virtual device") to introduce a fake neighboring Cisco device on the local segment.

### Usage

```bash
sudo ./NetDestruct --cdp --inject -I eth0
```

With custom source MAC:

```bash
sudo ./NetDestruct --cdp --inject -I eth0 --src-mac 02:11:22:33:44:55
```

### Flags

| Flag | Description |
|------|-------------|
| `--cdp` | Enable CDP mode |
| `--inject` | CDP injection mode (virtual device setup) |
| `-I` / `--interface` | Interface to send CDP injection frames on |
| `--src-mac` | Optional source MAC override; default is interface MAC |

### Behavior

- Sends forged CDP frames to multicast `01:00:0c:cc:cc:cc`
- Uses LLC/SNAP CDP encapsulation with version 2 and TTL 180
- Injects Device ID, Software Version, Platform, Port ID, Capabilities, Native VLAN, Duplex, Trust Bitmap, and Management Address TLVs
- Repeats every 2 seconds until Ctrl+C

### Output color

- `[CDP]` is **blue**

### Requirements

- Linux with root or `CAP_NET_RAW`
- L2 adjacency to the target switch domain

Implementation: `libs/vlan-bypassing/cdpinject/`

---

## DTP Enable Trunk (Non-DoS)

Send DTP frames aimed at enabling trunking on a dynamic switchport.

### Usage

```bash
sudo ./NetDestruct --dtp --enable-trunk -I eth0
```

With custom source MAC:

```bash
sudo ./NetDestruct --dtp --enable-trunk -I eth0 --src-mac 02:11:22:33:44:55
```

### Flags

| Flag | Description |
|------|-------------|
| `--dtp` | Enable DTP mode |
| `--enable-trunk` | Required for trunk-enabling attack |
| `-I` / `--interface` | Interface to send/sniff DTP on |
| `--src-mac` | Optional source MAC override; default is interface MAC |

### Behavior

- Sends DTP trunk-negotiation frames every 2 seconds
- Uses DTP status/type values that request trunk establishment
- Prints received DTP packets in decoded format:
  - `[DTP] Recieved DTP data from <mac>:`
  - `DTP Data`
  - parsed content, then a blank line

### Output color

- `[DTP]` is **orange**

### Requirements

- Linux with root or `CAP_NET_RAW`
- Switchport configured to negotiate DTP (dynamic desirable/auto scenarios)

Implementation: `libs/vlan-bypassing/dtpinject/`

---

## 802.1Q Double-Tag VLAN Bypass

Send 802.1Q double-tagged (QinQ) ICMP echo probes to hop between VLANs on misconfigured Cisco switches.

### Usage

```bash
sudo ./NetDestruct --802.1q --double-tag -I eth0 --src-vlan 1 --dst-vlan 2
```

With custom source MAC and ICMP payload:

```bash
sudo ./NetDestruct --802.1q --double-tag -I eth0 --src-vlan 1 --dst-vlan 2 --src-mac 02:11:22:33:44:55 --payload "mamad"
```

### Flags

| Flag | Description |
|------|-------------|
| `--802.1q` | Enable 802.1Q mode |
| `--double-tag` | Required with `--802.1q` for VLAN bypass |
| `-I` / `--interface` | Interface to send/sniff on |
| `--src-vlan` | Outer (native/trunk) VLAN ID (0–4095) |
| `--dst-vlan` | Inner (target) VLAN ID (0–4095) |
| `--src-mac` | Optional source MAC override; default is interface MAC |
| `--payload` | Optional ICMP echo payload string; defaults to `Cisco Production` |

### Behavior

- Builds a double-encapsulated frame: `[Ethernet][outer 802.1Q: src-vlan][inner 802.1Q: dst-vlan][IPv4][ICMP echo]`
- Outer and inner tags use priority 7
- Destination MAC is broadcast; destination IP is `255.255.255.255`
- Sends the probe on start and re-sends every 30 seconds
- Sniffs incoming frames in promiscuous mode with `PACKET_AUXDATA` for stripped VLAN tags
- Prints each received 802.1Q-tagged packet decode:
  - `[802.1Q] Recieved data from <src-mac>:` for tagged non-ICMP traffic
  - `[ICMP] Recieved 802.1Q ICMP data from <src-mac> to <dst-mac>:` for tagged ICMP
  - VLAN lines: `802.1Q Virtual LAN, PRI: [n], DEI: [n] and ID: [n]` (supports QinQ / multiple tags)
  - IPv4/IPv6, ICMP/ICMPv6, ARP, and LLC/SNAP (CDP/VTP/DTP/EAPOL) layers when present

### Output color

- `[802.1Q]` is **white**
- `[ICMP]` is **blue**

### Requirements

- Linux with root or `CAP_NET_RAW`
- Switch with native VLAN mismatch or double-tagging bypass scenario

Implementation: `libs/vlan-bypassing/dot1qdouble/`

