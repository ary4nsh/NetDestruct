# NetDestruct

Network reconnaissance and attack toolkit.

NetDestruct covers Layer-2/3 protocol abuse, service enumeration, offline hash cracking, MitM, and DoS. Most L2 modules need Linux with root (or `CAP_NET_RAW`). Many TCP/UDP service modules work without root.

<p align="center">
  <img src="NetDestruct-Logo.png" alt="NetDestruct" width="420"/>
</p>

---

## Build

```bash
go build -o NetDestruct .
```

Requires **Go 1.25+**. Standard library only (no third-party modules).

```bash
./NetDestruct -h
```

---

## Capabilities

| Area | What it does | Docs |
|------|----------------|------|
| **Intelligence Gathering** | ARP scan, CDP/DTP/DHCP/802.1Q/802.1X enum, SMB version, Memcached recon | [Intelligence Gathering](Documentation/Intelligence%20Gathering/README.md) |
| **Enumeration** | FTP/TFTP/SSH/Telnet/SMB/SNMP/Memcached enum & brute | [Enumeration](Documentation/Enumeration/README.md) |
| **Man-in-the-Middle** | ARP/DNS/DHCP/ICMP, LLMNR/NBT-NS/mDNS, STP/HSRP/VRRP hijack, SMB relay, cred sniff | [Man-in-the-middle](Documentation/Man-in-the-middle/README.md) |
| **Denial of Service** | MAC/CDP/STP/DHCP/VTP floods, ICMP/TCP/UDP/HTTP floods, EIGRP/OSPF injection | [Denial of Service](Documentation/Denial%20of%20Service/README.md) |
| **VLAN Bypassing** | CDP inject, DTP enable-trunk, 802.1Q double-tag | [Vlan Bypassing](Documentation/Vlan%20Bypassing/README.md) |
| **VLAN Tampering** | VTP add VLAN | [Vlan Tampering](Documentation/Vlan%20Tampering/README.md) |
| **Authentication Cracking** | Offline extract/crack from pcap: OSPF, HSRP, EIGRP, VRRP, GLBP, NTP, BFD, VTP, RSVP, IS-IS, TACACS+, SSH keys | [Authentication Cracking](Documentation/Authentication%20Cracking/README.md) |
| **Cisco Passwords** | Offline Type 4/5/7/8/9 crack/decrypt | [Cisco Passwords](Documentation/Cisco%20Passwords/README.md) |
| **Data Manipulation** | SNMP SET, Memcached set/delete | [Data Manipulation](Documentation/Data%20Manipulation/README.md) |
| **Exfiltration** | SNMPv3 Cisco running-config → TFTP | [Exfiltration](Documentation/Exfiltration/README.md) |

Full flag lists, behavior, colors, and examples live under `Documentation/`.

---

## Usage
```
[Shared]
  -I, --interface                      Network interface to listen on (e.g. eth0)
      --ip                             Target IP(s): comma-separated for --arp --poison; single IPv4 for flood modes
      --port                           Non-default port number
      --flood-count                    Unique MAC addresses (default 20000 for mac-flood; 0=live random for stp); other floods: total packets (0=unlimited)
      --flood-rate                     Packets per second for flood modes (default: full speed)
      --random-source                  Spoof a random source IP per packet (ICMP/TCP/UDP flood)
      --stp                            STP Protocol
      --revision-number                VTP forged Configuration Revision (default: learned+1)
      --src                            Source IP
      --smb                            SMB Protocol
      --memcached                      Memcached Protocol
      --cdp                            CDP Protocol
      --dhcp                           DHCP Protocol
      --dtp                            DTP Protocol
      --802.1q                         802.1Q Protocol
      --802.1x                         802.1X Protocol
      --enum                           Enumeration mode
      --dst-vlan                       802.1Q inner/target VLAN
      --src-mac                        Source MAC override (default: interface MAC)
      --payload                        802.1Q ICMP echo payload string (default: Cisco Production)
      --ospf                           OSPF Protocol
      --hsrp                           HSR Protocol
      --eigrp                          EIGRP Protocol
      --vrrp                           VRRP Protocol
      --auth                           Passphrase OR optional SNMPv3 auth protocol (MD5|SHA|SHA-224|SHA-256|SHA-384|SHA-512)
      --vtp                            VTP Protocol
      --wordlist                       Wordlist file for dictionary attack
      --snmp                           SNMP Protocol
      --v2c                            SNMPv2c
      --v3                             SNMPv3
      --community                      SNMP community string
      --oid                            SNMP OID
      --target                         Target IP address/host
      --username                       Username for authentication
      --file                           File path

[MitM — Name Resolution]
      --llmnr                          LLMNR poisoner (UDP multicast :5355)
      --nbt-ns                         NBT-NS poisoner (UDP broadcast :137)
      --mdns                           mDNS poisoner (224.0.0.251:5353 + ff02::fb:5353)

[MitM — ARP Poisoning]
      --arp                            ARP/NDP mode
      --scan                           Scan the interface subnet for live hosts (use with --arp)
      --poison                         Poison the ARP/NDP cache for targets (use with --arp)

[MitM — STP]
      --rstp                           RSTP Protocol
      --mac                            Attacker MAC address

[MitM — Hijacking]
      --hijack                         Protocol hijacking

[MitM — FHRP]
      --hsrpv2                         HSRPv2 Protocol
      --group                          Group or virtual router ID (0-255)
      --virtual-ip                     Virtual IP address

[MitM — ICMP]
      --icmp                           ICMP Protocol
      --redirect                       ICMP redirect attack

[MitM — 802.1X]
      --mitm                           Perform Man-in-the-middle attack
      --interface1                     802.1X MitM authenticator-side interface
      --interface2                     802.1X MitM supplicant-side interface

[MitM — 802.1Q]
      --arp-poison                     802.1Q ARP poison MitM
      --dst-ip                         Victim IP to poison
      --src-ip                         Spoofed source IP

[MitM — DNS]
      --dns                            DNS Protocol
      --spoof-domain                   DNS Domain(s) to spoof

[MitM — DHCP]
      --dhcp-spoofing                  DHCPv4 spoofing — race legitimate server (requires root)
      --rouge                          DHCP rogue server
      --dhcpv6-spoofing                DHCPv6 spoofing with ICMPv6 RA — rogue DHCPv6 server (requires root)

[MitM — SMB Relay]
      --smb-relay                      Intercept NTLM auth and relay to target (requires root)
      --relay-from                     Victim IP to relay NTLM auth from (optional; default: any poisoned host)
      --relay-to                       Target IP to relay NTLM auth to

[MitM — Credential Sniffing]
      --cred-sniffing                  Credential sniffing: FTP/SMTP/IRC/HTTP/LDAP/NTLM/Kerberos/SNMP/MSSQL (requires root)
      --ignore                         Skip packets from/to this IP while sniffing credentials
      --pcap-file                      Parse a single .pcap file for sniffing credentials
      --pcap-dir                       Recursively parse all .pcap files in a directory for sniffing credentials
      --output-dir                     Write per-protocol .txt files here for sniffing credentials

[DoS — Layer 2]
      --cage                           Poison target cache with random neighbor MACs
      --subnet                         Subnet to probe (e.g. 192.168.1.0/24)
      --flood-conf                     STP conf BPDU DoS flood
      --flood-tcn                      STP TCN BPDU DoS flood
      --mac-flood                      MAC flood / CAM table overflow (requires root)
      --cdp-flood                      CDP neighbor table overflow (requires root)
      --delete-all-vlans               VTP delete-all VLANs DoS
      --delete-vlan                    VTP delete one VLAN DoS
      --dos                            VTP DoS mode gate
      --catalyst-zero-day              VTP Catalyst crash DoS
      --cdp-rate                       CDP flood: packets per second (default: full speed)
      --dhcp-flood                     DHCP DoS
      --discover                       DHCP DISCOVER pool exhaustion
      --release                        DHCP RELEASE lease cancellation
      --dhcp-pool                      DHCP target IP range (e.g. 192.168.100.2-254)
      --dhcp-rate                      DHCP packets per second (default: full speed)

[DoS — ICMP]
      --icmp-flood                     ICMP Echo Request flood (requires root)

[DoS — TCP]
      --tcp-syn-flood                  TCP SYN flood (requires root)
      --tcp-ack-flood                  TCP ACK flood (requires root)
      --tcp-rst-flood                  TCP RST flood (requires root)
      --tcp-push-flood                 TCP PSH+ACK flood (requires root)
      --tcp-zero-window-flood          TCP SYN+zero-window flood (requires root)
      --tcp-null-flood                 TCP null (no flags) flood (requires root)
      --tcp-out-of-order-flood         TCP out-of-order PSH+ACK flood (requires root)
      --tcp-xmas-tree-flood            TCP Xmas FIN+PSH+URG flood (requires root)
      --tcp-fin-flood                  TCP FIN flood (requires root)

[DoS — UDP]
      --udp-normal-flood               UDP flood with correct checksum and 16-byte payload (requires root)
      --udp-zero-length-flood          UDP flood with 8-byte header only, no payload (requires root)
      --udp-random-checksum-flood      UDP flood with random (bad) checksum (requires root)
      --udp-zero-checksum-flood        UDP flood with checksum=0 (RFC 768 disabled) (requires root)

[DoS — HTTP]
      --http1.0-dos                    HTTP/1.0 connection flood — rapid reconnect GET requests
      --http1.1-dos                    HTTP/1.1 Slowloris — exhaust server connection table with open sockets
      --http2-dos                      HTTP/2 Rapid Reset flood (CVE-2023-44487) — HEADERS+RST_STREAM over TLS
      --http3-dos                      HTTP/3 QUIC Initial packet flood — exhaust server QUIC connection state (UDP)

[DoS — Routing]
      --as                             Autonomous System Number
      --blackhole                      EIGRP static route blackhole
      --table-overflow                 EIGRP routing table overflow with random external routes
      --fake-neighbors                 EIGRP fake neighbor Hello flood
      --reset-neighbors                EIGRP neighborship reset via spoofed Hello

[DoS — Application]
      --flush-all                      Invalidate all Memcached keys via flush_all

[Intelligence Gathering]
      --arp-scan                       ARP host discovery (requires root)
      --version                        SMB version / OS fingerprint
      --active                         Active mode — send ARP requests and collect replies
      --passive                        Passive mode — sniff ARP traffic without sending
      --eapinfo                        802.1X EAP Identity string in probe (default: Cisco Production)
      --range                          ARP active scan: CIDR range (e.g. 192.168.1.0/24); default: auto-detect from interface

[Data Manipulation]
      --set                            Set Memcached or SNMP key
      --delete                         Delete Memcached key
      --value                          Memcached value payload
      --v1                             SNMPv1

[Vlan Bypassing]
      --inject                         Injection mode
      --enable-trunk                   DTP enable trunking attack
      --double-tag                     802.1Q double-tag VLAN bypass
      --src-vlan                       802.1Q double-tag outer VLAN ID (0-4095)

[Enumeration]
      --brute                          Brute force
      --telnet                         Telnet Protocol
      --tftp                           TFTP server host, host:port, or domain name (default port 69)
      --get                            Comma-separated remote filenames to download/probe via TFTP
      --put                            Comma-separated local file paths to upload via TFTP — remote name is the file's basename
      --ftp                            FTP server host, host:port, or domain name (default port 21)
      --bounce                         FTP bounce scan: user:password@relay-host
      --ssh                            SSH Protocol
      --auth-methods                   Enumerate SSH supported auth methods
      --cipher-enum                    Enumerate SSHv2 algorithms, host keys, known-bad public key acceptance
      --key-enum                       Test SSH public/private keys for acceptance
      --threads                        Brute parallel tasks (optional, default 16, max 64)
      --walk                           SNMPv2c snmpwalk
      --rate-limit                     Wait n milliseconds between probe packets (default 100)
      --anon                           Check anonymous FTP login (USER anonymous / PASS anonymous@)
      --features                       List FTP server capabilities via FEAT command
      --userlist                       Username wordlist
      --passlist                       Password/community wordlist
      --password                       Password for authentication

[Authentication Cracking]
      --capture                        Pcap/pcapng file to analyse
      --glbp                           GLBP Protocol
      --ntp                            NTP Protocol
      --bfd                            BFD Protocol
      --rsvp                           RSVP Protocol
      --is-is                          IS-IS Protocol
      --tacacs-plus                    TACACS+ Protocol
      --crack                          Crack extracted hashes via dictionary attack

[Cisco Passwords]
      --cisco-pass                     Enable Cisco password cracking mode
      --hash                           Hash value to crack directly
      --type4                          Crack Cisco Type 4 (enable secret 4 / raw SHA) hashes — requires wordlist; auto-detects SHA-1/224/256/3-256/384/512
      --type5                          Crack Cisco Type 5 (enable secret 5 / md5crypt) hashes — requires wordlist
      --type7                          Decrypt Cisco Type 7 (enable secret 7 / XOR cipher) passwords — no wordlist needed
      --type8                          Crack Cisco Type 8 (enable secret 8 / PBKDF2-SHA256) hashes — requires wordlist
      --type9                          Crack Cisco Type 9 (enable secret 9 / scrypt N=16384 r=1 p=1) hashes — requires wordlist
```

---

## Quick examples

```bash
# L2 intel
sudo ./NetDestruct --cdp --enum -I eth0
sudo ./NetDestruct --arp-scan --active -I eth0 --range 192.168.1.0/24

# Service enum / brute
./NetDestruct --ssh --auth-methods --target 192.168.1.10 --username cisco
./NetDestruct --telnet --brute --target 192.168.1.10 --userlist users.txt --passlist pass.txt
./NetDestruct --snmp --enum --v2c --community public --target 192.168.1.10

# MitM
sudo ./NetDestruct --arp --poison -I eth0 --ip 192.168.1.50
sudo ./NetDestruct --dns --hijack -I eth0 --target 192.168.1.50
sudo ./NetDestruct --llmnr --nbt-ns -I eth0

# Offline auth cracking
./NetDestruct --ospf --capture ospf.pcap --crack --wordlist rockyou.txt
./NetDestruct --cisco-pass --type7 --hash 0822455D0A16

# DoS
sudo ./NetDestruct --mac-flood -I eth0 --flood-rate 1000
```

---

## Layout

```
NetDestruct/
├── main.go                 # CLI (Cobra) wiring
├── libs/
│   ├── authentication-cracking/
│   ├── cisco-passwords/
│   ├── data-manipulation/
│   ├── dos/
│   ├── enumeration/
│   ├── exfiltration/
│   ├── intelligence-gathering/
│   ├── mitm/
│   ├── vlan-bypassing/
│   └── vlan-tampering/
└── Documentation/          # Per-module READMEs
```

---

## Requirements

| Mode | Typical needs |
|------|----------------|
| Raw L2 / MitM / floods | Linux, root or `CAP_NET_RAW`, interface (`-I`) |
| TCP/UDP service enum/brute | Network reachability; often no root |
| Offline cracking | Capture/key/config file; no root |
