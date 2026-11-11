# Demo captures

Four small captures taken in a basic, controlled network environment
(traces T1-T4 of Table II in the companion paper, *Do LLMs Understand Network
Traces?*). They are the captures uploaded to the datalake in the demo and the
fixtures used by the test suite.

| File | Trace | Traffic | Packets (default / ARP / IP / TCP / UDP) |
| --- | --- | --- | --- |
| `arp-icmp.pcapng` | T1 | Host initialisation: neighbour discovery, address resolution, connectivity checks | 23 / 7 / 6 / 0 / 0 |
| `ip-networktrace2.pcapng` | T2 | Connectivity tests, DNS, IP fragmentation, failed TCP connections | 29 / 0 / 29 / 7 / 6 |
| `nmap22-23-53-80-443.pcapng` | T3 | Nmap TCP SYN and UDP scan, ICMP from closed ports | 32 / 4 / 27 / 13 / 8 |
| `nmap22-23-53-80-443-threewayhandshake.pcapng` | T4 | Host discovery and port scanning (ARP, UDP, TCP, ICMP), including TCP three-way handshake completion | 34 / 4 / 30 / 16 / 8 |

None of them contains ARP spoofing: every IP resolves to a single MAC.
