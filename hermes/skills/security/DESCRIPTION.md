# Security

Skills for defensive cybersecurity investigation inside the VIGILANT ecosystem.

- **pcap-filter**: captures already stored in the datalake (list, triage, then protocol views
  `pcap_ip`, `pcap_arp`, `pcap_tcp`, `pcap_udp`).

All work on network captures only. They never touch filesystem paths, shells or
external tools: every capture is reached through VIGILANT MCP tools.
