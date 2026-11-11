---
name: pcap-filter
description: Use for ANY analysis, packet inspection, protocol detail, or network inventory on ALREADY STORED captures in the datalake (e.g. by capture_id, UUID, "en la última captura", "qué capturas hay", or time range). Covers listing unique IPv4 addresses, MACs, ARP flows, TCP sessions, UDP traffic, ports, or generic trace filtering. Applies the matching protocol filter view (pcap_tcp, pcap_udp, pcap_arp, pcap_ip). Also use when the user attaches a pcap (pcap_ref marker): ingest it first.
---

# VIGILANT: Protocol Filtering and Packet Views of Stored Captures

## Tools

- `list_captures(start?, end?)`: captures in the datalake, newest first.
- `ingest_pcap(pcap_ref)`: registers an attachment staged by the API.
- `pcap_ip`, `pcap_arp`, `pcap_tcp`, `pcap_udp` (parameters: `capture_id`,
  `offset=0`, `limit=100`). Each applies one fixed display filter.

| Protocol focus | Tool | Fixed display filter |
| --- | --- | --- |
| TCP: handshakes, flags, resets, ports, sessions | `pcap_tcp` | `tcp && !icmp && !icmpv6` |
| UDP: DNS/NTP/DHCP, datagram inspection, ports | `pcap_udp` | `udp && !icmp && !icmpv6` |
| ARP: requests/replies, MAC-IP mapping, spoofing | `pcap_arp` | `arp` |
| Layer 3: IPv4 addresses, IP protocols, TTL | `pcap_ip` | `ip` |

## Workflow (all in the same turn; never stop to ask or announce)

Never end a turn with a sentence announcing what you are going to do. If you
need another tool call, make it; the turn ends only with the final answer.

### Step 0: Resolve the capture
- A `[pcap attachment staged: pcap_ref=...]` marker is present: call
  `ingest_pcap(pcap_ref=<exact token>)` and use the returned `capture_id`.
- UUID given: use it as `capture_id`. Never invent one.
- By time or "la última": call `list_captures` and take the matching entry.
- "Qué capturas hay": report the list and stop.

### Step 1: Pick the fewest views that answer the question
Several views may be used when the question needs them, but always use the
MINIMUM number of views required. Each extra view costs time and adds data
the question did not ask for.
1. Start with the single view whose protocol matches what the question asks for:
   - ARP / MAC-IP mapping / who resolved whom: `pcap_arp`
   - TCP / flags / TCP ports / sessions / resets: `pcap_tcp`
   - UDP / DNS / datagrams / UDP ports: `pcap_udp`
   - IPv4 addresses / `ip.proto` / TTL / address ranges: `pcap_ip`
2. Read the `columns` of that result. If they already contain the data needed
   to answer, STOP: do not call another view to confirm, enrich or "double
   check" it.
3. Call a second view only when the question asks for data the first view
   cannot contain (for example, a question about both TCP and UDP ports needs
   `pcap_tcp` and `pcap_udp`). Name that reason to yourself before the call;
   if you cannot, do not call it.
4. Never call the same view twice with the same arguments, and never try other
   views just because a view returned `matched_count: 0`.

### Step 2: Call the view and read ALL the rows
- Call the view, then read `columns` and `rows`.
- If `truncated` is true, call the same view again with `offset` increased by
  the number of rows received, until `truncated` is false. Do not answer an
  inventory, a unique-values list or a count from a partial page.
- Derive unique values, counts and ranges only from returned rows. If the
  result is too large to process reliably, say so instead of estimating.
- `matched_count: 0` is a valid result: report it, do not try other filters
  to find something.
- If a tool returns an error, state the error once and stop.

## Answer

Give only the requested result (list or table), in the user's language. Do not
narrate intermediate steps and do not mention paging, `offset`, `limit` or
`truncated` unless data is actually missing.