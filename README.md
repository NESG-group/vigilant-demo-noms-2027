# VIGILANT: NOMS 2027 demo

Vertical slice of VIGILANT for the NOMS 2027
demo paper: an analyst question in Open WebUI becomes a **fixed, audited
tshark filter** over a stored capture, and the LLM answers from that evidence.
This repository contains only what that flow needs.

```
Open WebUI -> vigilant-backend (FastAPI) -> Hermes Agent -> Ollama
                    |  sanitise, stage attachments,  |
                    |  prepend scope prompt          |
                    +--------- MCP (/mcp) -----------+
                       pcap_tcp / pcap_arp / ... -> tshark -> audit line
```

## The flow

1. The analyst asks in Open WebUI (`docker-compose.dev-ui.yml`).
2. The API ([chat.py](src/vigilant/api/v1/chat.py)) stages attachments
   outside the conversation ([staging.py](src/vigilant/api/v1/pcap/staging.py):
   the model only sees a `pcap_ref`) and prepends the scope prompt
   ([scope.py](src/vigilant/services/scope.py)).
3. Hermes offers the model its skills and the MCP tools of
   [server.py](src/vigilant/mcp/server.py).
4. The model loads the `pcap-filter` skill
   ([SKILL.md](hermes/skills/security/pcap-filter/SKILL.md)) and picks a view
   (`pcap_tcp`, `pcap_arp`, ...).
5. The view ([filter_pcaps.py](src/vigilant/mcp/tools/filter_pcaps.py)) runs a
   hard-coded display filter and logs one audit line, independent of what the
   model later says:
   ```
   PCAP_VIEW_APPLIED {"capture_id": "...", "tool": "pcap_tcp", "display_filter": "tcp && !icmp && !icmpv6", ...}
   ```
6. The model answers using that evidence.

| View | Fixed display filter |
| --- | --- |
| `pcap_tcp` | `tcp && !icmp && !icmpv6` |
| `pcap_udp` | `udp && !icmp && !icmpv6` |
| `pcap_arp` | `arp` |
| `pcap_ip` | `ip` |

## Run it

Requires Docker with the NVIDIA runtime (Hermes needs a >= 64K context; see
`docker-compose.yml`).

```bash
cp env.example .env           # set HERMES_API_SERVER_KEY
make up-ui                    # ollama + hermes + backend + Open WebUI on :3000
make ollama-model             # pulls qwen2.5:72b if no model is installed
docker compose exec vigilant-backend alembic upgrade head   # datalake schema

# register a capture (returns capture_id); see data/README.md for what each one contains
for f in data/*.pcapng; do curl -F file=@$f http://localhost:8000/v1/datalake/ingest; done
```

Ask in Open WebUI (http://localhost:3000), e.g. *"Is there ARP spoofing in
capture `<capture_id>`?"*, then check the ground truth of what was applied:

```bash
docker logs vigilant-backend 2>&1 | grep PCAP_VIEW_APPLIED
```

## Development

```bash
uv sync --all-groups
make test lint
```

The sensor, the ingest-time actor analysis and the evaluation scripts of the
full project are intentionally not part of this repository.
