# SIEMen

Security AI data layer on Cloudflare Workers. Purpose-built for AI security agents — combines fast KV scratch cache, semantic vector search over findings, per-engagement agent memory, and a similarity-based LLM triage cache. Exposes both a REST API and a built-in MCP server so Claude/AI agents can read, write, and search security data directly.

## Stack

| Layer | Technology | Details |
|-------|-----------|---------|
| Runtime | Cloudflare Workers | Edge-native, globally distributed, zero cold starts |
| Framework | Hono v4 + TypeScript | Lightweight routing, CORS, middleware |
| Database | Cloudflare D1 (SQLite) | Engagements, findings, memory, semantic cache log |
| Vector Search | Cloudflare Vectorize | 768-dim BGE embeddings, cosine similarity, namespace-isolated per engagement |
| KV Cache | Workers KV | Fast scratch store + semantic cache values |
| Embeddings | Workers AI (BGE-768) | Primary — OpenRouter fallback on failure |
| Rate Limiting | Workers Rate Limiting API | 60 req/min per caller (cross-isolate, durable) |
| Auth | Web Crypto SHA-256 | Timing-safe Bearer token verification |
| MCP | JSON-RPC 2.0 | 11 tools on `POST /mcp` — same handlers as REST |

## Pipeline

```
SIC scan output (JSON)
  └─▶ sic_siemen_bridge.py --scan <file> --engagement-name "Client"
        ├─▶ POST /v1/engagements       — create / upsert engagement
        └─▶ POST /v1/findings/batch    — transform + ingest findings (100/batch)

SIEMen data layer
  ├─▶ Vectorize        — BGE-768 embeddings for semantic search
  ├─▶ D1              — findings, memory, cache log
  └─▶ GET /v1/engagements/:id/report  — severity_rollup, status_rollup, memories, cache_stats

SOC report generation
  └─▶ generate_report_from_engagement (soc-reporter-mcp)
        └─▶ maps findings → P0/P1/P2/P3 buckets → SOC handoff HTML
```

## What It Does

### Fast KV Scratch Cache
Per-engagement key/value store for in-flight agent notes, intermediate results, and shared state across agent steps. Namespaced to prevent cross-engagement leakage. Optional TTL (max 24h).

### Semantic Vector Search
Embed and store security findings, CVEs, and controls with `finding_store`. Retrieve the closest matches by semantic similarity with `finding_search`. Namespace-scoped to engagement — an agent searching for "SQL injection" can only surface findings from its own engagement.

### Per-Engagement Agent Memory
Agents store notes with `engagement_remember` and recall them by recency or vector similarity with `engagement_recall`. Supports sub-scoping by `session_id` for multi-step workflows.

### Semantic LLM Triage Cache
`semantic_triage` routes security prompts through a two-level cache before hitting an LLM:
1. Exact-hash short-circuit — identical prompts reuse prior analysis instantly
2. Cosine similarity check — prompts above the configured threshold (default 0.92) return a cached response without an LLM call
3. Miss — calls the configured LLM gateway, writes result to KV + Vectorize for future hits

Cuts LLM spend significantly when agents analyze structurally similar findings across engagements.

### Finding Lifecycle
Findings transition through status states (`open` → `accepted` → `remediated` → `false_positive`) via `PATCH /v1/findings/:id`. Batch ingest via `POST /v1/findings/batch` for pipeline ingestion from scanners.

### Engagement Reports
`GET /v1/engagements/:id/report` exports all findings with cursor pagination, severity rollup, status rollup, memories, and cache stats in a single response — ready for SOC pipeline consumption.

## MCP Tools

| Tool | Description |
|------|-------------|
| `engagement_open` | Create or register a new pentest engagement |
| `engagement_list` | List all engagements (non-deleted, newest first) |
| `engagement_report` | Full export: findings, rollups, memories, cache stats |
| `sec_cache_get` | Read from the fast KV scratch store |
| `sec_cache_set` | Write to the fast KV scratch store (optional TTL) |
| `finding_store` | Embed and store a finding, CVE, or control |
| `finding_search` | Semantic RAG over findings scoped to an engagement |
| `engagement_remember` | Store agent memory for an engagement |
| `engagement_recall` | Recall memories by recency or vector similarity |
| `semantic_triage` | Semantic-cache-backed LLM triage |
| `cache_stats` | Get cache hit/miss stats for an engagement |

## REST Routes

All `/v1/*` routes require `Authorization: Bearer <SIEMEN_API_KEY>`.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check (unauthenticated) |
| GET | `/v1/engagements` | List all engagements (non-deleted, newest first) |
| POST | `/v1/engagements` | Create/upsert an engagement |
| GET | `/v1/engagements/:id/report` | Full export: findings, rollups, memories, cache stats |
| PATCH | `/v1/engagements/:id` | Update engagement status/name/client |
| POST | `/v1/findings` | Embed + store a finding/CVE/control |
| POST | `/v1/findings/batch` | Batch ingest (up to 100 findings per request) |
| POST | `/v1/findings/search` | Semantic search over findings |
| PATCH | `/v1/findings/:id` | Update finding severity/body/tags/status |
| DELETE | `/v1/findings/:id` | Soft-delete a finding |
| GET | `/v1/stats?engagement_id=` | Cache hit/miss stats + severity rollup |
| GET | `/v1/kv/:ns/:key` | KV scratch read |
| PUT | `/v1/kv/:ns/:key` | KV scratch write |
| POST | `/v1/memory` | Store agent memory |
| GET | `/v1/memory?engagement_id=` | Recall agent memories |
| POST | `/v1/triage` | Semantic triage with LLM cache |
| POST | `/mcp` | MCP JSON-RPC endpoint (all 11 tools) |

## D1 Schema

Apply migrations in order with `wrangler d1 execute siemen-db --remote --file migrations/<file>.sql`:

- **engagements** — engagement registry (id, name, client, status, timestamps)
- **memory** — agent memory per engagement (content, tags, vector_id, session_id)
- **findings** — security findings/CVEs/controls (kind, title, body, severity, asset, external_id, vector_id, tags, finding_status, deleted_at)
- **semantic_cache_log** — cache outcome log (prompt_hash, outcome, similarity, model, tokens, created_at)

## SIC Integration

`sic_siemen_bridge.py` — the official SIC → SIEMen bridge. Transforms SIC scan finding dicts and batch-POSTs them to SIEMen with full field mapping.

**Field mapping (SIC → SIEMen):**

| SIEMen field | SIC source fields |
|---|---|
| `title` | `name` / `vulnerabilityName` / `Title` / `template-id` / `checkID` |
| `body` | `description` / `info.description` / `details` (capped 2000 chars) |
| `severity` | `severity` / `info.severity` → remapped (`none`/`unknown` → `info`) |
| `kind` | `cve` if CVE-YYYY-NNNNN in title, `control` if Checkov, else `finding` |
| `external_id` | CVE ID extracted from title/template-id (enables dedup) |
| `asset` | `host` / `url` / `target` / `affected_component` / `matched-at` |
| `tags` | `[scanner, category]` (up to 5, deduped) |

**CLI:**

```bash
python sic_siemen_bridge.py \
    --scan ./_runs/scan-20260101.json \
    --engagement-name "Example Corp Pentest" \
    [--client "Example Corp"] \
    [--engagement-id "existing-id"] \
    [--url https://siemen.frxncois.workers.dev] \
    [--dry-run]
```

**Library:**

```python
from sic_siemen_bridge import SIEMenClient

client = SIEMenClient()  # reads SIEMEN_URL + SIEMEN_API_KEY from env
eid = client.open_engagement("My Pentest", client="Acme")
result = client.push_findings(eid, sic_findings)
# { stored, duplicates, errors, total_pushed }

report = client.get_report(eid)
# { findings, severity_rollup, status_rollup, memories, cache_stats }
```

## Deploy

```bash
# 1. Create infrastructure
wrangler vectorize create siemen-vectors --dimensions=768 --metric=cosine
wrangler d1 create siemen-db
wrangler kv namespace create siemen-sc-cache
wrangler kv namespace create siemen-kv

# 2. Update wrangler.toml with the returned IDs

# 3. Apply D1 migrations (run in order)
wrangler d1 execute siemen-db --remote --file migrations/migration-001-engagements.sql
wrangler d1 execute siemen-db --remote --file migrations/migration-002-memory.sql
wrangler d1 execute siemen-db --remote --file migrations/migration-003-findings.sql
wrangler d1 execute siemen-db --remote --file migrations/migration-004-semantic-cache-log.sql
wrangler d1 execute siemen-db --remote --file migrations/migration-005-roi.sql
wrangler d1 execute siemen-db --remote --file migrations/migration-006-finding-status.sql

# 4. Set secrets
wrangler secret put SIEMEN_API_KEY
wrangler secret put OPENROUTER_API_KEY
wrangler secret put LLM_GATEWAY_KEY

# 5. Deploy
npm run deploy
```

## MCP Configuration

Add to your Claude Desktop / Claude Code MCP config:

```json
{
  "mcpServers": {
    "siemen": {
      "url": "https://your-worker.workers.dev/mcp",
      "headers": {
        "Authorization": "Bearer ${SIEMEN_API_KEY}"
      },
      "alwaysAllow": [
        "engagement_open",
        "engagement_list",
        "sec_cache_get",
        "finding_search",
        "engagement_recall",
        "cache_stats"
      ]
    }
  }
}
```

Set `SIEMEN_API_KEY` in your shell environment. Write tools (`finding_store`, `finding_store_batch`, `sec_cache_set`, `engagement_remember`, `semantic_triage`) require explicit approval by default.

## Security

- All `/v1/*` and `/mcp` routes require a `Bearer` token verified with Web Crypto SHA-256 (no Node.js crypto — edge-compatible)
- Findings are namespace-scoped to `engagement_id` in Vectorize at the query layer
- Secrets via `wrangler secret put` only — never in source or `wrangler.toml`
- Rate limited at 60 req/min per token identity (not per IP)

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

MIT
