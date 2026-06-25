# SIEMen

Security AI data layer on Cloudflare Workers. Purpose-built for AI security agents — SIEMen stores scan findings in a relational database, indexes them as semantic vectors for similarity search, maintains per-engagement agent memory, and exposes everything through both a REST API and a built-in MCP server.

When a security scanner finishes a run, SIEMen becomes the single place where findings accumulate, get enriched, get triaged, and eventually get exported into a SOC report — all without spinning up any additional infrastructure.

---

## How It Fits Into a Security Pipeline

```
SIC scan output (JSON)
  └─▶ sic_siemen_bridge.py --scan <file> --engagement-name "Client"
        ├─▶ POST /v1/engagements       — create or resume the engagement record
        └─▶ POST /v1/findings/batch    — transform and ingest findings (100/batch)

SIEMen data layer
  ├─▶ D1 (SQLite)    — structured storage: engagements, findings, memory, cache log
  ├─▶ Vectorize      — BGE-768 embeddings for semantic similarity search
  └─▶ Workers KV     — fast scratch cache for in-flight agent state

Report and handoff
  └─▶ GET /v1/engagements/:id/report  — severity rollup, status rollup, memories, cache stats
        └─▶ soc-reporter-mcp          — maps findings into P0–P3 buckets → SOC handoff HTML
```

---

## Stack

| Layer | Technology | Why This Choice |
|-------|-----------|-----------------|
| Runtime | Cloudflare Workers | Edge-native, globally distributed, zero cold starts — findings are stored and queried at the edge without a separate server |
| Framework | Hono v4 + TypeScript | Lightweight routing with zero Node.js dependencies, required for the edge runtime |
| Database | Cloudflare D1 (SQLite) | Relational data (engagements, findings, memory) with full SQL — no separate database server to manage |
| Vector Search | Cloudflare Vectorize | 768-dimension BGE embeddings for semantic similarity — lets agents find "SQL injection" findings even when the text uses different phrasing |
| KV Cache | Workers KV | Sub-millisecond reads for scratch state and triage cache values |
| Embeddings | Workers AI (BGE-768) | Runs inside Cloudflare — no external embedding API call. OpenRouter fallback on failure |
| Rate Limiting | Workers Rate Limiting API | Cross-isolate, durable limits — works correctly even when requests hit different edge locations |
| Auth | Web Crypto SHA-256 | Timing-safe Bearer token verification without the Node.js `crypto` module (not available at the edge) |
| MCP | JSON-RPC 2.0 | 11 tools on `POST /mcp` — same handlers as REST, just a different transport |

---

## What It Does

### Fast KV Scratch Cache

Per-engagement key/value store for in-flight agent notes, intermediate results, and shared state across agent steps. Namespaced to prevent cross-engagement leakage. Optional TTL (max 24h).

*Why it exists:* AI agents running multi-step workflows need a place to write intermediate state that isn't yet final enough to be a finding. KV is the scratchpad.

### Semantic Vector Search

Embed and store security findings, CVEs, and controls with `finding_store`. Retrieve closest matches by semantic similarity with `finding_search`. Namespace-scoped to engagement — an agent searching for "SQL injection" only surfaces findings from its own engagement.

*Why it exists:* Traditional keyword search misses findings that describe the same vulnerability with different words. Semantic search finds them regardless of phrasing.

### Per-Engagement Agent Memory

Agents store notes with `engagement_remember` and recall them by recency or vector similarity with `engagement_recall`. Supports sub-scoping by `session_id` for multi-step workflows.

*Why it exists:* Without memory, each agent step starts from scratch. Memory allows an agent to build context across multiple steps within the same engagement.

### Semantic LLM Triage Cache

`semantic_triage` routes security prompts through a two-level cache before hitting an LLM:

1. **Exact hash match** — identical prompts reuse prior analysis instantly
2. **Cosine similarity check** — prompts above the configured threshold (default 0.92) return a cached response without an LLM call
3. **Cache miss** — calls the configured LLM gateway, writes result to KV + Vectorize for future hits

*Why it exists:* When agents analyze 50 findings across 10 engagements, many prompts are structurally identical. The cache eliminates redundant LLM calls.

### Finding Lifecycle

Findings transition through status states (`open` → `accepted` → `remediated` → `false_positive`) via `PATCH /v1/findings/:id`. Batch ingest via `POST /v1/findings/batch` for pipeline ingestion from scanners.

*Why it exists:* A raw list of findings has no operational value unless you can track which ones have been acted on. Status tracking makes the data usable by a SOC team.

### Engagement Reports

`GET /v1/engagements/:id/report` exports all findings with cursor pagination, severity rollup, status rollup, memories, and cache stats in a single response — ready for SOC pipeline consumption.

*Why it exists:* The SOC report generator needs a single structured snapshot of the engagement. This endpoint provides it without requiring multiple round-trips.

---

## MCP Tools

| Tool | Description |
|------|-------------|
| `engagement_open` | Create or register a new pentest engagement |
| `engagement_list` | List all engagements (non-deleted, newest first) |
| `engagement_report` | Full export: findings, rollups, memories, cache stats |
| `sec_cache_get` | Read from the fast KV scratch store |
| `sec_cache_set` | Write to the fast KV scratch store (optional TTL) |
| `finding_store` | Embed and store a finding, CVE, or control |
| `finding_search` | Semantic search over findings scoped to an engagement |
| `engagement_remember` | Store agent memory for an engagement |
| `engagement_recall` | Recall memories by recency or vector similarity |
| `semantic_triage` | Semantic-cache-backed LLM triage |
| `cache_stats` | Get cache hit/miss stats for an engagement |

---

## REST Routes

All `/v1/*` routes require `Authorization: Bearer <SIEMEN_API_KEY>`.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check (unauthenticated) |
| GET | `/v1/engagements` | List all engagements |
| POST | `/v1/engagements` | Create or upsert an engagement |
| GET | `/v1/engagements/:id/report` | Full export for SOC handoff |
| PATCH | `/v1/engagements/:id` | Update engagement status, name, or client |
| POST | `/v1/findings` | Embed and store a single finding |
| POST | `/v1/findings/batch` | Batch ingest (up to 100 per request) |
| POST | `/v1/findings/search` | Semantic search over findings |
| PATCH | `/v1/findings/:id` | Update finding severity, body, tags, or status |
| DELETE | `/v1/findings/:id` | Soft-delete a finding |
| GET | `/v1/stats?engagement_id=` | Cache hit/miss stats and severity rollup |
| GET | `/v1/kv/:ns/:key` | KV scratch read |
| PUT | `/v1/kv/:ns/:key` | KV scratch write |
| POST | `/v1/memory` | Store agent memory |
| GET | `/v1/memory?engagement_id=` | Recall agent memories |
| POST | `/v1/triage` | Semantic triage with LLM cache |
| POST | `/mcp` | MCP JSON-RPC endpoint (all 11 tools) |

---

## D1 Schema

Apply migrations in order with `wrangler d1 execute siemen-db --remote --file migrations/<file>.sql`:

| Table | Purpose |
|-------|---------|
| `engagements` | Engagement registry — id, name, client, status, timestamps |
| `memory` | Agent memory per engagement — content, tags, vector_id, session_id |
| `findings` | Security findings, CVEs, controls — kind, title, body, severity, asset, external_id, vector_id, tags, finding_status, deleted_at |
| `semantic_cache_log` | Triage cache outcome log — prompt_hash, outcome, similarity, model, tokens |

---

## SIC Integration

`sic_siemen_bridge.py` is the official SIC → SIEMen bridge. It reads a SIC scan output file, transforms each finding into the SIEMen schema, and batch-posts them to the API. Every field is mapped from multiple possible source names so the bridge handles output from different SIC scanner tools without configuration.

### Field Mapping

| SIEMen field | SIC source fields (tried in order) |
|---|---|
| `title` | `name`, `vulnerabilityName`, `Title`, `template-id`, `checkID` |
| `body` | `description`, `info.description`, `details` (capped at 2000 chars) |
| `severity` | `severity`, `info.severity` → normalized (`none`/`unknown` → `info`) |
| `kind` | `cve` if CVE-YYYY-NNNNN in title, `control` if Checkov ID, else `finding` |
| `external_id` | CVE ID extracted from title/template-id — used for deduplication |
| `asset` | `host`, `url`, `target`, `affected_component`, `matched-at` |
| `tags` | `[scanner, category]` (up to 5, deduplicated) |

### CLI

```bash
python sic_siemen_bridge.py \
    --scan ./_runs/scan-20260101.json \
    --engagement-name "Example Corp Pentest" \
    [--client "Example Corp"] \
    [--engagement-id "existing-id"] \
    [--url https://your-worker.workers.dev] \
    [--dry-run]
```

### Library

```python
from sic_siemen_bridge import SIEMenClient

client = SIEMenClient()  # reads SIEMEN_URL + SIEMEN_API_KEY from env
eid = client.open_engagement("My Pentest", client="Acme Corp")
result = client.push_findings(eid, sic_findings)
# { stored, duplicates, errors, total_pushed }

report = client.get_report(eid)
# { findings, severity_rollup, status_rollup, memories, cache_stats }
```

---

## Deploy

```bash
# 1. Create infrastructure
wrangler vectorize create siemen-vectors --dimensions=768 --metric=cosine
wrangler d1 create siemen-db
wrangler kv namespace create siemen-sc-cache
wrangler kv namespace create siemen-kv

# 2. Update wrangler.toml with the IDs returned above

# 3. Apply D1 migrations in order
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

---

## MCP Configuration

Add to Claude Desktop or Claude Code MCP config:

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

Set `SIEMEN_API_KEY` in your shell environment. Write tools (`finding_store`, `sec_cache_set`, `engagement_remember`, `semantic_triage`) require explicit approval by default — intentional, because they modify stored data.

---

## Security

- All `/v1/*` and `/mcp` routes require a Bearer token verified with Web Crypto SHA-256. The Web Crypto API is used instead of Node.js `crypto` because Node.js APIs are not available in the Cloudflare Workers edge runtime.
- Timing-safe comparison prevents timing attacks where an attacker could infer token length or prefix by measuring response time.
- Findings are namespace-scoped to `engagement_id` in Vectorize — a semantic search for one engagement cannot surface findings from another.
- Secrets are managed via `wrangler secret put` only and never appear in source code or `wrangler.toml`.
- Rate limiting is durable across edge instances — counters are shared, so distributing requests across data centers does not bypass the limit.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

## License

MIT
