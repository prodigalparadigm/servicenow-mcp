# servicenow-mcp

An MCP server that gives an LLM client read and (optionally) write access to ServiceNow ITSM: incident search, incident detail, incident creation and annotation, assignment-group lookup, and read-only CMDB ownership lookup.

## The problem

Connecting a model to ServiceNow is easy to do badly. The Table API will happily return every column of every matching record, so a single "show me open P1s" turns into fifty thousand tokens of empty `u_*` columns and caller phone numbers; instances enforce per-user rate limits that a retry-happy agent trips within seconds; and an agent that can write has no built-in notion of "I already filed this ticket", so a reconnect files it again.

This server is the boring middle layer that stops those things: a hard per-call record cap, a field allowlist pushed down to the wire, rate limiting with 429-aware backoff, a read-only default, and one structured audit line per tool call.

## Quickstart

Requires Python 3.12.

```bash
git clone <this repo> && cd servicenow-mcp
uv venv --python 3.12 && source .venv/bin/activate
uv pip install -e ".[dev]"

# Run the full test suite. No credentials, no network.
pytest
```

To point it at a real instance:

```bash
cp .env.example .env    # then fill in the instance URL and credentials
set -a && source .env && set +a
servicenow-mcp          # speaks MCP over stdio
```

Registering it with an MCP client (Claude Desktop, Claude Code, or any other):

```json
{
  "mcpServers": {
    "servicenow": {
      "command": "/path/to/.venv/bin/servicenow-mcp",
      "env": {
        "SERVICENOW_INSTANCE_URL": "https://dev12345.service-now.com",
        "SERVICENOW_AUTH_MODE": "basic",
        "SERVICENOW_USERNAME": "svc_mcp",
        "SERVICENOW_PASSWORD": "...",
        "SERVICENOW_READ_ONLY": "true"
      }
    }
  }
}
```

The server refuses to start on a bad configuration rather than starting and failing every call.

## Tools

| Tool | Mode | What it does |
| --- | --- | --- |
| `server_info` | read | Reports read-only vs writable, the record cap, and which fields come back. Cheap to call first. |
| `search_incidents` | read | Filtered, paginated incident search returning a triage-sized projection. |
| `get_incident` | read | One incident by number, with the narrative fields; journals opt-in. |
| `list_assignment_groups` | read | Group lookup, for routing work to a name that actually exists. |
| `lookup_ci_owner` | read | Who supports/owns a CI, from the CMDB. Read-only in every configuration. |
| `create_incident` | write | Opens an incident. Idempotent when given a `correlation_id`. |
| `update_incident` | write | Annotates or updates an incident. Work notes and comments stay distinct. |

The two write tools are not registered at all when the server is read-only.

## How it works

```
MCP client (stdio)
      │  JSON-RPC on stdout/stdin
┌─────▼──────────┐
│ server.py      │  registers tools on mcp.server.MCPServer;
│                │  omits mutating tools when read-only
├────────────────┤
│ service.py     │  tool bodies: read-only enforcement, audit span,
│                │  projection, idempotency  ──────► audit.py (JSON lines → stderr/file)
├────────────────┤
│ client.py      │  Table API: pagination loop, record cap,
│                │  response-shape validation  ─────► projection.py, query.py
├────────────────┤
│ transport.py   │  token bucket → auth header → retry/backoff → 429/Retry-After
├────────────────┤
│ auth.py        │  basic  |  oauth2 client credentials (cached, refreshed)
└─────┬──────────┘
      │  httpx
   ServiceNow instance
```

Pagination is a loop, not a passthrough. The caller says how many records it wants; the client fetches pages of `page_size` until it has them, the result set ends, or the cap is hit. It targets one record past the limit so `has_more` is answered honestly, and skips that probe entirely when the instance sends `X-Total-Count`.

Tests inject an in-memory ServiceNow as an `httpx` transport, so the production request path — header assembly, retry loop, query encoding, response validation — executes unchanged offline.

## Design decisions

- **Field allowlists, pushed down as `sysparm_fields`.** A stock `incident` has ~180 columns. Returning them all is bad for context economy and worse for data minimisation: incidents carry caller phone numbers and free-text that quotes account identifiers. An allowlist is a reviewable, one-screen statement of exactly what crosses the boundary; a denylist isn't, because the next plugin install adds columns nobody vetted. Sending the allowlist as `sysparm_fields` means the unwanted columns are never transferred rather than fetched and dropped. `search_incidents` returns a triage summary and `get_incident` adds the narrative fields, so the expensive projection is paid for one record at a time.

- **Writes are retried on 429 and 503, and on nothing else.** A read can be replayed freely. A `POST` that timed out may already have created the incident, and quietly creating two P1s is worse than surfacing the timeout — so timeouts and 500s fail the write loudly. `ConnectError` is the exception: no bytes reached the instance, so replay is safe. Retry-After is honoured as seconds or HTTP-date, then clamped, because a misconfigured gateway advertising an hour should not be able to park the server for an hour.

- **Read-only is the default, and it's enforced twice.** `SERVICENOW_READ_ONLY` defaults to true; when set, mutating tools are absent from `list_tools` *and* the service refuses them. The tool list is advisory — a client can call a name it was never shown — so the list keeps the model from planning a write it can't do, while the service layer is what actually stops it.

- **Idempotency is a parameter, not a hope.** `create_incident` takes a `correlation_id`; if an incident already carries it, that incident is returned and nothing is written. Agent retries and client reconnects both replay tool calls, and this is the cheapest place to make that harmless.

- **Filter values can't rewrite the query.** ServiceNow's encoded-query grammar has no escape for its `^` delimiter, so a model-supplied `short_description` of `x^active=false` would silently change the filter. Operands containing a delimiter are refused; `extra_query` is the single, documented, audit-visible path that accepts raw query text.

- **The audit log never touches stdout.** Under stdio transport stdout *is* the protocol channel, and one stray byte breaks JSON-RPC framing. Audit lines go to stderr or a file, credential-shaped argument keys are redacted, and every value is length-capped so the audit trail can't become the leak.

## Limitations

- **Incidents only, plus two lookup tables.** No changes, problems, requests, catalog items, or knowledge articles. No attachments. The client is generic over tables, but the tools, projections, and state mappings are incident-specific.
- **State and priority mappings assume the out-of-box model.** An instance with a customised state model needs `extra_query`, or a change to `INCIDENT_STATES`.
- **`search_incidents` text matching is `LIKE` on `short_description`.** Not the indexed full-text search (`123TEXTQUERY321`), which behaves differently across instances and isn't portable enough to expose blindly.
- **Reference-field writes resolve group names only.** `caller` and `assigned_to` must be passed as sys_ids; only `assignment_group` accepts a display name.
- **The rate limiter is per-process and in-memory.** Several server instances against one account will collectively exceed the configured rate; the 429 handling is the backstop, not the limiter.
- **No streaming or partial results.** A capped call returns its records and a `next_offset`; it does not stream.
- **Only stdio transport is wired up.** The SDK also supports SSE and streamable HTTP; those would need auth and CORS decisions that depend on the deployment.
- **The fake backend implements a useful subset, not all of ServiceNow.** Notably it has no ACL evaluation, no business rules, and a one-hop dotted reference walk.

## License

MIT. Copyright (c) 2026 Kathleen Bartin.
