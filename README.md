# certstream-server-go

A high-performance, self-hostable [Certificate Transparency](https://www.certificate-transparency.org/what-is-ct) log aggregator and streaming server written in Go.

It monitors every active CT log (both classic RFC 6962 logs and newer tiled/Static CT API logs), parses each certificate as it is issued, enriches the data with CA ownership, registered domain extraction, validation type, key type, and certificate type classification, then streams it to connected clients over WebSocket in real time.

This project is a drop-in replacement for [Calidog's certstream-server](https://github.com/CaliDog/certstream-server/), compatible with the same JSON wire format and WebSocket endpoints.

---

## Contents

- [Getting started](#getting-started)
- [Configuration](#configuration)
- [WebSocket endpoints](#websocket-endpoints)
- [Message format](#message-format)
- [Log status dashboard](#log-status-dashboard)
- [CCADB CA owners dashboard](#ccadb-ca-owners-dashboard)
- [Error log dashboard](#error-log-dashboard)
- [Historical dashboard](#historical-dashboard)
- [System stats and bottlenecks](#system-stats-and-bottlenecks)
- [Prometheus metrics](#prometheus-metrics)
- [Recovery and resumption](#recovery-and-resumption)
- [Tiled log support](#tiled-log-support)
- [Certificate enrichment](#certificate-enrichment)
- [Buffer tuning](#buffer-tuning)
- [Scanner tuning](#scanner-tuning)
- [Custom user agent](#custom-user-agent)
- [CLI reference](#cli-reference)
- [Network requirements](#network-requirements)
- [Health checks and reverse proxies](#health-checks-and-reverse-proxies)
- [Client tips](#client-tips)

---

## Getting started

### Binary

Download a precompiled binary from the [Releases](https://github.com/pki-tools/certstream-server-go/releases) page, copy the sample config, and start the server:

```bash
cp config.sample.yaml config.yaml
# edit config.yaml as needed
./certstream-server-go --config config.yaml
```

### Docker

```bash
docker run -d \
  -v /path/to/config.yaml:/app/config.yaml \
  -p 8080:8080 \
  0rickyy0/certstream-server-go
```

> **Note** — if you do not mount a config file, the bundled `config.sample.yaml` is used, which listens on `0.0.0.0:8080` and exposes Prometheus metrics on the same port restricted to `127.0.0.1/8`.

### Build from source

```bash
git clone https://github.com/pki-tools/certstream-server-go.git
cd certstream-server-go
go build ./cmd/certstream-server-go/
```

---

## Configuration

All configuration lives in a single YAML file (`config.yml` by default; override with `--config`).

```yaml
webserver:
  listen_addr: "0.0.0.0"   # IPv6: "::"
  listen_port: 8080
  real_ip: false            # trust X-Forwarded-For from a reverse proxy
  full_url: "/full-stream"
  lite_url: "/"
  domains_only_url: "/domains-only"
  cert_path: ""             # leave empty for plain HTTP
  cert_key_path: ""
  compression_enabled: false
  ui:
    enabled: false          # serve the dashboards on their own port
    listen_addr: ""         # defaults to the websocket listener's interface
    listen_port: 8081
    whitelist: []           # restrict the UI by IP/CIDR

prometheus:
  enabled: true
  listen_addr: "0.0.0.0"
  listen_port: 8080         # can be the same port as the webserver
  metrics_url: "/metrics"
  expose_system_metrics: false
  real_ip: false
  whitelist:
    - "127.0.0.1/8"         # restrict metrics endpoint by IP/CIDR

general:
  disable_default_logs: false   # set true to monitor only your own additional_logs

  # Append logs not in the Google log list (e.g. your own CT log)
  additional_logs:
    - url: "https://ct.example.com/2024/"
      operator: "Example Org"
      description: "Example CT Log 2024"

  # Remove logs that have been retired from the Google log list
  drop_old_logs: true

  buffer_sizes:
    websocket: 150          # per-client send queue (entries)
    ctlog: 50               # internal scanner queue per regular log (entries)
    broadcastmanager: 3000  # central broadcast channel depth (entries)
    certchan: 1000          # internal worker→broadcaster pipeline depth (entries)

  scanner:
    batch_size: 256         # entries per HTTP request for regular logs (max 1000)
    parallel_fetch: 1       # concurrent fetches per regular log (>3 risks rate-limiting)
    num_workers: 1          # parsing goroutines per regular log
    tiled_batch_size: 500   # max entries per 30s tick for tiled logs

  recovery:
    enabled: true
    start_at_head: true     # skip history on first run; resume from saved position thereafter
    ct_index_file: "./ct_index.json"
```

### TLS

Set `cert_path` and `cert_key_path` to enable TLS on the WebSocket server directly. In most deployments a reverse proxy (nginx, Caddy) handles TLS termination instead.

---

## WebSocket endpoints

Connect a WebSocket client to any of the three streaming endpoints. All three streams update in real time as certificates are issued.

| Endpoint (configurable) | Default path | Content |
|---|---|---|
| `full_url` | `/full-stream` | Every certificate with full chain and raw DER |
| `lite_url` | `/` | Every certificate — no `as_der`, no `chain` (smaller payload) |
| `domains_only_url` | `/domains-only` | Domain names only (`dns_entries` message type) |

The server requires a **WebSocket ping at least every 60 seconds** (30 s recommended). If no ping is received within 65 seconds the connection is closed. The server does not send pings to clients.

### Example connection (Go)

```go
conn, _, err := websocket.DefaultDialer.Dial("ws://localhost:8080/", nil)
```

### Live example

Append `/example.json` to any endpoint path to fetch a single cached example via plain HTTP:

```
GET http://localhost:8080/full-stream/example.json
GET http://localhost:8080/example.json
GET http://localhost:8080/domains-only/example.json
```

---

## Message format

### `certificate_update` (full and lite streams)

```json
{
  "message_type": "certificate_update",
  "data": {
    "update_type": "PrecertLogEntry",
    "cert_index": 712420366,
    "cert_link": "https://yeti2024.ct.digicert.com/log/ct/v1/get-entries?start=712420366&end=712420366",
    "seen": 1720000000.123,
    "source": {
      "name": "DigiCert Yeti2024 Log",
      "url": "https://yeti2024.ct.digicert.com/log"
    },
    "leaf_cert": {
      "all_domains": ["example.com", "www.example.com"],
      "all_reg_domains": ["example.com"],
      "as_der": "<base64 DER — full stream only>",
      "ca_owner": "DigiCert",
      "cert_type": "Single",
      "cert_type_ext": {
        "san_count": 2,
        "single_san_count": 2,
        "wildcard_san_count": 0
      },
      "extensions": {
        "authorityInfoAccess": "URI:http://r3.i.lencr.org/, URI:http://r3.o.lencr.org",
        "authorityKeyIdentifier": "keyid:14:2e:...",
        "basicConstraints": "CA:FALSE",
        "certificatePolicies": "Policy: 2.23.140.1.2.1\n",
        "extendedKeyUsage": "...",
        "keyUsage": "Digital Signature, Key Encipherment",
        "subjectAltName": "DNS:example.com, DNS:www.example.com",
        "subjectKeyIdentifier": "keyid:4e:cb:...",
        "ctlPoisonByte": true
      },
      "fingerprint": "27:58:3D:...",
      "sha1": "27:58:3D:...",
      "sha256": "57:61:38:C0:...",
      "is_ca": false,
      "key_type": "RSA2048",
      "not_after": 1735689600,
      "not_before": 1720000000,
      "serial_number": "0498bdf812faf923febd5ef7b374899fc61a",
      "signature_algorithm": "SHA256WithRSA",
      "validation_type": "DV",
      "subject": {
        "CN": "example.com",
        "C": null, "L": null, "O": null, "OU": null, "ST": null,
        "aggregated": "/CN=example.com",
        "email_address": null
      },
      "issuer": {
        "CN": "R3",
        "C": "US", "L": null, "O": "Let's Encrypt", "OU": null, "ST": null,
        "aggregated": "/C=US/CN=R3/O=Let's Encrypt",
        "email_address": null
      }
    },
    "chain": [
      { "...": "intermediate cert fields (full stream only)" }
    ]
  }
}
```

#### Field reference

| Field | Description |
|---|---|
| `update_type` | `X509LogEntry` (end-entity cert) or `PrecertLogEntry` (pre-certificate) |
| `cert_index` | Position of this entry in the CT log |
| `cert_link` | Direct URL to retrieve this entry from the log |
| `seen` | Unix timestamp (millisecond precision) when the server observed this entry |
| `leaf_cert.all_domains` | All SANs plus CN if not already listed |
| `leaf_cert.all_reg_domains` | De-duplicated eTLD+1 registered domains via Public Suffix List |
| `leaf_cert.ca_owner` | Issuing CA organisation name from CCADB (or `"unknown"`) |
| `leaf_cert.cert_type` | `"Single"`, `"Multi"`, or `"Wildcard"` |
| `leaf_cert.cert_type_ext` | SAN counts broken down into total, single, and wildcard |
| `leaf_cert.validation_type` | `"DV"`, `"OV"`, `"EV"`, or `"IV"` |
| `leaf_cert.key_type` | Algorithm and size, e.g. `"RSA2048"`, `"ECDSA256"`, `"Ed25519"` |
| `leaf_cert.as_der` | Base64-encoded raw DER certificate (**full stream only**) |
| `chain` | Array of intermediate certificates (**full stream only**, empty for tiled logs) |
| `extensions.ctlPoisonByte` | `true` for pre-certificates (RFC 6962 §3.1) |

### `dns_entries` (domains-only stream)

```json
{
  "message_type": "dns_entries",
  "data": ["example.com", "www.example.com"]
}
```

---

## Log status dashboard

The server exposes a self-refreshing HTML dashboard at **`/log-status`** (plain HTTP, same port as the WebSocket server).

Every column header is sortable. Numeric columns open descending, so one click on **Behind** or **Tree Size** puts the most interesting rows on top; name columns open ascending. Sorting uses the underlying values rather than the formatted text, so `Pending` tree sizes sort as zero and `Est. Catch-up` orders as longest → shortest → `Live` → unknown. The choice is remembered in the browser, so the two-minute auto-refresh does not reset it.

It shows one row per monitored CT log and updates automatically every 2 minutes:

| Column | Description |
|---|---|
| Operator | Organisation operating the log |
| Log Name | Human-readable log description |
| Type | **Regular** (RFC 6962) or **Tiled** (Static CT API) |
| Current Index | Last certificate position processed by this server |
| Tree Size | Current published tree size from the log (fetched every 3 minutes) |
| Behind | Number of unprocessed entries (`tree_size − current_index`) |
| Rate (e/s) | Recent processing rate in entries per second |
| Est. Catch-up | Estimated time to reach the live head at the current rate |
| Tree Size Age | How long ago the tree size was last fetched |

Colour coding: green = live, amber = minutes behind, red = hours behind.

All data is in-memory only and resets on server restart.

---

## CCADB CA owners dashboard

The server exposes a self-refreshing HTML dashboard at **`/ccadb`** (plain HTTP, same port as the WebSocket server) that lists every CA owner loaded from the CCADB public record.

It shows one row per CA owner and updates automatically every 5 minutes:

| Column | Description |
|---|---|
| CA Owner | Organisation name from the CCADB CA record |
| # CAs | Number of distinct CA certificates belonging to this owner (by Subject Key Identifier) |
| First Seen | UTC timestamp when entries for this owner were first loaded into memory |
| First Seen (relative) | Human-readable age ("2 hours ago", "3 days ago") |

A live-filter search box at the top narrows the table by owner name without a page reload.

The page header shows:
- **Last CCADB refresh** — timestamp and age of the most recent successful CCADB download (refreshed at startup then every 6 hours)
- **Total CAs** — total number of CA key identifiers loaded
- **CA Owners** — number of distinct owning organisations

All data is in-memory only and resets on server restart.

---

## Error log dashboard

The server exposes a self-refreshing HTML dashboard at **`/errors`** (plain HTTP, same port as the WebSocket server) that shows a sliding window of the 500 most-recent errors across all monitored CT logs.

It auto-refreshes every 30 seconds and includes a live-filter search box. When no errors have been recorded since startup, the page shows a "all logs appear healthy" message.

| Column | Description |
|---|---|
| Time (UTC) | Exact timestamp of the error |
| Age | How long ago the error occurred |
| Log | Human-readable log name (hover for full URL) |
| Category | Colour-coded error type badge (see below) |
| Message | The underlying error string |

**Error categories:**

| Category | Colour | Meaning |
|---|---|---|
| `connection` | Red | Network errors, DNS failures, client creation failures |
| `sth` | Amber | Failed to fetch Signed Tree Head from a regular log |
| `checkpoint` | Amber | Failed to fetch checkpoint from a tiled log |
| `parse` | Purple | Certificate or precertificate could not be parsed |
| `scan` | Orange | Scanner-level error during continuous log scanning |
| `tree-size` | Blue | Background tree-size poll failed (used by `/log-status`) |
| `ccadb` | Green | CCADB data download or parse failure |
| `rate-limit` | Outlined red | Log operator returned HTTP 429 or 503 (see below) |
| `backfill` | Indigo | Log had no saved index and is downloading its entire history from index 0 |
| `tile` | Amber | Tiled log served 404 for a tile its checkpoint already covers (see below) |
| `other` | Grey | Unexpected errors not matching the above categories |

The ring buffer holds the last 500 errors in memory and is reset on server restart.

### Throughput diagnosis

The page opens with a diagnosis panel answering the usual question: *why is this log falling behind?*

Rate limiting is otherwise invisible. `certificate-transparency-go` retries HTTP 429 inside `jsonclient` (honouring `Retry-After`) and again inside `scanner.fetcher`'s own backoff loop, which retries indefinitely and logs only at klog verbosity 2. A throttled log therefore never produces a scan error — it just quietly stalls. To catch this, the server instruments its HTTP transport *below* both retry layers, so every 429/503 is counted regardless of how the library handles it.

Because a heavily throttled log could otherwise evict every other error from the 500-entry window, ring-buffer notes are throttled to one per log per 30 seconds. Exact counts are kept separately and shown in the panel's table.

Reading the verdict:

| Verdict | Meaning | Action |
|---|---|---|
| **Backfilling from index 0** | Logs with no saved index are downloading their entire history. Indistinguishable from falling behind on `/log-status`, but it is a cold start working through a fixed backlog | Expected after deleting `ct_index.json` or when a new log shard appears. Set `recovery.start_at_head: true` to start these live instead |
| **Rate limiting detected** | The operator is throttling you | **Lower** `parallel_fetch` for those logs. Raising it — or hitting Catch Up — earns more throttling and makes the backlog worse |
| **Pipeline is backed up** | Fetching outpaces processing; the entry channel is over half full | Bottleneck is downstream (CPU, JSON encoding, slow WebSocket clients). More connections will not help. Raise `buffer_sizes.certchan`, check CPU headroom |
| **Keeping up, no throttling** | Neither limit is being hit | Fetch rate is simply too low. Raise `scanner.batch_size` toward 1000 and `parallel_fetch` to 2–3, then re-check this page for throttling |

### Tiled logs: 404 on a tile

Static CT logs sign and publish a checkpoint before every data tile behind it is necessarily being served by their CDN, so a tile the advertised tree size already covers can briefly return 404 — reported as `tile/data/x456/118: unexpected status code 404`.

The client library retries 429 and 5xx internally but treats any other non-200 as fatal, so without special handling one transient 404 tore down the whole log worker: dropping its tile cache, sleeping, and re-fetching the checkpoint over a condition that clears on its own within seconds.

These are now recognised, logged under the `tile` category (throttled to one note per log per five minutes so they cannot flood the window), and retried on the next poll with progress kept. Occasional entries are normal and harmless. A log producing them continuously while its **Behind** count does not fall is a genuine problem worth raising with the operator.

Note that `batch_size` cannot exceed 1000 for regular logs — RFC 6962 §4.6 caps `get-entries` server-side, so requesting more returns at most 1000 anyway.

The instrumented transport also raises the idle connection pool to 20 per host. Go's default is 2, so with `parallel_fetch` above 2 the surplus connections were previously torn down and re-handshaked on every batch.

---

## Historical dashboard

`/log-status`, `/ccadb` and `/errors` all show the *current* moment. The historical dashboard at **`/dashboard`** adds the time dimension: it periodically snapshots log state into a local SQLite database and charts it over selectable windows, covering the cases that would otherwise require a full Prometheus + Grafana deployment.

It is **disabled by default**. Enable it in config:

```yaml
general:
  dashboard:
    enabled: true
    db_path: "./dashboard.db"
    sample_interval: 60
    retention_days: 7
```

| Option | Default | Description |
|---|---|---|
| `enabled` | `false` | Turns the endpoint and background sampler on |
| `db_path` | `./dashboard.db` | SQLite file used to persist samples |
| `sample_interval` | `60` | Seconds between snapshots |
| `retention_days` | `7` | How long samples are kept before hourly pruning |

**Time ranges:** 1 hour, 12 hours, 24 hours, 3 days, 7 days. Switching range re-queries the server without reloading the page. Each range is downsampled to roughly 120 points, so a 7-day chart is as responsive as a 1-hour one.

**Charts and figures:**

| Panel | Description |
|---|---|
| Ingestion rate | Certificates + precertificates per second, derived from the cumulative counters |
| Total backlog | Entries behind, summed across all logs |
| Backlog by log | Backlog history for the five logs currently furthest behind |
| Log health | Logs caught up vs. logs behind, over time |
| Connected clients | WebSocket subscribers stacked by stream type (full / lite / domains-only) |
| Fastest logs | Current entries per second, ranked |
| Certificates processed | Cumulative growth curve over the window |
| Certificates vs precertificates | Entries per second split by type |
| Published vs ingested | What CT publishes across all logs, against what this server consumes |
| Share of ingestion by operator | Percentage of the current entry stream, per operator |
| Share of ingestion by log | Percentage of the current entry stream, per log |
| Logs furthest behind | Table of current state with behind count, rate and estimated catch-up |

Both share charts keep the top eight slices and fold the remainder into **Other**, so the percentages always total 100% rather than silently dropping the tail.

**Published vs ingested** is the clearest read on whether this server is keeping up globally. The published figure comes from summing every log's tree size and differencing it over time. A bucket is only compared against its predecessor when the same number of logs reported a tree size in both, because the total also jumps whenever a log is polled for the first time — without that guard, startup would register as millions of entries per second.

Headline tiles show current/peak/average rate, certificates seen in the window, total backlog, live-vs-total log counts, connected clients, lifetime processed count, CT-wide publish rate, precertificate share, the busiest operator, combined size of all known logs with the percentage consumed, and the regular-vs-tiled log split.

**Notes:**

- The database is opened once at startup. If it cannot be opened the dashboard is disabled and the server continues streaming normally — certificate delivery never depends on it.
- Data persists across restarts. Rate is derived from counter deltas and correctly ignores the reset that a restart causes, so restarts leave a gap rather than a false spike.
- WAL mode is used, so `dashboard.db-wal` and `dashboard.db-shm` appear alongside the database file. Ensure the process has write permission on the directory, not just the file.
- Sizing: roughly 100 logs at a 60-second interval over 7 days is about 50–80 MB. Raise `sample_interval` or lower `retention_days` to shrink it.
- SQLite is accessed through a pure-Go driver, so `CGO_ENABLED=0` static builds and the Alpine Docker image continue to work unchanged.

---

## System stats and bottlenecks

**`/system`** answers a question the other pages cannot: when the server is not keeping up, is it limited by *downloading* certificates or by *processing* them?

### How the bottleneck is identified

Entries flow through a fixed pipeline:

```
per-log fetchers → entry channel → certHandler → broadcast channel → broadcaster → clients
```

`certHandler` sits between the two buffers, so timing how long it waits at each end pins down the constraint without attaching a profiler:

| Where the time goes | Meaning | What to change |
|---|---|---|
| **Waiting for certificates** | The handler is starved — downloading is the limit | `scanner.batch_size`, `parallel_fetch`; check `/errors` for throttling |
| **Blocked sending downstream** | JSON encoding and client fan-out cannot keep up — **processing** is the limit | Fewer/faster clients, prefer the lite stream, more CPU |
| **Own work** | The handler is CPU-bound itself | A hard ceiling: this is one goroutine fanning out every certificate |

The page shows this split as a bar, with a plain-language verdict. It reads the delta over the sampled window rather than cumulative totals, so it reflects current conditions rather than being dominated by startup. Sampling costs about 100 ns per certificate — negligible beside the parsing and encoding on either side.

### Queues

Both pipeline buffers are shown with their fill level. A queue sitting near capacity is where work is backing up:

- **Entry channel** (`buffer_sizes.certchan`) full → the handler cannot keep up with downloads
- **Broadcast channel** (`buffer_sizes.broadcastmanager`) full → encoding and fan-out cannot keep up

Raising a buffer that is persistently full defers the problem rather than fixing it; it only helps absorb bursts.

### Other figures

Throughput (with sparkline), process CPU as a percentage of one core plus the share spent in GC, goroutine count and window peak, heap in use and GC cycles, certificates and precertificates processed, connected clients by stream type, certificates skipped for slow clients, and total 429/503 responses from log operators. A breakdown of the error ring by category links through to `/errors`.

CPU figures come from `runtime/metrics` and are omitted rather than guessed at on platforms that do not report them.

---

## Prometheus metrics

Enable the metrics endpoint in config (`prometheus.enabled: true`). By default it is exposed at `/metrics` and restricted by IP whitelist.

| Metric | Type | Description |
|---|---|---|
| `certstreamservergo_clients_total{type="full\|lite\|domain"}` | Gauge | Currently connected WebSocket clients by stream type |
| `certstreamservergo_certificates_total{type="regular\|precert"}` | Gauge | Cumulative certificates processed since startup |
| `certstreamservergo_certs_by_log_total{url, operator}` | Gauge | Certificates processed per CT log |
| `certstreamservergo_skipped_certs{client}` | Counter | Certificates dropped for a slow client (buffer full) |

The metrics endpoint can share the same port as the WebSocket server, or run on a separate port and interface for isolation.

---

## Recovery and resumption

When `recovery.enabled` is true the server persists the last-processed certificate index for every log to `ct_index_file` (default `./ct_index.json`) every 30 seconds and on graceful shutdown. On restart, each log worker resumes from its saved index rather than replaying from the beginning.

```yaml
recovery:
  enabled: true
  start_at_head: true      # recommended for new deployments
  ct_index_file: "./ct_index.json"
```

**`start_at_head`** — on first run (or for any log with no saved index), start from the current live tree size rather than index 0. This avoids downloading years of historical certificates. On subsequent restarts, the saved index is used normally for catch-up. Requires `enabled: true` (auto-enabled if not set).

### Creating an index file manually

To pre-seed the index file at current live positions without starting the streaming server:

```bash
./certstream-server-go --create-index-file --config config.yaml
```

This fetches the current STH from every log, writes `ct_index.json`, and exits. Useful before enabling a new deployment that should only stream future certificates.

---

## Tiled log support

The server monitors both log types transparently:

| Type | Spec | Transport |
|---|---|---|
| **Regular** | RFC 6962 | `GET /ct/v1/get-entries` batch scanner |
| **Tiled** | Static CT API (sunlight) | Tile-based iterator with signature verification |

Tiled logs are discovered automatically from the Google log list alongside regular logs. Their workers use verified checkpoint fetches (public key from the log list) and process entries in batches of up to 500 per 30-second polling cycle to avoid unbounded catch-up spikes. Chain data is not available for tiled log entries; `chain` is returned as an empty array for those certificates.

---

## Certificate enrichment

Beyond raw CT log data, the server enriches every certificate with:

### CA Owner (CCADB)

At startup and every 6 hours, the server downloads the [CCADB public CA list](https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv4) and builds an Authority Key Identifier → CA Owner mapping. The `leaf_cert.ca_owner` field reflects the publishing CA organisation for every certificate.

### Registered domains (`all_reg_domains`)

Each SAN is resolved to its eTLD+1 registered domain using the [Public Suffix List](https://publicsuffix.org/). Duplicates are removed. IP addresses are passed through as-is. This field makes it straightforward to bucket certificates by the root domain being protected without parsing each SAN yourself.

### Validation type

Determined from certificate policy OIDs and subject fields:

| Value | Meaning |
|---|---|
| `DV` | Domain Validated (no Organisation in subject, or OID `2.23.140.1.2.1`) |
| `OV` | Organisation Validated (OID `2.23.140.1.2.2`, default) |
| `EV` | Extended Validation (OID `2.23.140.1.1` or jurisdiction field present) |
| `IV` | Individual Validated (OID `2.23.140.1.2.3`) |

### Certificate type

| Value | Condition |
|---|---|
| `Single` | 1–2 SANs, no wildcards |
| `Multi` | 3+ SANs, no wildcards |
| `Wildcard` | At least one wildcard SAN |

`cert_type_ext` provides exact counts: `san_count`, `single_san_count`, `wildcard_san_count`.

### Key type

Returns the algorithm and key size as a compact string: `RSA2048`, `RSA4096`, `ECDSA256`, `ECDSA384`, `Ed25519`, etc.

---

## Buffer tuning

The server pipelines certificate data through several in-memory channels. Each buffer trades memory for throughput headroom. Values that are too large waste RAM (and contribute to OOM kills during catch-up bursts); values that are too small cause entries to be dropped when processing temporarily lags.

| Config key | Default | What it controls |
|---|---|---|
| `buffer_sizes.ctlog` | `50` | Internal scanner queue per regular-log worker. Multiplied by the number of regular logs — keep this small. |
| `buffer_sizes.certchan` | `1000` | Pipeline from all workers to the broadcaster. Shared across all logs. |
| `buffer_sizes.broadcastmanager` | `3000` | Channel from the broadcaster pipeline to the JSON encoder/dispatcher. |
| `buffer_sizes.websocket` | `150` | Per-client send queue. Entries are dropped (and counted in `skipped_certs`) when a client can't drain this fast enough. |

**Recommended values for a typical deployment** (50+ logs, moderate client count):

```yaml
buffer_sizes:
  ctlog: 50
  certchan: 1000
  broadcastmanager: 3000
  websocket: 150
```

Reduce `websocket` further if you have many slow clients. Increase `certchan` / `broadcastmanager` if you see high `skipped_certs` metrics on the server itself (as opposed to on individual clients).

---

## Scanner tuning

These settings control how aggressively the server fetches entries from CT logs. They are the primary levers for reducing catch-up time after the server has been offline or when a new log is added.

| Config key | Default | What it controls |
|---|---|---|
| `scanner.batch_size` | `256` | Entries fetched per HTTP `get-entries` request for regular (RFC 6962) logs. The CT spec allows up to **1000**. A larger value means fewer round-trips during catch-up. |
| `scanner.parallel_fetch` | `1` | Concurrent `get-entries` requests per regular log. Increasing to `2` roughly doubles catch-up throughput; values above `3` risk 429 rate-limiting from log operators. |
| `scanner.num_workers` | `1` | Certificate parsing goroutines per regular log. Rarely the bottleneck — network is. |
| `scanner.tiled_batch_size` | `500` | Maximum entries processed per 30-second polling tick for tiled (sunlight) logs. Caps catch-up speed to prevent memory spikes from a single tiled log flooding the pipeline. |

**For faster catch-up** (if the server has been offline or is significantly behind):

```yaml
scanner:
  batch_size: 1000
  parallel_fetch: 2
  num_workers: 1
  tiled_batch_size: 2000
```

**Conservative defaults** (prioritise stability and memory over catch-up speed):

```yaml
scanner:
  batch_size: 256
  parallel_fetch: 1
  num_workers: 1
  tiled_batch_size: 500
```

Note: when running with many logs simultaneously, `parallel_fetch: 2` means up to ~100 concurrent outbound HTTP connections (50 logs × 2). Ensure the host OS and any upstream firewall allow this.

---

## Custom user agent

To use a custom HTTP User-Agent when connecting to CT logs, create a file named `certstream-ua` in the same directory as the binary containing the desired UA string (one line, no trailing newline required). The server reads this at startup. If the file is absent or empty, the default UA is used:

```
Certstream Server v1.x.x (github.com/pki-tools/certstream-server-go)
```

---

## CLI reference

```
certstream-server-go [flags]

Flags:
  --config string            Path to the config file (default "config.yml")
  --version                  Print version and exit
  --create-index-file        Write ct_index.json from current log STHs and exit
```

---

## Network requirements

### Outbound

The server makes outbound HTTPS connections to:

- `www.gstatic.com` — Google CT log list (`log_list.json`)
- All CT log operators — typically DigiCert, Google, Cloudflare, Sectigo, Let's Encrypt, and others
- `ccadb.my.salesforce-sites.com` — CCADB CA owner data

### Inbound

- `webserver.listen_port` — WebSocket clients, `/health`, and (unless split off) the `/log-status`, `/ccadb`, `/errors`, `/system` and `/dashboard` pages
- `webserver.ui.listen_port` — the dashboards, `/system` and `/health`, when `webserver.ui.enabled` is set
- `prometheus.listen_port` — Prometheus scraping (can be the same port as above)

---

## Health checks and reverse proxies

The WebSocket endpoints answer plain HTTP requests with **426 Upgrade Required**. That is correct — they genuinely require an upgrade — but most load balancer health checks, including HAProxy's `option httpchk`, treat anything outside 2xx/3xx as a failure and take the backend out of rotation.

**`/health` is registered on every listener** and always returns 200 with a small JSON body:

```json
{"status":"ok","version":"1.9.7","uptimeSeconds":3600,"logsMonitored":92,"certificates":4820113006,"precertificates":5901224418}
```

It reports `ok` whenever the process is serving. This is deliberate: tying the status to whether logs are keeping up would pull the server out of rotation during a backlog, when it is still perfectly capable of serving clients. Use `/log-status` or `/dashboard` to judge ingestion health.

```haproxy
backend certstream_ws
    option httpchk GET /health
    http-check expect status 200
    timeout tunnel 1h
    server cs1 10.0.0.5:8080 check
```

### Splitting the web UI onto its own port

WebSocket and HTTP backends want different proxy settings — the former needs long tunnel timeouts, the latter short ones. Setting `webserver.ui.enabled` moves the dashboards to a separate listener so each can be configured independently:

```yaml
webserver:
  listen_addr: "0.0.0.0"
  listen_port: 8080        # websockets + /health
  ui:
    enabled: true
    listen_port: 8081      # dashboards + /health
    whitelist:
      - "10.0.0.0/8"       # keep the UI off the public internet
```

With this set, `/log-status` and friends return 404 on the websocket port, and the websocket endpoints return 404 on the UI port. `listen_addr` defaults to the websocket listener's interface. If the UI is pointed at the address and port already serving websockets, the setting is ignored and everything stays on one listener rather than failing to bind.

---

## Client tips

### Choose the right endpoint

| Use case | Endpoint |
|---|---|
| Full certificate analysis (chain, DER) | `/full-stream` |
| Domain monitoring, phishing detection | `/` (lite) |
| DNS-only pipelines | `/domains-only` |

The lite stream is typically 3–5× smaller per message than the full stream. If your client does not use `as_der` or `chain`, always prefer the lite endpoint.

### Keep up with the stream

The server drops entries for a client whose send buffer (`buffer_sizes.websocket`) fills up. The `certstreamservergo_skipped_certs` Prometheus metric and the server log show when this is happening.

To avoid drops:

- **Separate reading from processing.** Read from the WebSocket in a tight loop into a local buffered channel; process from a separate goroutine pool. Never do database writes or HTTP calls inline on the read loop.
- **Acknowledge pings promptly.** A missed ping closes the connection after 65 seconds.
- **Use the domains-only endpoint** if your downstream pipeline only needs SANs.

### Ping interval

Send a WebSocket ping every **30 seconds**. The server closes connections that do not send a ping within 65 seconds.
