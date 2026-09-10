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
- [Prometheus metrics](#prometheus-metrics)
- [Recovery and resumption](#recovery-and-resumption)
- [Tiled log support](#tiled-log-support)
- [Certificate enrichment](#certificate-enrichment)
- [Buffer tuning](#buffer-tuning)
- [Scanner tuning](#scanner-tuning)
- [Custom user agent](#custom-user-agent)
- [CLI reference](#cli-reference)
- [Network requirements](#network-requirements)
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

- `webserver.listen_port` — WebSocket clients, `/log-status` dashboard, and `/ccadb` dashboard
- `prometheus.listen_port` — Prometheus scraping (can be the same port as above)

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
