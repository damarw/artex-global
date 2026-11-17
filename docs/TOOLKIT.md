# Toolkit layer — skills & tools added on top of upstream ARTEX

This fork adds three things on top of `jiwoochris/artex-global`. Nothing upstream is modified;
everything here is additive and can be removed by deleting the listed paths.

| Addition | Path | Why |
| --- | --- | --- |
| 30 vulnerability playbooks | `skills/<class>/SKILL.md` | Upstream ships only 3 skills (`api-recon`, `playwright-cli`, `scopesentry`). Exploitation procedure lived entirely in prompts. |
| CVE chaining skill | `skills/cve-chain/SKILL.md` | No CVE database or exploit chain in upstream — this adds the procedure and the queries. |
| Indonesian report skill | `skills/laporan-id/SKILL.md` | Upstream UI/report languages are en/ko/zh/es/ja. |
| Pentest tool layer | `docker/Dockerfile.tools`, `docker/tools-compose.yml` | Upstream image has nmap/whois/dig/nc only: no nuclei, sqlmap, ffuf, interactsh, jwt_tool. |
| SARIF 2.1.0 export | `report/sarif.go`, `server/server.go` | Findings could leave as Markdown/CSV/JSON only; auditors and CI dashboards import SARIF. |
| Generic web-attack detections | `detections/sigma/web-attack-generic/` | The 9 built-in Sigma rules describe ARTEX's own behaviour, not the attack patterns found in real estates. |

## Skills

Skills are mounted from `./skills`, so editing one takes effect without rebuilding the image
(`docker compose restart artex` is enough).

Vulnerability classes added: `agentic-system-security`, `argument-injection`, `authentication-jwt`,
`broken-function-level-authorization`, `browser-security`, `business-logic`, `csrf`,
`header-injection`, `http-request-smuggling`, `idor`, `information-disclosure`,
`insecure-deserialization`, `insecure-file-uploads`, `llm-prompt-injection`, `mass-assignment`,
`nosql-injection`, `open-redirect`, `path-traversal-lfi-rfi`, `prototype-pollution`,
`query-language-injection`, `race-conditions`, `rce`, `semantic-confusion`, `sql-injection`, `ssrf`,
`ssti`, `subdomain-takeover`, `weak-password-detection`, `xss`, `xxe`.

Each carries an appended **Evidence discipline** section that is stricter than the upstream prompts:

- a payload that "looks" injectable is not a finding;
- every ruled-out class needs a positive control proving the probe could have detected it;
- baseline status/length/timing recorded before payloads;
- CVE/version matching may not substitute for a real trigger (mark `inferred` instead);
- re-trigger through a different path before filing;
- stop at one record — no bulk harvesting, no writes to real data;
- bind the raw traffic entry or paste the command output.

Playbooks originate from the Strix project (`github.com/usestrix/strix`, Apache-2.0) and are
redistributed here under this repository's AGPL-3.0 with attribution kept in each file.
Compatibility: Apache-2.0 → AGPL-3.0 is a permitted direction; the attribution notice must stay.

### `cve-chain`

Fingerprint → candidate lookup (NVD REST, CIRCL, GitHub Advisories) → reachability → minimal trigger
with positive control → write-up. Includes the hard-won PHP-FPM / php2shell constraints
(CVE-2026-109618) so the next agent does not rediscover them the painful way:

1. OOM after RINIT does not kill the worker (`socket: CLOSED` ≠ dead process);
2. the producer primitive needs `session_start()` only — no APP_KEY;
3. the chain can transfer to FPM, with primitives different from the public lab;
4. RCE reached in lab on PHP 8.1.33 FPM, not in production when the app does not use native sessions;
5. therefore report OOM/DoS separately and treat RCE as lab-proven / production-blocked, naming the
   blocking mechanism.

### `laporan-id`

Fixed structure for government hand-over reports: summary table → glossary → scope → per-finding
(four fixed sections) → what held up → staged recommendations → what was not tested → cleanup notes.
Rules: severity from demonstrated consequence (not CVE score), PII masked from the start, "reachable"
never described as "already leaked", tool limits stated, no credentials anywhere in the document.

## Tool layer

```bash
cp .env.example .env        # set POSTGRES_PASSWORD, ARTEX_LLM_BASE_URL, ARTEX_ADMIN_PASSWORD
docker compose -f docker-compose.yml -f docker/tools-compose.yml up -d --build
```

Adds to the runtime: `nuclei` (with templates baked in), `sqlmap`, `ffuf`, `httpx`,
`interactsh-client`, `jwt_tool`. Versions are pinned by build args in `docker/Dockerfile.tools`;
override with `--build-arg` when you need a newer release.

Point ARTEX at an OpenAI-compatible gateway (a local relay, for example) rather than a per-token
provider when you want the whole estate to share one quota:

```bash
ARTEX_LLM_PROVIDER=openai
ARTEX_LLM_BASE_URL=http://127.0.0.1:20200/v1
ARTEX_LLM_MODEL=ocg/deepseek-v4.1-flash
```

## SARIF export

`GET /api/exploration/findings/export?format=sarif` (same `scope`/`ids`/filter parameters as the other
formats) returns a SARIF 2.1.0 log:

- one rule per vulnerability class, id normalised to `artex/<class-slug>` (`SQL Injection` and
  `sql_injection` collapse to the same rule);
- severity mapping: `critical|high` → `error`, `medium` → `warning`, `low|unknown` → `note`;
- results are severity-ordered and carry `properties` with `severity`, `findingId`, `status`,
  `worker`, `taskId`, `assetIds` and the evidence text (truncated at 4 000 chars — the full
  evidence stays in the evidence store / `md-zip` export);
- no `locations` are emitted: a finding references internal asset ids, not URLs, and a fabricated
  URI would be worse than no location.

Verified with `go test ./report/ -run SARIF` (shape, level mapping, rule de-duplication, ordering)
and `go build ./... && go vet ./report/ ./server/` on Go 1.26.3.

## Deep mode: `deeptool` + `deepctl`

Exploitation above detection is gated by `deeptool` (`docker/deeptool`, installed at
`/usr/local/bin/deeptool`). It is **off by default**, expiring, budgeted, recorded, and stoppable.

```bash
deeptool enable --level 2 --ttl 30m --max-attempts 20 --per-key 2
deeptool run --key idor-001 -- curl -s -o /tmp/p1.json -w '%{http_code}' 'https://target/x?id=1'
deeptool record -- nmap -sV target       # L0/L1, recorded, no enable needed
deeptool log --tail 20                   # audit trail
deeptool stop                            # kill switch (sets STOP file)
deeptool serve --port 8790               # browser buttons
```

Levels: **L2** proof-of-read, **L3** controlled impact on a synthetic record, **L4** post-exploitation
(lab only). Every invocation — executed or refused, with the reason — is appended to
`$DEEP_DIR/audit.jsonl` with timestamp, level, hypothesis key, command, exit code and duration.

Client policy, enforced by the blocklist:

| Allowed | Blocked |
| --- | --- |
| account creation | DROP / TRUNCATE / unbounded DELETE or UPDATE |
| RCE, command execution, shell (prove then close) | encryption (`openssl enc`, `gpg --symmetric`), wiping (`shred`, `wipe`) |
| one record read (L2), one synthetic write (L3) | file deletion, account deletion, service stop |
| ordinary recon and detection | persistence (cron, systemd, ssh keys, web shells) |
| creating test accounts | mass collection (`{1..n}`, `seq` loops, parallel bulk, masscan, wfuzz), brute force |

`deepctl` is the button panel (compose service, `127.0.0.1:8790`): **Aktifkan L2/L3/L4**, **Matikan**,
**HENTIKAN SEKARANG**. STOP sets the STOP file, so every later L2+ call is refused immediately —
including from a task already running. A token (`DEEP_TOKEN`) is required; the panel prints it on
start if unset.

## Tools

Base image (upstream) has `nmap`, `whois`, `dig`, `netcat`, `telnet`, Playwright/Chromium.

Added by `docker/Dockerfile.tools`:

| Tool | Purpose | Verified in image |
| --- | --- | --- |
| `nuclei` 3.11.1 + 14 225 templates | CVE / misconfiguration templates | `nuclei -version` |
| `sqlmap` 1.10 | prove SQLi (boolean, time-based, union) | `sqlmap --version` |
| `ffuf` 2.3.0 | path / parameter discovery | `ffuf -V` |
| `httpx` 1.12.0 | fast HTTP probing, inventory | `httpx -version` |
| `interactsh-client` 1.4.1 | out-of-band proof (SSRF/XXE/RCE blind) | banner |
| `jwt_tool` | JWT forgery/analysis (alg confusion, HS256 secret) | `jwt_tool -h` |
| `searchsploit` (Exploit-DB mirror) | offline public-PoC lookup per product/version | `searchsploit --cve 2021-44228` → 3 hits |
| `katana` 1.8.0 | JS-aware crawler | `katana -version` |
| `dalfox` 3.3.0 | XSS scanning + DOM verification | `dalfox --version` |
| Metasploit 6.5.11 | module-driven check/exploit, driven via `msfconsole -r` | `msfconsole -v` |

Build: `docker build -f docker/Dockerfile.tools -t artex-global-tools:deep .` (5.02 GB with MSF;
`--build-arg INSTALL_MSF=0` skips it and drops most of the weight).

## Detection rules

`detections/sigma/web-attack-generic/` holds 11 Sigma rules for attack *patterns* rather than tool
fingerprints: identifier walking, traversal payloads, injection tokens, sensitive-file probing,
document-generator access without a captcha session, unthrottled admin login, upload-then-HTML
access, debug-console probing, origin bypass by Host mismatch, OAuth `client_credentials` without a
secret, and scanner User-Agents. Each rule records the finding it came from and what must be tuned
before enabling.

## Not changed

- `agent/`, `db/` — untouched. `server/server.go` gains exactly one `case "sarif"` branch in the
  existing findings export handler; no other server behaviour changes.
- No multi-language beyond upstream's en/ko/zh/es/ja; Indonesian output comes from `laporan-id`.
  The UI stays English for now.
