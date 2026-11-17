# Toolkit layer — skills & tools added on top of upstream ARTEX

This fork adds three things on top of `jiwoochris/artex-global`. Nothing upstream is modified;
everything here is additive and can be removed by deleting the listed paths.

| Addition | Path | Why |
| --- | --- | --- |
| 30 vulnerability playbooks | `skills/<class>/SKILL.md` | Upstream ships only 3 skills (`api-recon`, `playwright-cli`, `scopesentry`). Exploitation procedure lived entirely in prompts. |
| CVE chaining skill | `skills/cve-chain/SKILL.md` | No CVE database or exploit chain in upstream — this adds the procedure and the queries. |
| Indonesian report skill | `skills/laporan-id/SKILL.md` | Upstream UI/report languages are en/ko/zh/es/ja. |
| Pentest tool layer | `docker/Dockerfile.tools`, `docker/tools-compose.yml` | Upstream image has nmap/whois/dig/nc only: no nuclei, sqlmap, ffuf, interactsh, jwt_tool. |

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

## Not changed

- `agent/`, `server/`, `db/` — untouched; no behaviour change to planner/worker/gate.
- No SARIF exporter yet. Upstream writes findings to PostgreSQL and its own report format.
  Strix's `strix/report/sarif.py` is the reference if that gets ported (`findings.sarif` is what
  auditors can import today from the Strix runs).
- No multi-language beyond upstream's en/ko/zh/es/ja; Indonesian output comes from `laporan-id`.
