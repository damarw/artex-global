# Generic web-attack detection rules

Sigma rules for the attack *patterns* that recur in government web estates — not tool
fingerprints. They complement the ARTEX-specific rules in [`..`](..) and the behaviour guide in
[`docs/defense-en.md`](../../../docs/defense-en.md).

Each rule was written from a finding we actually produced on an authorized target: identifier
walking on a property-tax portal, a captcha-protected lookup whose document endpoints were
unprotected, admin logins with no throttle, a polyglot upload served inline from the portal origin,
debug consoles left in production, an origin reachable around the CDN, and an OAuth token endpoint
that issued credentials without a client secret.

Field names follow the Sigma web-server convention (`cs-method`, `cs-uri-stem`, `cs-uri-query`,
`sc-status`, `c-ip`, `cs-host`, `c-useragent`). Map them to your own stack when converting, and
keep the `condition` semantics of the correlation rules — a single hit is noise, a ratio is signal.

## Rules

| Rule | Level | Detects |
| --- | --- | --- |
| [`web_sequential_object_enumeration.yml`](web_sequential_object_enumeration.yml) | high | Sequential Object Identifier Enumeration (IDOR / Register Walking) |
| [`web_path_traversal_probe.yml`](web_path_traversal_probe.yml) | high | Path Traversal / LFI Probing in URI or Query |
| [`web_sql_injection_strings.yml`](web_sql_injection_strings.yml) | high | SQL Injection / NoSQL Injection Payload Strings in Request |
| [`web_xss_payload_strings.yml`](web_xss_payload_strings.yml) | medium | XSS / HTML Injection Payload Strings in Request |
| [`web_sensitive_file_probe.yml`](web_sensitive_file_probe.yml) | medium | Sensitive File / Backup / Repository Metadata Probe |
| [`web_ssrf_inbound_url_parameters.yml`](web_ssrf_inbound_url_parameters.yml) | high | SSRF — private/metadata address in a URL parameter |
| [`web_xxe_xml_payload.yml`](web_xxe_xml_payload.yml) | high | XXE — DOCTYPE / external entity in submitted XML |
| [`web_state_change_without_csrf_controls.yml`](web_state_change_without_csrf_controls.yml) | low | State-changing request without CSRF token or same-origin Referer |
| [`web_document_generator_captcha_bypass.yml`](web_document_generator_captcha_bypass.yml) | high | Document Generator Hit Without Captcha Session (Captcha Bypass Pattern) |
| [`web_admin_login_bruteforce.yml`](web_admin_login_bruteforce.yml) | high | Unthrottled Administrative Login Brute Force |
| [`web_upload_then_html_access.yml`](web_upload_then_html_access.yml) | high | Upload Followed by Direct Access to Executable Content (Polyglot Upload) |
| [`web_debug_console_and_telemetry_probe.yml`](web_debug_console_and_telemetry_probe.yml) | medium | Debug Console / Telemetry Endpoint Probing (Telescope, Actuator, pprof) |
| [`web_origin_bypass_host_mismatch.yml`](web_origin_bypass_host_mismatch.yml) | medium | Origin Bypass Attempt — Public Host Header Reaching Origin Directly |
| [`sso_oauth_token_client_credentials_without_secret.yml`](sso_oauth_token_client_credentials_without_secret.yml) | high | OAuth2 Token Issued for client_credentials Without Client Secret |
| [`web_scanner_signature_user_agents.yml`](web_scanner_signature_user_agents.yml) | low | Offensive Scanner User-Agent or Default Tool Fingerprint |

## Tuning

Counts and windows are starting points, not truths. Measure your own baseline for a week before
enabling a correlation rule at alert level — a rule nobody tunes gets muted, and a muted rule is
worse than no rule.

Two rules need environment input before they are useful:

- `web_origin_bypass_host_mismatch.yml` — fill in the origin addresses and the CDN ranges.
- `web_document_generator_captcha_bypass.yml` — point it at your own captcha route and document
  path prefix, and keep the ratio condition (documents without captcha), not the raw count.
