# Threat model

Scope: the ShadowTrace application (API, worker, engine, frontend), its data, and the
targets it scans. Method: assets → actors → STRIDE per component → abuse cases → controls →
tests. Every row names the control that mitigates it and the test that proves it.

## 1. Assets

| ID | Asset | Why it matters |
|---|---|---|
| A1 | Scanned target availability | A scanner that hammers or mutates a target causes real damage |
| A2 | Third-party systems | The scanner must never be usable as an SSRF/attack proxy |
| A3 | Findings and evidence | Contain sensitive routes, banners, sometimes secrets |
| A4 | Credentials and sessions | Account takeover would expose every target's data |
| A5 | Tenant data | Organizations must never see each other's targets/scans |
| A6 | Audit trail | Must be trustworthy to reconstruct who scanned what |
| A7 | Availability of ShadowTrace itself | Resource exhaustion through scans/uploads |

## 2. Actors

| Actor | Capability |
|---|---|
| Anonymous internet user | Can reach the login page and public health endpoint only |
| Authenticated viewer | Read-only access to own organization's data |
| Authenticated analyst | Create targets/scans, triage findings |
| Organization admin | Manage users, approve targets, delete scans, read audit log |
| Analyst | Register targets, run scans, triage findings, verify *ownership-mode* targets. Cannot approve anything, and cannot move an approved target to a new origin and keep the approval |
| Operator | Deploy, configure limits, run the kill switch, seed the demo account |
| **Hostile target** | Controls everything the scanner will parse: HTML, JS, specs, XML, headers |
| **Malicious tenant** | Tries to read other organizations' data or escalate role |
| **Attacker using the product** | Tries to turn ShadowTrace into a request proxy |

## 3. STRIDE by component

### 3.1 Authentication and sessions (`app/security/auth.py`)

| Threat | Control | Test |
|---|---|---|
| Spoofing: credential stuffing | Per-IP and per-account sliding windows (20/5 min, 10/5 min) | `test_auth_flow.py::test_login_rate_limit_per_account` |
| Spoofing: session fixation | Session token rotated on login; every prior session revoked | `test_auth_flow.py::test_logout_revokes_the_session` |
| Information disclosure: user enumeration | Identical error and message for unknown user and wrong password; constant-cost verify | `test_auth_flow.py::test_login_failures_do_not_reveal_account_existence` |
| Tampering: CSRF | `X-CSRF-Token` must equal the session's token; Origin checked when present; `SameSite=strict` | `test_auth_flow.py::test_csrf_header_is_required_for_state_changes`, `test_cross_origin_state_change_is_rejected` |
| Elevation: role change without re-auth | Role change revokes the victim's sessions; self-demotion refused; last admin protected | `test_auth_flow.py::test_admin_user_management_guards` |
| Repudiation | Append-only audit log with triggers rejecting UPDATE/DELETE | `test_security_helpers.py`, `test_auth_flow.py::test_login_is_audited_without_secrets` |

### 3.2 Authorization (`app/api/deps.py`, every router)

| Threat | Control | Test |
|---|---|---|
| Elevation of privilege | `ROUTE_POLICY` maps every route to a minimum role; `policy_guard` enforces it before body parsing; unknown route in the map fails closed | `test_api_authz.py::test_every_route_has_a_policy_entry`, `test_role_matrix_enforcement[anonymous|viewer|analyst|admin]` |
| Tenant escape (IDOR) | Every query is scoped by `org_id`; foreign objects return 404, not 403 | `test_api_authz.py::test_cross_organization_access_is_not_found` |
| Mass assignment | Pydantic strict models forbid extra fields; no model accepts `role`/`org_id` from the client on create | `test_api_scan_objects.py::test_scan_creation_rejects_short_attestation_and_bad_limits` |
| Injection (SQL) | Parameterised statements everywhere; sort keys resolved through an allow-list | `test_api_scan_objects.py::test_scan_endpoints_filters_and_sort` |
| **Approval laundering** (edit an approved target until it points somewhere else) | An approval is bound to the origin that was reviewed. `PATCH /targets/{id}` revokes it when host, scheme, port set or path prefixes change (only `lab_allowlist` is exempt, because that mode is re-validated against the operator allow-list on every edit), clears `verified_at`/`verified_by`, and writes `target.approval_revoked`. `POST /verify` may self-approve **only** `ownership` mode; an `admin`/`lab_allowlist` target needs an administrator | `test_target_scope_change.py` (14 tests) |

### 3.3 Egress / SSRF (`engine/urlguard.py`, `engine/safe_http.py`, `engine/scope.py`)

| Abuse case | Control | Test |
|---|---|---|
| Direct SSRF to loopback/RFC1918/metadata | Explicit network blocklist before any connection, `is_global`/`is_private`/`is_reserved` checks | `test_urlguard.py::BLOCKED_DESTINATIONS` corpus, `test_is_blocked_ip_classifies_every_family` |
| Non-canonical IP notations (`127.1`, `2130706433`, `0x7f000001`, `0177…`, `0`) | Numeric-host shape check *before* hostname validation | `test_urlguard.py` (SSRF corpus) |
| DNS rebinding | Resolve → validate every address → pin the socket to the validated IP; re-validate each hop | `test_safe_http.py::test_connection_is_pinned_to_validated_ip` |
| Redirect to metadata / other origin / downgrade | Same-origin + in-scope + no HTTPS→HTTP; refusal recorded | `test_safe_http.py::test_redirect_metadata_hop_is_blocked`, `test_path_prefix_limits_what_is_fetched` |
| `$ref` to internal URL in an OpenAPI document | Remote/`file:` refs are refused and counted, never fetched | `test_extractors.py::test_openapi_remote_refs_are_refused_not_fetched` |
| Metadata hostnames | Name blocklist applied before DNS | `test_urlguard.py` |
| Operator allow-list abuse | Allow-list is exact `host:port`; metadata/link-local/unspecified stay blocked even for allow-listed hosts | `test_safe_http.py::test_target_ports_never_authorize_metadata`, `test_urlguard.py::test_is_always_blocked_ignores_private_but_not_metadata` |
| **Target record used as an egress grant** (an org admin creates `127.0.0.1:9999` and scans internal services) | Declared target ports authorize *ports only*; a private/loopback address requires an **operator** `ST_PRIVATE_ALLOWLIST` entry, checked both at target creation (422) and again per request in `validate_destination`. Reproduced with a live canary in round 7 | `test_egress_guard.py` (34 tests: canary exploit reproductions, private-range matrix, declared-port negatives, allow-list positives), `test_egress_guard.py::test_a_declared_port_never_relaxes_the_address_rule` |
| Non-standard ports | Only the target record's declared ports plus the operator allow-list | `test_safe_http.py::test_target_declared_port_is_authorized`, `test_undeclared_port_is_blocked_even_for_the_target_host` |
| Scanner used as an attack tool | Only `GET/HEAD/OPTIONS`; attestation + approval + audit; kill switch | `test_safe_http.py::test_only_safe_methods_are_sent`, `test_security_helpers.py::test_scanning_kill_switch_blocks_scan_creation` |

### 3.4 Parsing hostile target content (`engine/parsers.py`, `extractors/*`)

| Abuse case | Control | Test |
|---|---|---|
| XXE / billion laughs / DTD | defusedxml with `forbid_dtd`, `forbid_entities`, `forbid_external` | `test_parsers.py::test_xml_rejects_doctype_and_entities` |
| XML nesting / size bomb | Element and depth caps, document size cap | `test_parsers.py::test_xml_rejects_nesting_bomb` |
| YAML alias bomb / Python tags | Anchor and alias caps, `safe_load`, depth cap | `test_parsers.py::test_yaml_rejects_alias_bomb`, `test_yaml_rejects_python_object_tags` |
| JSON depth bomb | `json_depth` short-circuits at 40 | `test_parsers.py::test_json_depth_is_capped` |
| ReDoS in extraction | Linear-time regexes only (no nested quantifiers); tree-sitter primary path | `test_extractors.py`, `test_crawler.py` (bounded inputs) |
| Gzip/deflate bomb | Streaming read cap + decompression cap | `test_safe_http.py::test_decompression_bomb_is_capped` |
| Header flood | Header count and byte caps | `test_safe_http.py::test_header_size_limit_is_enforced` |
| Path traversal in source-map `sources` | Traversal strings are noted and ignored; nothing is resolved to disk | `test_extractors.py::test_source_map_contents_are_scanned_but_traversal_strings_ignored` |
| Endless redirects / slow-loris | Hop cap, total deadline, per-read timeout | `test_safe_http.py::test_redirect_loop_and_hop_limit`, `test_read_timeout_maps_to_response_timeout` |

### 3.5 Data handling (`security/redaction.py`, `services/reports.py`)

| Threat | Control | Test |
|---|---|---|
| Secret leakage into the database | Redaction at capture (`make_snippet`, `redact_headers`, `redact_har_entry`); stored values already redacted | `test_security_helpers.py::test_redact_har_entry_handles_both_header_shapes` |
| Secret leakage into audit log | `audit_redact` on every detail mapping | `test_security_helpers.py::test_audit_redaction_never_leaks_values` |
| XSS through scanned content in reports | All interpolated values HTML-escaped; reports contain no scripts | `test_api_scan_objects.py::test_html_export_escapes_untrusted_values` |
| CSV formula injection | Leading `= + - @` prefixed before export | `test_api_scan_objects.py::test_csv_exports_are_rfc4180_parseable` |
| XSS in the UI | React text nodes only; no `dangerouslySetInnerHTML`; CSP without `unsafe-inline` | `frontend/src/main.tsx` (no `dangerouslySetInnerHTML`), `deploy/proxy/nginx.conf` |

### 3.6 Availability (`config.py`, `services/scans.py`, `workers/worker.py`)

| Threat | Control | Test |
|---|---|---|
| Scan flood | Concurrency and daily quotas per organization | `test_scan_integration.py`, `test_lifecycle_service.py` |
| Runaway scan | Request/page/script/time budgets, hard caps from settings | `test_safe_http.py::test_budget_accounting`, `test_crawler.py::test_crawler_respects_the_page_cap` |
| Worker crash | Lease + heartbeat + `recover_stale` with partial results | `test_lifecycle_service.py::test_recover_stale_fails_abandoned_scans` |
| Huge upload | Body limit middleware (8 MiB default) | `test_security_helpers.py::test_body_limit_is_enforced` |
| Host header attacks | Host allow-list middleware | `test_security_helpers.py::test_unknown_host_is_rejected` |

## 4. Out of scope (documented, not mitigated)

- **Magic-link / MFA**: no TOTP is implemented (column exists for forward compatibility).
- **Denial of service from the internet at large**: rate limits are in-process; a real
  deployment must add proxy-level limits (documented in `deploy/HARDENING.md`).
- **Malicious operator**: an operator can allow-list a private host deliberately; the
  metadata ranges stay blocked, but loopback is by definition reachable in lab mode.
  The allow-list is the *only* thing that can do this — an organization admin cannot,
  which is the difference between "the operator chose to scan their own lab" and
  "any tenant admin can reach internal services".
- **Supply chain**: pinned dependencies + pip-audit in CI, but no signature verification.
