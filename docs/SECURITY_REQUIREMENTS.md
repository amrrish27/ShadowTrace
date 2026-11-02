# Security requirements

Every requirement has an ID, an implementation pointer and a test pointer. "Verified"
means an automated test in `backend/tests` or `frontend/src` fails if the requirement is
broken. Requirements marked **partial** or **documented** are explained in
[known-issues.md](known-issues.md).

## AUTH — authentication and sessions

| ID | Requirement | Implementation | Test |
|---|---|---|---|
| AUTH-01 | Passwords ≥ 12 chars, ≥ 3 character classes, not equal to identity, not common | `security/passwords.py::validate_password` | `test_security_helpers.py::test_password_policy_accepts_strong_and_rejects_weak` |
| AUTH-02 | Argon2id hashing with per-password salt; verification is constant-cost even for unknown users | `passwords.py::hash_password/verify_password` | `test_hashing_is_salted_and_verifiable` |
| AUTH-03 | Session tokens are 256-bit random; only SHA-256 hashes are stored | `security/tokens.py` | `test_tokens_are_random_and_hashed_for_storage` |
| AUTH-04 | Cookies: `HttpOnly`, `SameSite=strict`, `Secure` in production, path `/` | `security/auth.py::create_session` | `test_auth_flow.py::test_login_sets_hardened_cookies` |
| AUTH-05 | Session fixation: rotate on login, revoke all on password change | `auth.py`, `auth_routes.py` | `test_password_change_requires_current_password_and_rotates_sessions` |
| AUTH-06 | Idle and absolute expiry, refreshed at most once a minute | `auth.py::authenticate` | `test_auth_flow.py` (expiry logic covered via `authenticate`) |
| AUTH-07 | Login failures audited with no secret material | `security/auth.py::audit_login` (durable write) | `test_login_is_audited_without_secrets` |
| AUTH-08 | Invitations: single use, 7-day expiry, hashed token, existing-account refusal | `api/users.py`, `auth_routes.py` | `test_invitation_acceptance_flow` |
| AUTH-09 | No open registration; only admins invite | `api/users.py` | `test_api_authz.py::test_viewer_cannot_mutate_but_can_read` |

## AUTHZ — authorization

| ID | Requirement | Implementation | Test |
|---|---|---|---|
| AUTHZ-01 | Every route declares a minimum role in one map | `api/deps.py::ROUTE_POLICY` | `test_every_route_has_a_policy_entry` |
| AUTHZ-02 | The policy is enforced before body parsing; under-privileged callers get 403 | `api/deps.py::policy_guard` | `test_role_matrix_enforcement[viewer|analyst|admin]` |
| AUTHZ-03 | Unauthenticated access to non-public routes is 401 | `security/auth.py` | `test_role_matrix_enforcement[anonymous]` |
| AUTHZ-04 | Cross-organization access returns 404 | `security/auth.py::scoped` | `test_cross_organization_access_is_not_found` |
| AUTHZ-05 | No mass assignment: strict models, no role/org fields on create | `api/schemas.py` | `test_scan_creation_rejects_short_attestation_and_bad_limits` |
| AUTHZ-06 | Mutations require a CSRF token **and** an acceptable `Origin`: the configured `ST_CORS_ORIGINS`/`ST_BASE_URL`, or the origin the request was addressed to (same-origin). `null`, malformed and foreign origins are refused; `X-Forwarded-Proto` is honoured only from a trusted proxy | `security/auth.py::authenticate`, `_origin_allowed`, `request_origin` | `test_csrf_header_is_required_for_state_changes`, `test_csrf_origin.py` (54) |
| AUTH-06a | `POST /auth/login` applies the same `Origin` check even though it has no CSRF token to compare (no session exists yet); a present-but-disallowed origin is `403 csrf_failed` | `api/auth_routes.py::login`, `security/auth.py::_origin_allowed` | `test_csrf_origin.py::test_login_rejects_a_foreign_origin` |

## SSRF — egress control

| ID | Requirement | Implementation | Test |
|---|---|---|---|
| SSRF-01 | Only `http`/`https`; no userinfo, backslashes, control chars, whitespace | `engine/urlguard.py::canonicalize` | `test_urlguard.py` corpus |
| SSRF-02 | Non-canonical IPv4 forms rejected before hostname matching | `urlguard.py::_looks_like_numeric_host` | corpus |
| SSRF-03 | Every resolved address must be globally routable; explicit blocklist | `urlguard.py::is_blocked_ip` | `test_is_blocked_ip_classifies_every_family` |
| SSRF-04 | Metadata hostnames blocked by name before DNS | `urlguard.py::METADATA_HOSTNAMES` | corpus |
| SSRF-05 | Only declared ports (target record) or the exact operator allow-list | `urlguard.py::validate_destination`, `safe_http.py` | `test_target_declared_port_is_authorized` |
| SSRF-05a | A declared port authorizes a **port**, never a private address: non-public destinations require an operator `ST_PRIVATE_ALLOWLIST` entry, enforced at target creation and again per request | `urlguard.py::validate_destination(private_allowlist=…, declared_ports=…)`, `api/targets.py::create_target` | `test_egress_guard.py` (34), `test_egress_guard.py::test_a_declared_port_never_relaxes_the_address_rule` |
| SSRF-06 | Socket pinned to the validated IP (rebinding defence) | `safe_http.py::_Pinned*Connection` | `test_connection_is_pinned_to_validated_ip` |
| SSRF-07 | Redirects: same-origin, in-scope, no HTTPS→HTTP downgrade, hop cap | `safe_http.py::request` | `test_redirect_metadata_hop_is_blocked`, `test_redirect_loop_and_hop_limit` |
| SSRF-08 | Allow-list never authorizes metadata/link-local/multicast | `urlguard.py::is_always_blocked` | `test_target_ports_never_authorize_metadata` |
| SSRF-09 | No outbound HTTP outside `SafeHttpClient` | CI grep gate | `.github/workflows/ci.yml` (`grep -rn … \| grep -v safe_http`) |
| SSRF-10 | Response size, header count/size and decompression capped | `safe_http.py` | `test_oversized_body_aborts_instead_of_truncating`, `test_header_size_limit_is_enforced`, `test_decompression_bomb_is_capped` |
| SSRF-11 | Kill switch and cancellation checked before every request | `safe_http.py::_preflight` | `test_kill_switch_and_cancel_are_checked_before_connecting` |
| SSRF-12 | A lab target is scanned through an **HMAC grant**, never by relaxing the address rule: `lab-v1\|target_id\|scheme\|host\|port`, minted with `ST_SECRET_KEY`, stored on the target row and verified by the worker against its own row **and** its own allow-list | `security/labgrant.py`, `engine/urlguard.py::validate_destination(lab_grants=…)` | `test_lab_grants.py` (17): empty worker allow-list + valid grant scans; missing/forged/foreign grant stays blocked; metadata and other loopback ports stay blocked with a grant |
| SSRF-13 | Every refused redirect is counted, so the scan summary cannot under-report the boundary that was enforced | `safe_http.py::request` (`blocked_attempts`) | `test_https_to_http_redirect_is_refused`, `test_redirect_outside_the_path_scope_is_refused`, `scripts/e2e_round8.py` |

## SCAN — safe scanning

| ID | Requirement | Implementation | Test |
|---|---|---|---|
| SCAN-01 | Only `GET`/`HEAD`/`OPTIONS` are ever sent | `safe_http.py::ALLOWED_METHODS`, `validator.py` | `test_only_safe_methods_are_sent`, `test_validator_only_sends_safe_methods` |
| SCAN-02 | Budgets for requests/pages/scripts/seconds, hard caps from settings | `scanner.py`, `safe_http.py::RequestBudget` | `test_budget_accounting`, `test_crawler_respects_the_page_cap` |
| SCAN-03 | Circuit breaker after 5 consecutive errors | `validator.py` | `test_validator_circuit_breaker_opens_after_repeated_errors` |
| SCAN-04 | Backoff on 429/5xx | `validator.py` | `test_validator_backoff_uses_injected_sleep` |
| SCAN-05 | Soft-404 detection so a shell is not reported as live | `validator.py::Soft404Probe` | `test_soft_404_detects_and_matches_catch_all_shell` |
| SCAN-06 | Targets require attestation + approval; lab mode requires the operator allow-list | `api/targets.py` | `test_target_outside_allowlist_is_refused`, `test_targets_crud_and_approval` |
| SCAN-07 | Cancellation honoured and recorded; partial results preserved | `services/scans.py`, `worker.py` | `test_cancel_queued_scan_is_immediate`, `test_cancellation_stops_the_scan` |
| SCAN-08 | Crash recovery keeps partial results and audits the event | `worker.py::recover_stale` | `test_recover_stale_fails_abandoned_scans` |

## DATA — confidentiality of findings and evidence

| ID | Requirement | Implementation | Test |
|---|---|---|---|
| DATA-01 | Secrets redacted at capture, in storage, in logs and in exports | `security/redaction.py`, `make_snippet` | `test_redaction_masks_well_known_secret_shapes`, `test_secret_rule_redacts_the_value` |
| DATA-02 | Audit details redacted; log payloads carry no secrets | `audit_redact`, `logging.py` | `test_audit_redaction_never_leaks_values` |
| DATA-03 | Reports escape untrusted values; no scripts in HTML reports | `services/reports.py` | `test_html_export_escapes_untrusted_values` |
| DATA-04 | CSV exports neutralise formula prefixes | `reports.py::_csv_safe` | `test_csv_exports_are_rfc4180_parseable` |
| DATA-05 | Every finding has evidence and passes the wording lint | `rules.py::finalize_hit`, `lint_wording` | `test_scan_integration.py::test_real_scan_completes_with_evidence` |

## INP — input handling

| ID | Requirement | Implementation | Test |
|---|---|---|---|
| INP-01 | XML: no DTD, no entities, bounded depth/size | `engine/parsers.py::safe_xml_fromstring` | `test_parsers.py` (XML group) |
| INP-02 | YAML: safe load, anchor/alias caps, depth cap | `parsers.py::safe_yaml_load` | `test_yaml_rejects_alias_bomb` |
| INP-03 | JSON: depth cap | `parsers.py::safe_json_load` | `test_json_depth_is_capped` |
| INP-04 | Linear-time regexes only; JS parsed as data | `extractors/js_extract.py` | `test_extractors.py`, `test_crawler.py` |
| INP-05 | Request bodies limited (8 MiB default) | `security/middleware.py::BodyLimitMiddleware` | `test_body_limit_is_enforced` |
| INP-06 | Host header allow-list | `middleware.py::HostAllowlistMiddleware` | `test_unknown_host_is_rejected` |
| INP-07 | Pagination and page-size bounds on every list endpoint | `api/*` | `test_role_matrix_enforcement` (422 on bad params) |
| INP-08 | SQL only through parameters; sort keys allow-listed | `api/scans.py`, `api/inventory.py` | `test_scan_endpoints_filters_and_sort` |

## OPS — operations

| ID | Requirement | Implementation | Test |
|---|---|---|---|
| OPS-01 | Fail-closed production configuration (weak secret, insecure cookie, empty hosts rejected) | `config.py::_validate` | `test_config` guards inside `config.py`; covered by startup tests |
| OPS-02 | Security headers on every response | `middleware.py::SecurityHeadersMiddleware` | `test_security_headers_and_request_id` |
| OPS-03 | Request IDs propagated and validated | `middleware.py::RequestContextMiddleware` | same test |
| OPS-04 | Structured logs with redaction | `core/logging.py` | `test_audit_redaction_never_leaks_values` |
| OPS-05 | Rate limits per IP and per account; the client IP is unspoofable (header honoured only from a trusted proxy, walked right-to-left over validated IP literals, and overwritten by nginx with `$remote_addr`) | `security/ratelimit.py`, `security/auth.py::client_ip`, `deploy/proxy/nginx.conf` | `test_login_rate_limit_per_account`, `test_trusted_proxy.py` (34) |
| OPS-06 | Append-only audit log | `migrations/0001_init.sql` triggers | `test_lifecycle_service.py` (audit assertions) |
| OPS-07 | API docs disabled in production | `main.py::create_app` | reviewed in gate 1 |
| OPS-08 | Kill switch documented and testable: `ST_SCANNING_ENABLED=false` blocks scan creation **and** every outbound request (`SCANNING_ENABLED` is a deprecated fallback that logs a warning) | `config.py::load_settings`, `api/scans.py`, `engine/safe_http.py::_preflight` | `test_kill_switch.py` (creation, egress, verification, metadata, precedence, fallback) |
