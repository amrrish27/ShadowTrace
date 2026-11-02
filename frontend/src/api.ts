/**
 * Typed API client. Every call goes through one place so CSRF handling,
 * error normalisation and cancellation live in a single spot.
 */
export type Role = "admin" | "analyst" | "viewer";

export interface ApiErrorShape {
  code: string;
  message: string;
  request_id?: string;
}

export class ApiError extends Error {
  code: string;
  requestId: string;
  status: number;

  constructor(status: number, error: ApiErrorShape) {
    super(error.message);
    this.status = status;
    this.code = error.code;
    this.requestId = error.request_id ?? "";
    this.name = "ApiError";
  }
}

let csrfToken = "";

export function setCsrfToken(token: string): void {
  csrfToken = token;
}

function readCookie(name: string): string {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1] ?? "") : "";
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body) headers.set("Content-Type", "application/json");
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    headers.set("X-CSRF-Token", csrfToken || readCookie("st_csrf"));
  }
  const response = await fetch(path, { ...init, method, headers, credentials: "same-origin" });
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  let payload: unknown = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = null;
  }
  if (!response.ok) {
    const shape = (payload as { error?: ApiErrorShape } | null)?.error;
    throw new ApiError(
      response.status,
      shape ?? { code: "request_failed", message: `Request failed (${response.status}).` },
    );
  }
  return payload as T;
}

export interface User {
  id: string;
  email: string;
  name: string;
  role: Role;
  org_id: string;
}

export interface MemberRow {
  id: string;
  email: string;
  name: string;
  role: Role;
  is_active: boolean;
  created_at: number;
  last_login_at: number | null;
}

export interface InviteResult {
  id: string;
  email: string;
  role: Role;
  token: string;
  expires_in: number;
}

export interface MeResponse {
  user: User;
  csrf_token: string;
  organization: string;
}

export interface TargetDetail extends Target {
  scheme?: string;
  ports?: number[] | string;
  path_prefixes?: number[] | string;
  justification?: string;
  attestation?: string;
  created_at?: number;
  verified_at?: number | null;
  lab_granted?: boolean;
  scan_ready?: boolean;
}

export interface Target {
  id: string;
  name: string;
  base_url: string;
  host: string;
  authorization_status: string;
  authorization_mode: string;
  verification_token?: string;
  last_scan_at?: number | null;
}

/**
 * Live progress counters written by the scanner (`ScanSummary.as_counters()`).
 * The snake_case names below are the wire format; the index signature keeps the UI tolerant
 * of counters added later. Unknown/missing values must render as 0, never as `undefined`.
 */
export interface ScanCounters {
  endpoints_found?: number;
  endpoints_validated?: number;
  shadow_endpoints?: number;
  zombies?: number;
  findings?: number;
  findings_by_severity?: Record<string, number>;
  pages_fetched?: number;
  scripts_analyzed?: number;
  requests_used?: number;
  source_maps?: number;
  external_references?: number;
  partial?: boolean | number;
  [key: string]: number | boolean | Record<string, number> | undefined;
}

export interface Scan {
  id: string;
  phase?: string;
  outcome?: string;
  profile?: string;
  retryable?: boolean;
  target_id: string;
  target_name: string;
  state: string;
  partial: boolean;
  error_category: string | null;
  error_message: string | null;
  counters: ScanCounters;
  config?: Record<string, unknown>;
  created_at: number;
  started_at: number | null;
  finished_at: number | null;
}

export interface Endpoint {
  id: string;
  method: string;
  host: string;
  path_template: string;
  query_template: string;
  classification: "shadow" | "documented" | "zombie" | "unknown";
  validation_status: string;
  response_status: number | null;
  source_types?: string | null;
  first_seen_at?: number | null;
  last_seen_at?: number | null;
}

export interface Finding {
  id: string;
  rule_id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence: string;
  status: string;
  risk_score: number;
  triage_status: string;
  endpoint_method?: string | null;
  endpoint_path?: string | null;
}

export interface ScanEvent {
  id: number;
  ts: number;
  level: string;
  kind: string;
  message: string;
}

/** One row of `source_breakdown`: how many endpoints each discovery source contributed. */
export interface SourceBreakdownRow {
  source: string;
  endpoints: number;
}

/** One row of `recent_scans`. `counters` is the live progress object from the scan row. */
export interface RecentScan {
  id: string;
  state: string;
  created_at: number;
  finished_at: number | null;
  counters: ScanCounters;
  target_name: string;
}

/**
 * `GET /api/v1/dashboard/overview`.
 *
 * This type previously declared `recent_findings` while the API never returned it, which made
 * the dashboard crash on `undefined.length`. The backend now always returns every key below;
 * `frontend/src/__fixtures__/overview.contract.json` is the shared, test-enforced source of
 * truth for both sides.
 */
export interface Overview {
  scans_by_state: Record<string, number>;
  endpoints: { total: number; shadow: number; documented: number; zombie: number };
  findings_by_severity: Record<string, number>;
  triage: Record<string, number>;
  recent_findings: Finding[];
  source_breakdown: SourceBreakdownRow[];
  recent_scans: RecentScan[];
  scan_timeline: { day: string; scans: number }[];
  targets: { total: number; approved: number };
}

/**
 * Normalise an overview payload at the network boundary.
 *
 * The API always returns every field (enforced by `backend/tests/test_api_dashboard.py` against
 * the shared contract fixture). This guard exists because a cached response from an older
 * backend, or a proxy that strips an empty array, must never turn into
 * "Cannot read properties of undefined (reading 'length')" and a blank page.
 */
export function normalizeOverview(raw: Partial<Overview> | null | undefined): Overview {
  const value = raw ?? {};
  const asRecord = (input: unknown): Record<string, number> =>
    input && typeof input === "object" ? (input as Record<string, number>) : {};
  const asList = <T,>(input: unknown): T[] => (Array.isArray(input) ? (input as T[]) : []);
  const endpoints = (value.endpoints ?? {}) as Partial<Overview["endpoints"]>;
  const targets = (value.targets ?? {}) as Partial<Overview["targets"]>;
  return {
    scans_by_state: asRecord(value.scans_by_state),
    endpoints: {
      total: endpoints.total ?? 0,
      shadow: endpoints.shadow ?? 0,
      documented: endpoints.documented ?? 0,
      zombie: endpoints.zombie ?? 0,
    },
    findings_by_severity: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      ...asRecord(value.findings_by_severity),
    },
    triage: { open: 0, accepted_risk: 0, false_positive: 0, fixed: 0, ...asRecord(value.triage) },
    recent_findings: asList<Finding>(value.recent_findings),
    source_breakdown: asList<SourceBreakdownRow>(value.source_breakdown),
    recent_scans: asList<RecentScan>(value.recent_scans).map((scan) => ({ ...scan, counters: scan.counters ?? {} })),
    scan_timeline: asList<{ day: string; scans: number }>(value.scan_timeline),
    targets: { total: targets.total ?? 0, approved: targets.approved ?? 0 },
  };
}

export interface LabStatus {
  enabled: boolean;
  managed: boolean;
  running: boolean;
  healthy: boolean;
  lab_id: string;
  pid: number | null;
  url: string;
  host: string;
  port: number;
  uptime_seconds: number;
  entrypoint: string;
  warning: string;
  last_error: string;
  log_tail: string[];
  scenarios: number;
  target: {
    id: string;
    name: string;
    base_url: string;
    host: string;
    authorization_status: string;
    authorization_mode: string;
    lab_granted: boolean;
    scan_ready: boolean;
  } | null;
  allowlisted: boolean;
  scanning_enabled: boolean;
  hint?: string;
}

export interface LabScenario {
  id: string;
  title: string;
  category: string;
  severity: string;
  path: string;
  summary: string;
  demo: string;
  expected_rules: string[];
  safe: string;
  enabled?: boolean;
  containment_note?: string;
}

export interface LabMapping {
  rule_id: string;
  title: string;
  severity: string;
  status: string;
  scenarios: string[];
}

export interface WorkerHealth {
  worker_id: string;
  hostname: string;
  pid: number | null;
  started_at: number;
  last_seen_at: number;
  scans_run: number;
  version: string;
  alive: boolean;
  seconds_since_seen: number;
}

export interface AuditEntry {
  id: number;
  ts: number;
  actor_type: string;
  actor_id: string;
  action: string;
  object_type: string;
  object_id: string;
  ip: string;
  details: Record<string, unknown> | null;
}

export interface ComparedEndpoint {
  fingerprint: string;
  method: string;
  path: string;
  status: string | null;
  previous_status?: string | null;
}

export interface Comparison {
  previous_scan_id: string | null;
  new: ComparedEndpoint[];
  removed: ComparedEndpoint[];
  changed: ComparedEndpoint[];
  findings_new: string[];
  findings_resolved: string[];
}

export const api = {
  changePassword: (currentPassword: string, newPassword: string) =>
    request<{ ok: boolean }>("/api/v1/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    }),
  acceptInvite: (payload: { token: string; password: string; name: string }) =>
    request<{ ok: boolean; user: User }>("/api/v1/auth/accept-invite", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  users: () => request<{ users: MemberRow[] }>("/api/v1/users"),
  inviteUser: (payload: { email: string; role: Role }) =>
    request<InviteResult>("/api/v1/users/invite", { method: "POST", body: JSON.stringify(payload) }),
  updateUser: (id: string, payload: { role?: Role; is_active?: boolean }) =>
    request<{ user: MemberRow }>(`/api/v1/users/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  login: (email: string, password: string) =>
    request<{ user: User }>("/api/v1/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  logout: () => request<{ ok: boolean }>("/api/v1/auth/logout", { method: "POST" }),
  me: () => request<MeResponse>("/api/v1/auth/me"),
  overview: () =>
    request<Partial<Overview>>("/api/v1/dashboard/overview").then(normalizeOverview),
  targets: () => request<{ targets: Target[] }>("/api/v1/targets"),
  createTarget: (payload: Record<string, unknown>) =>
    request<{ target: Target }>("/api/v1/targets", { method: "POST", body: JSON.stringify(payload) }),
  scans: () => request<{ scans: Scan[] }>("/api/v1/scans"),
  scan: (id: string) => request<{ scan: Scan }>(`/api/v1/scans/${encodeURIComponent(id)}`),
  createScan: (payload: Record<string, unknown>, idempotencyKey: string) =>
    request<{ scan: Scan }>("/api/v1/scans", {
      method: "POST",
      headers: { "Idempotency-Key": idempotencyKey },
      body: JSON.stringify(payload),
    }),
  cancelScan: (id: string) =>
    request<{ scan: Scan }>(`/api/v1/scans/${encodeURIComponent(id)}/cancel`, { method: "POST" }),
  endpoints: (id: string, params: Record<string, string> = {}) =>
    request<{ endpoints: Endpoint[]; total: number }>(
      `/api/v1/scans/${encodeURIComponent(id)}/endpoints?${new URLSearchParams(params).toString()}`,
    ),
  findings: (id: string, params: Record<string, string> = {}) =>
    request<{ findings: Finding[]; total: number }>(
      `/api/v1/scans/${encodeURIComponent(id)}/findings?${new URLSearchParams(params).toString()}`,
    ),
  events: (id: string, after = 0) =>
    request<{ events: ScanEvent[] }>(`/api/v1/scans/${encodeURIComponent(id)}/events?after=${after}`),
  finding: (id: string) => request<{ finding: Finding & { evidence: Record<string, unknown>; rationale: string; limitations: string; remediation: string } }>(`/api/v1/findings/${encodeURIComponent(id)}`),
  triage: (id: string, status: string, reason: string) =>
    request<{ finding: Finding }>(`/api/v1/findings/${encodeURIComponent(id)}/triage`, {
      method: "POST",
      body: JSON.stringify({ status, reason }),
    }),
  exportUrl: (id: string, format: string) =>
    `/api/v1/scans/${encodeURIComponent(id)}/export?format=${encodeURIComponent(format)}`,
  retryScan: (id: string, idempotencyKey: string) =>
    request<{ scan: Scan; retry_of: string }>(`/api/v1/scans/${encodeURIComponent(id)}/retry`, {
      method: "POST",
      headers: { "Idempotency-Key": idempotencyKey },
    }),
  startScan: (id: string) =>
    request<{ scan: Scan }>(`/api/v1/scans/${encodeURIComponent(id)}/start`, { method: "POST" }),
  comparison: (id: string) =>
    request<Comparison>(`/api/v1/scans/${encodeURIComponent(id)}/comparison`),
  deleteScan: (id: string) =>
    request<{ ok: boolean }>(`/api/v1/scans/${encodeURIComponent(id)}`, { method: "DELETE" }),
  target: (id: string) => request<{ target: TargetDetail }>(`/api/v1/targets/${encodeURIComponent(id)}`),
  updateTarget: (id: string, payload: Record<string, unknown>) =>
    request<{ target: TargetDetail }>(`/api/v1/targets/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  deleteTarget: (id: string) =>
    request<{ ok: boolean }>(`/api/v1/targets/${encodeURIComponent(id)}`, { method: "DELETE" }),
  approveTarget: (id: string, justification: string) =>
    request<{ target: TargetDetail }>(`/api/v1/targets/${encodeURIComponent(id)}/approve`, {
      method: "POST",
      body: JSON.stringify({ justification }),
    }),
  verifyTarget: (id: string) =>
    request<{ target: TargetDetail }>(`/api/v1/targets/${encodeURIComponent(id)}/verify`, { method: "POST" }),
  listBaselines: (targetId: string) =>
    request<{ baselines: { id: string; source: string; source_ref: string; endpoint_count: number; created_at: number }[] }>(
      `/api/v1/targets/${encodeURIComponent(targetId)}/baselines`,
    ),
  createBaseline: (targetId: string, payload: { source: string; content?: string; url?: string }) =>
    request<{ id: string; endpoint_count: number; source: string; target_id: string }>(
      `/api/v1/targets/${encodeURIComponent(targetId)}/baselines`,
      { method: "POST", body: JSON.stringify(payload) },
    ),
  importHar: (targetId: string, content: string, name?: string) =>
    request<{ id: string; entries_total: number; entries_in_scope: number; entries_out_of_scope: number; endpoints_found: number }>(
      `/api/v1/targets/${encodeURIComponent(targetId)}/har`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(name ? { "X-Har-Name": name } : {}) },
        body: content,
      },
    ),
  allFindings: (params: Record<string, string> = {}) =>
    request<{ findings: Finding[]; total: number }>(`/api/v1/findings?${new URLSearchParams(params).toString()}`),
  allEndpoints: (params: Record<string, string> = {}) =>
    request<{ endpoints: Endpoint[]; total: number }>(`/api/v1/endpoints?${new URLSearchParams(params).toString()}`),
  endpoint: (id: string) =>
    request<{ endpoint: Endpoint & { scans?: unknown[]; observations?: unknown[] } }>(
      `/api/v1/endpoints/${encodeURIComponent(id)}`,
    ),
  rules: () => request<{ rules: { id: string; title: string; category: string; severity: string; confidence: string; status: string; description: string }[] }>("/api/v1/meta/rules"),
  runtimeConfig: () =>
    request<{ scanning_enabled: boolean; environment: string; [key: string]: unknown }>("/api/v1/meta/config"),
  adminSettings: () => request<Record<string, unknown>>("/api/v1/admin/settings"),
  workers: () =>
    request<{ workers: WorkerHealth[]; alive: number; window_seconds: number; scanning_enabled: boolean }>(
      "/api/v1/admin/workers",
    ),
  audit: (params: Record<string, string> = {}) =>
    request<{ entries: AuditEntry[] }>(`/api/v1/admin/audit?${new URLSearchParams(params).toString()}`),
  labStatus: () => request<{ lab: LabStatus }>("/api/v1/lab/status"),
  labScenarios: () => request<{ scenarios: LabScenario[] }>("/api/v1/lab/scenarios"),
  labMappings: () => request<{ rules: LabMapping[]; scenarios: number }>("/api/v1/lab/mappings"),
  labStart: () => request<{ lab: LabStatus }>("/api/v1/lab/start", { method: "POST" }),
  labStop: () => request<{ lab: LabStatus }>("/api/v1/lab/stop", { method: "POST" }),
  labRestart: () => request<{ lab: LabStatus }>("/api/v1/lab/restart", { method: "POST" }),
  labReset: () => request<{ lab: LabStatus; reset: boolean }>("/api/v1/lab/reset", { method: "POST" }),
  labTarget: () =>
    request<{ target: LabStatus["target"]; created: boolean }>("/api/v1/lab/target", { method: "POST" }),
  labScan: (payload: Record<string, unknown>) =>
    request<{ scan: Scan; created: boolean }>("/api/v1/lab/scan", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
};

/** Idempotency keys must be ≥ 8 characters; a UUID is both unique and opaque. */
export function newIdempotencyKey(prefix = "ui"): string {
  const random = typeof crypto !== "undefined" && "randomUUID" in crypto
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `${prefix}-${random}`.slice(0, 64);
}

export function formatTimestamp(value: number | null | undefined): string {
  if (!value) return "—";
  return new Date(value * 1000).toLocaleString();
}
