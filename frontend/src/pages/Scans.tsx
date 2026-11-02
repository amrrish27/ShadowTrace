import { useCallback, useEffect, useMemo, useState } from "react";
import { api, ApiError } from "../api";
import type { Scan, Target } from "../api";
import type { PageProps } from "../App";
import { duration, elapsedSeconds, number, OUTCOME_HINT, relativeTime, STATE_HINT } from "../lib/format";
import { href, navigate } from "../lib/router";
import { useAsync } from "../useAsync";
import {
  Badge, Card, Empty, ErrorState, Icon, Loading, Modal, Notice, Pagination,
  Progress, RefreshToggle, SearchInput, Select, useInterval,
} from "../ui";

const RUN_ACTIVE = new Set(["queued", "running", "cancelling"]);

export function ScansPage({ session, notify, focusId }: PageProps & { focusId?: string }): JSX.Element {
  const [state, setState] = useState("");
  const [query, setQuery] = useState("");
  const [target, setTarget] = useState("");
  const [page, setPage] = useState(1);
  const [live, setLive] = useState(true);
  const [showNew, setShowNew] = useState(false);
  const pageSize = 15;

  const loader = useCallback(() => api.scans(), []);
  const { data, error, loading, reload } = useAsync(loader, []);
  const targetsLoader = useCallback(() => api.targets(), []);
  const targets = useAsync(targetsLoader, []);

  // Live progress: poll while anything is queued or running (or while the user asks).
  const anyActive = (data?.scans ?? []).some((scan) => RUN_ACTIVE.has(scan.state));
  useInterval(live ? reload : () => undefined, live && (anyActive || showNew) ? 2500 : 8000);

  useEffect(() => {
    setPage(1);
  }, [state, query, target]);

  useEffect(() => {
    if (focusId) setQuery(focusId);
  }, [focusId]);

  const rows = useMemo(() => {
    const list = (data?.scans ?? []).filter((scan) => {
      if (state && scan.state !== state) return false;
      if (target && scan.target_id !== target) return false;
      if (!query) return true;
      const needle = query.toLowerCase();
      return (
        scan.id.toLowerCase().includes(needle) ||
        (scan.target_name ?? "").toLowerCase().includes(needle) ||
        (scan.outcome ?? "").toLowerCase().includes(needle)
      );
    });
    return list.sort((a, b) => b.created_at - a.created_at);
  }, [data, state, query, target]);

  const paged = rows.slice((page - 1) * pageSize, page * pageSize);

  async function cancel(scan: Scan): Promise<void> {
    try {
      await api.cancelScan(scan.id);
      notify("ok", "Cancellation requested — the worker stops within a few seconds.");
      reload();
    } catch (err) {
      notify("error", err instanceof ApiError ? err.message : "Cancel failed.");
    }
  }

  async function retry(scan: Scan): Promise<void> {
    try {
      const response = await api.retryScan(scan.id, `ui-retry-${scan.id.slice(0, 8)}-${Date.now()}`);
      notify("ok", "Retry queued with the same configuration.");
      navigate("scan", response.scan.id);
    } catch (err) {
      notify("error", err instanceof ApiError ? err.message : "Retry failed.");
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Scans</h1>
          <p className="lede">
            A scan is queued, claimed by a worker, then crawls, validates and analyses the target.
            Progress below is the scanner&apos;s own counters.
          </p>
        </div>
        <div style={{ flex: 1 }} />
        <RefreshToggle enabled={live} onToggle={setLive} intervalMs={2500} />
        <button onClick={reload} disabled={loading}>
          <Icon name="refresh" size={14} /> Refresh
        </button>
        <button className="primary" onClick={() => setShowNew(true)}>
          <Icon name="play" size={14} /> New scan
        </button>
      </div>

      {error ? <div className="section"><ErrorState message={error} onRetry={reload} /></div> : null}

      <div className="toolbar">
        <SearchInput value={query} onChange={setQuery} placeholder="Search scan id or target" />
        <Select
          label="Filter by state"
          value={state}
          onChange={setState}
          options={[
            { value: "", label: "Any state" },
            { value: "queued", label: "Queued" },
            { value: "running", label: "Running" },
            { value: "completed", label: "Completed" },
            { value: "failed", label: "Failed" },
            { value: "cancelled", label: "Cancelled" },
            { value: "timed_out", label: "Timed out" },
          ]}
        />
        <Select
          label="Filter by target"
          value={target}
          onChange={setTarget}
          options={[{ value: "", label: "Any target" }, ...(targets.data?.targets ?? []).map((item: Target) => ({ value: item.id, label: item.name }))]}
        />
      </div>

      {loading && !data ? <Loading label="Loading scans…" /> : null}

      {data && rows.length === 0 ? (
        <Card>
          <Empty
            title={(data.scans ?? []).length === 0 ? "No scans yet" : "No scans match the filter"}
            message={
              (data.scans ?? []).length === 0
                ? "Run your first scan against an approved target."
                : "Adjust the search or filters."
            }
            action={
              (data.scans ?? []).length === 0 ? (
                <button className="primary" onClick={() => setShowNew(true)}>
                  <Icon name="play" size={14} /> New scan
                </button>
              ) : null
            }
            icon="radar"
          />
        </Card>
      ) : null}

      {paged.length > 0 ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Target</th>
                <th>State</th>
                <th>Outcome</th>
                <th>Progress</th>
                <th className="num">Endpoints</th>
                <th className="num">Findings</th>
                <th>Started</th>
                <th className="num">Actions</th>
              </tr>
            </thead>
            <tbody>
              {paged.map((scan) => {
                const counters = scan.counters ?? {};
                const active = RUN_ACTIVE.has(scan.state);
                const elapsed = elapsedSeconds(scan.started_at, scan.finished_at);
                return (
                  <tr key={scan.id} className="clickable" onClick={() => navigate("scan", scan.id)}>
                    <td>
                      <div className="cell-main">{scan.target_name || "—"}</div>
                      <div className="mono-cell cell-sub">{scan.id.slice(0, 12)}</div>
                    </td>
                    <td>
                      <Badge value={scan.state} />
                      {scan.partial ? <div className="cell-sub">partial</div> : null}
                    </td>
                    <td>
                      {scan.outcome ? (
                        <span title={OUTCOME_HINT[scan.outcome] ?? ""}>
                          <Badge value={scan.outcome} />
                        </span>
                      ) : (
                        <span className="cell-sub">{active ? "in progress" : "—"}</span>
                      )}
                    </td>
                    <td style={{ minWidth: 150 }}>
                      <Progress
                        value={active ? Math.min(96, Number(counters.pages_fetched ?? 0) * 6 + Number(counters.endpoints_validated ?? 0) * 2) : 100}
                        tone={scan.state === "failed" ? "danger" : scan.state === "completed" ? "ok" : undefined}
                      />
                      <div className="cell-sub">
                        {number(Number(counters.pages_fetched ?? 0))} pages · {duration(elapsed)}
                      </div>
                    </td>
                    <td className="num">{number(Number(counters.endpoints_found ?? 0))}</td>
                    <td className="num">{number(Number(counters.findings ?? 0))}</td>
                    <td>{relativeTime(scan.started_at ?? scan.created_at)}</td>
                    <td className="num" onClick={(event) => event.stopPropagation()}>
                      <div style={{ display: "flex", gap: 6, justifyContent: "flex-end" }}>
                        {active ? (
                          <button className="small" onClick={() => void cancel(scan)}>
                            <Icon name="stop" size={12} /> Cancel
                          </button>
                        ) : null}
                        {scan.retryable ? (
                          <button className="small" onClick={() => void retry(scan)}>
                            <Icon name="refresh" size={12} /> Retry
                          </button>
                        ) : null}
                        <a className="btn small" href={href("scan", scan.id)}>
                          Open
                        </a>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}

      {rows.length > pageSize ? (
        <Pagination page={page} pageSize={pageSize} total={rows.length} onPage={setPage} />
      ) : null}

      <div className="section" style={{ marginTop: 18 }}>
        <Notice kind="info" title="What the states mean">
          {Object.entries(STATE_HINT).map(([key, text]) => `${key}: ${text}`).join(" ")}
        </Notice>
      </div>

      {showNew ? (
        <NewScanModal
          targets={targets.data?.targets ?? []}
          onClose={() => setShowNew(false)}
          onStarted={(scan) => {
            setShowNew(false);
            notify("ok", "Scan queued. A worker will pick it up.");
            navigate("scan", scan.id);
          }}
          notify={notify}
          role={session.user.role}
        />
      ) : null}
    </>
  );
}

const PROFILES = {
  quick: { max_pages: 8, max_scripts: 4, max_requests: 120, max_seconds: 120 },
  standard: { max_pages: 24, max_scripts: 12, max_requests: 400, max_seconds: 300 },
  deep: { max_pages: 60, max_scripts: 40, max_requests: 900, max_seconds: 900 },
} as const;

export function NewScanModal({
  targets,
  onClose,
  onStarted,
  notify,
  role,
  lockedTargetId,
}: {
  targets: Target[];
  onClose: () => void;
  onStarted: (scan: Scan) => void;
  notify: (kind: "ok" | "error" | "info", message: string) => void;
  role: string;
  lockedTargetId?: string;
}): JSX.Element {
  const approved = targets.filter((target) => target.authorization_status === "approved");
  const [targetId, setTargetId] = useState(lockedTargetId ?? approved[0]?.id ?? "");
  const [profile, setProfile] = useState<keyof typeof PROFILES>("standard");
  const [baselines, setBaselines] = useState<{ id: string; source: string; source_ref: string; endpoint_count: number }[]>([]);
  const [baselineId, setBaselineId] = useState("");
  const [includeCrawler, setIncludeCrawler] = useState(true);
  const [includeSpecs, setIncludeSpecs] = useState(true);
  const [includeSourceMaps, setIncludeSourceMaps] = useState(true);
  const [activeValidation, setActiveValidation] = useState(true);
  const [attestation, setAttestation] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!targetId) {
      setBaselines([]);
      setBaselineId("");
      return;
    }
    api.listBaselines(targetId).then((res) => {
      setBaselines(res.baselines || []);
      setBaselineId("");
    }).catch(() => {
      setBaselines([]);
      setBaselineId("");
    });
  }, [targetId]);

  async function submit(): Promise<void> {
    if (!targetId) {
      setError("Choose an approved target first.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const limits = PROFILES[profile];
      const scanPayload: Record<string, unknown> = {
        target_id: targetId,
        include_crawler: includeCrawler,
        include_specs: includeSpecs,
        include_source_maps: includeSourceMaps,
        active_validation: activeValidation,
        ...limits,
        seeds: [],
        attestation: attestation.trim() || "Authorized assessment started from the dashboard.",
      };
      if (baselineId) {
        scanPayload.baseline_id = baselineId;
      }
      const response = await api.createScan(scanPayload, `ui-scan-${Date.now()}`);
      onStarted(response.scan);
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Could not start the scan.";
      setError(message);
      notify("error", message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title="Start a scan"
      onClose={onClose}
      footer={
        <>
          <button onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="primary" onClick={() => void submit()} disabled={busy || !targetId}>
            {busy ? "Queuing…" : "Queue scan"}
          </button>
        </>
      }
    >
      {approved.length === 0 ? (
        <Notice kind="warn" title="No approved targets">
          Register a target and have an administrator approve it before scanning.
        </Notice>
      ) : null}
      <label className="field">
        Target
        <select value={targetId} onChange={(event) => setTargetId(event.target.value)} disabled={Boolean(lockedTargetId)}>
          {approved.map((target) => (
            <option key={target.id} value={target.id}>
              {target.name} — {target.base_url}
            </option>
          ))}
        </select>
      </label>
      <label className="field">
        Baseline specification (optional)
        <select value={baselineId} onChange={(event) => setBaselineId(event.target.value)}>
          <option value="">Auto-discover from target or none</option>
          {baselines.map((b) => (
            <option key={b.id} value={b.id}>
              {b.source_ref} ({b.endpoint_count} endpoints, {b.source})
            </option>
          ))}
        </select>
      </label>
      <label className="field">
        Profile
        <select value={profile} onChange={(event) => setProfile(event.target.value as keyof typeof PROFILES)}>
          <option value="quick">Quick (8 pages, 120 requests)</option>
          <option value="standard">Standard (24 pages, 400 requests)</option>
          <option value="deep">Deep (60 pages, 900 requests)</option>
        </select>
      </label>
      <div style={{ display: "grid", gap: 8 }}>
        <label className="checkbox">
          <input type="checkbox" checked={includeCrawler} onChange={(event) => setIncludeCrawler(event.target.checked)} />
          Crawl pages and scripts
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={includeSpecs} onChange={(event) => setIncludeSpecs(event.target.checked)} />
          Probe for API specifications
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={includeSourceMaps} onChange={(event) => setIncludeSourceMaps(event.target.checked)} />
          Analyse source maps
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={activeValidation} onChange={(event) => setActiveValidation(event.target.checked)} />
          Validate endpoints with read-only requests (GET/HEAD/OPTIONS only)
        </label>
      </div>
      <label className="field">
        Attestation
        <textarea
          value={attestation}
          onChange={(event) => setAttestation(event.target.value)}
          placeholder="I am authorized to test this target. (recorded in the audit log)"
        />
      </label>
      {role === "viewer" ? (
        <Notice kind="warn">Your role can view scans but not start them.</Notice>
      ) : null}
      {error ? <ErrorState title="Could not queue the scan" message={error} /> : null}
      <Notice kind="info">
        Every request stays inside the target&apos;s host, port and path scope, and every redirect is
        re-validated. The scanner never sends anything but GET, HEAD and OPTIONS.
      </Notice>
    </Modal>
  );
}
