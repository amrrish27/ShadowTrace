import { useCallback, useEffect, useMemo, useState } from "react";
import { api, ApiError } from "../api";
import type { Endpoint, Finding, ScanEvent } from "../api";
import type { PageProps } from "../App";
import { duration, elapsedSeconds, number, OUTCOME_HINT, relativeTime, STATE_HINT } from "../lib/format";
import { navigate } from "../lib/router";
import { useAsync } from "../useAsync";
import {
  Badge, Card, ConfirmDialog, Empty, ErrorState, Icon, Loading, Notice, Pagination,
  Progress, RefreshToggle, SearchInput, Select, SeverityBars, Tabs, useInterval,
} from "../ui";

const PHASES = ["queued", "discover", "normalize", "reconcile", "validate", "analyze", "done"];
const ACTIVE = new Set(["queued", "running", "cancelling"]);
const EXPORTS = [
  { id: "json", label: "JSON", hint: "machine-readable bundle" },
  { id: "html", label: "HTML", hint: "formatted report" },
  { id: "markdown", label: "Markdown", hint: "for tickets and wikis" },
  { id: "csv_findings", label: "Findings CSV", hint: "spreadsheet" },
  { id: "csv_inventory", label: "Inventory CSV", hint: "endpoint list" },
  { id: "openapi_stub", label: "OpenAPI stub", hint: "from the inventory" },
];

type Tab = "overview" | "findings" | "endpoints" | "events" | "comparison";

export function ScanDetailPage({ scanId, notify }: PageProps & { scanId: string }): JSX.Element {
  const [tab, setTab] = useState<Tab>("overview");
  const [live, setLive] = useState(true);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [busy, setBusy] = useState(false);

  const loader = useCallback(() => api.scan(scanId), [scanId]);
  const { data, error, loading, reload } = useAsync(loader, [scanId]);
  const scan = data?.scan;

  useInterval(live && scan && ACTIVE.has(scan.state) ? reload : () => undefined, live ? 2500 : null);

  const eventsLoader = useCallback(() => api.events(scanId), [scanId]);
  const events = useAsync<{ events: ScanEvent[] }>(eventsLoader, [scanId]);
  useInterval(live && scan && ACTIVE.has(scan.state) ? events.reload : () => undefined, live ? 2500 : null);

  useEffect(() => {
    setTab("overview");
  }, [scanId]);

  async function cancel(): Promise<void> {
    setBusy(true);
    try {
      await api.cancelScan(scanId);
      notify("ok", "Cancellation requested.");
      reload();
    } catch (err) {
      notify("error", err instanceof ApiError ? err.message : "Cancel failed.");
    } finally {
      setBusy(false);
    }
  }

  async function retry(): Promise<void> {
    setBusy(true);
    try {
      const response = await api.retryScan(scanId, `ui-retry-${Date.now()}`);
      notify("ok", "Retry queued.");
      navigate("scan", response.scan.id);
    } catch (err) {
      notify("error", err instanceof ApiError ? err.message : "Retry failed.");
    } finally {
      setBusy(false);
    }
  }

  async function remove(): Promise<void> {
    setBusy(true);
    try {
      await api.deleteScan(scanId);
      notify("ok", "Scan deleted.");
      navigate("scans");
    } catch (err) {
      notify("error", err instanceof ApiError ? err.message : "Delete failed.");
      setBusy(false);
      setConfirmDelete(false);
    }
  }

  if (loading && !scan) return <Loading label="Loading scan…" />;
  if (error && !scan) return <ErrorState message={error} onRetry={reload} />;
  if (!scan) return <Empty title="Scan not found" message="It may have been deleted." icon="radar" />;

  const counters = scan.counters ?? {};
  const elapsed = elapsedSeconds(scan.started_at, scan.finished_at);
  const maxSeconds = Number((scan.config as Record<string, unknown>)?.max_seconds ?? 0);
  const phaseIndex = PHASES.indexOf(scan.phase ?? (scan.state === "queued" ? "queued" : "done"));
  const severity = (counters.findings_by_severity ?? {}) as Record<string, number>;

  return (
    <>
      <div className="page-head">
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
            <h1>{scan.target_name || "Scan"}</h1>
            <Badge value={scan.state} />
            {scan.outcome ? <Badge value={scan.outcome} /> : null}
            {scan.partial ? <Badge value="partial" label="partial results" /> : null}
          </div>
          <p className="lede mono" style={{ fontSize: 12 }}>
            {scan.id} · profile {scan.profile ?? "standard"} · started {relativeTime(scan.started_at ?? scan.created_at)}
          </p>
        </div>
        <div style={{ flex: 1 }} />
        <RefreshToggle enabled={live} onToggle={setLive} intervalMs={2500} />
        <button onClick={reload} disabled={loading}>
          <Icon name="refresh" size={14} /> Refresh
        </button>
        {ACTIVE.has(scan.state) ? (
          <button className="danger" onClick={() => void cancel()} disabled={busy}>
            <Icon name="stop" size={14} /> Cancel
          </button>
        ) : null}
        {scan.retryable ? (
          <button onClick={() => void retry()} disabled={busy}>
            <Icon name="refresh" size={14} /> Retry
          </button>
        ) : null}
        <button className="danger" onClick={() => setConfirmDelete(true)} disabled={busy}>
          <Icon name="trash" size={14} /> Delete
        </button>
      </div>

      {error ? <div className="section"><ErrorState message={error} onRetry={reload} /></div> : null}

      {scan.state === "timed_out" ? (
        <div className="section">
          <Notice kind="warn" title="Scan exceeded its time limit">
            {scan.error_message || "The scan exceeded its configured wall-clock time limit. Partial findings and discovered endpoints have been preserved."}
            {maxSeconds > 0 ? <span className="mono"> · configured limit: {duration(maxSeconds)}</span> : null}
          </Notice>
        </div>
      ) : null}

      {scan.state === "failed" || scan.outcome === "policy_blocked" || scan.outcome === "unreachable" ? (
        <div className="section">
          <Notice kind="danger" title={`This scan did not assess the target (${scan.outcome || scan.state})`}>
            {scan.error_message || OUTCOME_HINT[scan.outcome ?? ""] || STATE_HINT[scan.state]}
            {scan.error_category ? <span className="mono"> · category: {scan.error_category}</span> : null}
          </Notice>
        </div>
      ) : null}

      {scan.state !== "queued" && scan.state !== "running" && Number(counters.endpoints_found ?? 0) === 0 && Number(counters.pages_fetched ?? 0) > 0 ? (
        <div className="section">
          <Notice kind="warn" title="No API endpoint candidates found">
            {events.data?.events.find((e) => e.kind === "discovery.zero_candidates")?.message ||
              "The scan found 0 endpoint candidates. Likely reasons: page is rendered via client-side JavaScript without discoverable static endpoints, out-of-scope external scripts were excluded, or all extracted paths were filtered out by the API-likeness gate."}
          </Notice>
        </div>
      ) : null}

      <div className="section">
        <Card className="tight">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8, gap: 12, flexWrap: "wrap" }}>
            <div className="card-title">
              Progress · {scan.phase ?? scan.state} · {duration(elapsed)}{maxSeconds > 0 ? ` / ${duration(maxSeconds)}` : ""}
            </div>
            <div className="cell-sub">
              {number(Number(counters.requests_used ?? 0))} requests · {number(Number(counters.pages_fetched ?? 0))} pages ·{" "}
              {number(Number(counters.scripts_analyzed ?? 0))} scripts
            </div>
          </div>
          <Progress
            value={ACTIVE.has(scan.state) ? Math.min(96, ((phaseIndex + 1) / PHASES.length) * 100) : 100}
            tone={scan.state === "failed" ? "danger" : scan.state === "timed_out" ? "warn" : scan.state === "completed" ? "ok" : undefined}
          />
          <div className="phases" style={{ marginTop: 10 }}>
            {PHASES.map((phase, index) => (
              <span
                key={phase}
                className={`phase ${index < phaseIndex ? "done" : index === phaseIndex ? "current" : ""}`}
              >
                {index < phaseIndex ? <Icon name="check" size={10} /> : null}
                {phase}
              </span>
            ))}
          </div>
        </Card>
      </div>

      <div className="grid cols-5 section">
        <div className="card tight"><div className="stat"><span className="stat-label">Endpoints found</span><span className="stat-value">{number(Number(counters.endpoints_found ?? 0))}</span></div></div>
        <div className="card tight"><div className="stat"><span className="stat-label">Validated</span><span className="stat-value">{number(Number(counters.endpoints_validated ?? 0))}</span></div></div>
        <div className="card tight"><div className="stat"><span className="stat-label">Shadow</span><span className="stat-value">{number(Number(counters.shadow_endpoints ?? 0))}</span></div></div>
        <div className="card tight"><div className="stat"><span className="stat-label">Findings</span><span className="stat-value">{number(Number(counters.findings ?? 0))}</span></div></div>
        <div className="card tight"><div className="stat"><span className="stat-label">Policy blocks</span><span className="stat-value">{number(Number(counters.policy_blocked ?? 0))}</span></div></div>
      </div>

      <Tabs
        tabs={[
          { id: "overview", label: "Overview" },
          { id: "findings", label: "Findings", count: Number(counters.findings ?? 0) },
          { id: "endpoints", label: "Endpoints", count: Number(counters.endpoints_found ?? 0) },
          { id: "events", label: "Events", count: events.data?.events.length },
          { id: "comparison", label: "Comparison" },
        ]}
        active={tab}
        onChange={setTab}
      />

      {tab === "overview" ? (
        <div className="split">
          <Card title="Configuration">
            <dl className="kv">
              <dt>Profile</dt>
              <dd>{scan.profile ?? "standard"}</dd>
              <dt>Max pages</dt>
              <dd>{String(scan.config?.max_pages ?? "—")}</dd>
              <dt>Max requests</dt>
              <dd>{String(scan.config?.max_requests ?? "—")}</dd>
              <dt>Max seconds</dt>
              <dd>{String(scan.config?.max_seconds ?? "—")}</dd>
              <dt>Crawler</dt>
              <dd>{scan.config?.include_crawler === false ? "off" : "on"}</dd>
              <dt>Specs</dt>
              <dd>{scan.config?.include_specs === false ? "off" : "on"}</dd>
              <dt>Source maps</dt>
              <dd>{scan.config?.include_source_maps === false ? "off" : "on"}</dd>
              <dt>Active validation</dt>
              <dd>{scan.config?.active_validation === false ? "off" : "on"}</dd>
              <dt>Seeds</dt>
              <dd className="mono">{JSON.stringify(scan.config?.seeds ?? [])}</dd>
              <dt>Outcome</dt>
              <dd>{scan.outcome ? `${scan.outcome} — ${OUTCOME_HINT[scan.outcome] ?? ""}` : "pending"}</dd>
              <dt>Finished</dt>
              <dd>{relativeTime(scan.finished_at)}</dd>
            </dl>
          </Card>
          <div className="grid" style={{ gap: 14 }}>
            <Card title="Findings by severity">
              <SeverityBars counts={severity} />
            </Card>
            <Card title="Exports">
              <div className="list">
                {EXPORTS.map((format) => (
                  <a
                    key={format.id}
                    className="list-row"
                    href={api.exportUrl(scan.id, format.id)}
                    download
                    title={format.hint}
                  >
                    <Icon name="download" size={14} />
                    <span className="grow">{format.label}</span>
                    <span className="cell-sub">{format.hint}</span>
                  </a>
                ))}
              </div>
            </Card>
          </div>
        </div>
      ) : null}

      {tab === "findings" ? <FindingsTab scanId={scan.id} /> : null}
      {tab === "endpoints" ? <EndpointsTab scanId={scan.id} /> : null}
      {tab === "events" ? <EventsTab events={events.data?.events ?? []} loading={events.loading} error={events.error} /> : null}
      {tab === "comparison" ? <ComparisonTab scanId={scan.id} /> : null}

      {confirmDelete ? (
        <ConfirmDialog
          title="Delete this scan?"
          message="The scan, its endpoint inventory, findings and evidence are removed. Exports already downloaded are unaffected."
          confirmLabel="Delete scan"
          danger
          busy={busy}
          onCancel={() => setConfirmDelete(false)}
          onConfirm={() => void remove()}
        />
      ) : null}
    </>
  );
}

function FindingsTab({ scanId }: { scanId: string }): JSX.Element {
  const [severity, setSeverity] = useState("");
  const [confidence, setConfidence] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(1);
  const pageSize = 20;
  const loader = useCallback(
    () =>
      api.findings(scanId, {
        ...(severity ? { severity } : {}),
        ...(confidence ? { confidence } : {}),
        ...(status ? { status } : {}),
        page: String(page),
        page_size: String(pageSize),
      }),
    [scanId, severity, confidence, status, page],
  );
  const { data, error, loading, reload } = useAsync(loader, [scanId, severity, confidence, status, page]);

  if (loading && !data) return <Loading label="Loading findings…" />;
  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (!data) return <Empty title="No findings" message="Nothing recorded yet." icon="shield" />;

  return (
    <>
      <div className="toolbar">
        <Select
          label="Severity"
          value={severity}
          onChange={(value) => { setSeverity(value); setPage(1); }}
          options={[
            { value: "", label: "Any severity" },
            { value: "critical", label: "Critical" },
            { value: "high", label: "High" },
            { value: "medium", label: "Medium" },
            { value: "low", label: "Low" },
            { value: "info", label: "Info" },
          ]}
        />
        <Select
          label="Confidence"
          value={confidence}
          onChange={(value) => { setConfidence(value); setPage(1); }}
          options={[
            { value: "", label: "Any confidence" },
            { value: "confirmed", label: "Confirmed" },
            { value: "high", label: "High" },
            { value: "medium", label: "Medium" },
            { value: "low", label: "Low" },
          ]}
        />
        <Select
          label="Status"
          value={status}
          onChange={(value) => { setStatus(value); setPage(1); }}
          options={[
            { value: "", label: "Any status" },
            { value: "confirmed", label: "Confirmed" },
            { value: "suspected", label: "Suspected" },
          ]}
        />
      </div>

      {data.findings.length === 0 ? (
        <Card><Empty title="No findings match" message="Adjust the filters to see more." icon="shield" /></Card>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Rule</th>
                <th>Title</th>
                <th>Endpoint</th>
                <th>Status</th>
                <th className="num">Risk</th>
              </tr>
            </thead>
            <tbody>
              {data.findings.map((finding: Finding) => (
                <tr key={finding.id} className="clickable" onClick={() => navigate("finding", finding.id)}>
                  <td><Badge value={finding.severity} /></td>
                  <td><Badge value={finding.confidence} /></td>
                  <td className="mono-cell">{finding.rule_id}</td>
                  <td className="cell-main">{finding.title}</td>
                  <td className="mono-cell truncate" style={{ maxWidth: 240 }}>
                    {finding.endpoint_method} {finding.endpoint_path ?? "—"}
                  </td>
                  <td><Badge value={finding.status} /></td>
                  <td className="num">{finding.risk_score.toFixed(1)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {data.total > pageSize ? (
        <Pagination page={page} pageSize={pageSize} total={data.total} onPage={setPage} />
      ) : null}
    </>
  );
}

function EndpointsTab({ scanId }: { scanId: string }): JSX.Element {
  const [query, setQuery] = useState("");
  const [classification, setClassification] = useState("");
  const [page, setPage] = useState(1);
  const pageSize = 25;
  const loader = useCallback(
    () =>
      api.endpoints(scanId, {
        ...(query ? { q: query } : {}),
        ...(classification ? { classification } : {}),
        page: String(page),
        page_size: String(pageSize),
      }),
    [scanId, query, classification, page],
  );
  const { data, error, loading, reload } = useAsync(loader, [scanId, query, classification, page]);

  if (loading && !data) return <Loading label="Loading endpoints…" />;
  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (!data) return <Empty title="No endpoints" icon="route" />;

  return (
    <>
      <div className="toolbar">
        <SearchInput value={query} onChange={(value) => { setQuery(value); setPage(1); }} placeholder="Search path" />
        <Select
          label="Classification"
          value={classification}
          onChange={(value) => { setClassification(value); setPage(1); }}
          options={[
            { value: "", label: "Any classification" },
            { value: "shadow", label: "Shadow" },
            { value: "documented", label: "Documented" },
            { value: "zombie", label: "Zombie" },
          ]}
        />
      </div>
      {data.endpoints.length === 0 ? (
        <Card><Empty title="No endpoints match" message="Adjust the filters." icon="route" /></Card>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Method</th>
                <th>Path</th>
                <th>Classification</th>
                <th>Validation</th>
                <th className="num">Status</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {data.endpoints.map((endpoint: Endpoint) => (
                <tr key={endpoint.id} className="clickable" onClick={() => navigate("endpoints", endpoint.id)}>
                  <td className="mono-cell">{endpoint.method}</td>
                  <td className="mono-cell truncate" style={{ maxWidth: 340 }}>{endpoint.path_template}</td>
                  <td><Badge value={endpoint.classification} /></td>
                  <td><Badge value={endpoint.validation_status} /></td>
                  <td className="num">{endpoint.response_status ?? "—"}</td>
                  <td className="cell-sub">{endpoint.source_types || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {data.total > pageSize ? (
        <Pagination page={page} pageSize={pageSize} total={data.total} onPage={setPage} />
      ) : null}
    </>
  );
}

function EventsTab({
  events,
  loading,
  error,
}: {
  events: ScanEvent[];
  loading: boolean;
  error: string;
}): JSX.Element {
  const [level, setLevel] = useState("");
  const filtered = useMemo(
    () => (level ? events.filter((event) => event.level === level) : events),
    [events, level],
  );
  if (loading && events.length === 0) return <Loading label="Loading events…" />;
  if (error) return <ErrorState message={error} />;
  if (events.length === 0) return <Card><Empty title="No events" message="Events appear as the worker progresses." icon="list" /></Card>;

  return (
    <Card
      title="Timeline"
      subtitle="Readable log of what the worker did"
      actions={
        <Select
          label="Level"
          value={level}
          onChange={setLevel}
          options={[
            { value: "", label: "All levels" },
            { value: "error", label: "Errors" },
            { value: "warning", label: "Warnings" },
            { value: "info", label: "Info" },
          ]}
        />
      }
    >
      <div className="timeline">
        {filtered.map((event) => (
          <div className="timeline-item" key={event.id}>
            <span className="timeline-time">{relativeTime(event.ts)}</span>
            <span>
              <span className={`timeline-level ${event.level}`}>{event.level}</span>
              <span className="mono" style={{ color: "var(--text-dim)", marginRight: 8 }}>{event.kind}</span>
              {event.message}
            </span>
          </div>
        ))}
      </div>
    </Card>
  );
}

function ComparisonTab({ scanId }: { scanId: string }): JSX.Element {
  const loader = useCallback(() => api.comparison(scanId), [scanId]);
  const { data, error, loading, reload } = useAsync(loader, [scanId]);
  if (loading) return <Loading label="Comparing with the previous scan…" />;
  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (!data) return <Empty title="Nothing to compare" icon="radar" />;

  if (!data.previous_scan_id) {
    return (
      <Card>
        <Empty
          title="No earlier scan to compare against"
          message="Comparisons need a previous completed scan of the same target."
          icon="radar"
        />
      </Card>
    );
  }

  const columns: { key: "new" | "removed" | "changed"; label: string; hint: string }[] = [
    { key: "new", label: `New endpoints (${data.new.length})`, hint: "present now, absent in the previous scan" },
    { key: "removed", label: `Removed (${data.removed.length})`, hint: "present before, absent now" },
    { key: "changed", label: `Status changed (${data.changed.length})`, hint: "same endpoint, different status" },
  ];

  return (
    <>
      <div className="section">
        <Notice kind="info" title={`Compared with scan ${data.previous_scan_id}`}>
          {data.findings_new.length} new finding(s) and {data.findings_resolved.length} resolved since the
          previous scan of this target.
        </Notice>
      </div>
      <div className="grid cols-3">
        {columns.map((column) => {
          const items = data[column.key];
          return (
            <Card key={column.key} title={column.label} subtitle={column.hint}>
              {items.length === 0 ? (
                <div className="cell-sub">Nothing {column.key === "removed" ? "removed" : column.key}.</div>
              ) : (
                <div className="list">
                  {items.slice(0, 60).map((item) => (
                    <div className="list-row" key={item.fingerprint}>
                      <span className="mono truncate" style={{ fontSize: 12 }}>
                        {item.method} {item.path}
                      </span>
                      <span className="cell-sub" style={{ marginLeft: "auto" }}>
                        {item.status ?? "—"}
                        {column.key === "changed" ? ` ← ${item.previous_status ?? "—"}` : ""}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </Card>
          );
        })}
      </div>
    </>
  );
}
