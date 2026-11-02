import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type { Finding, Target } from "../api";
import type { PageProps } from "../App";
import { navigate } from "../lib/router";
import { useAsync } from "../useAsync";
import {
  Badge, Card, Empty, ErrorState, Loading, Pagination, Select, SeverityBars,
} from "../ui";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export function FindingsPage({
  focusId,
  initialScan,
}: PageProps & { focusId?: string; initialScan?: string }): JSX.Element {
  const [severity, setSeverity] = useState("");
  const [confidence, setConfidence] = useState("");
  const [status, setStatus] = useState("");
  const [targetId, setTargetId] = useState("");
  const [scanId, setScanId] = useState(initialScan ?? "");
  const [page, setPage] = useState(1);
  const pageSize = 25;

  const targetsLoader = useCallback(() => api.targets(), []);
  const targets = useAsync(targetsLoader, []);

  const loader = useCallback(
    () =>
      api.allFindings({
        ...(severity ? { severity } : {}),
        ...(confidence ? { confidence } : {}),
        ...(status ? { status } : {}),
        ...(targetId ? { target_id: targetId } : {}),
        ...(scanId ? { scan_id: scanId } : {}),
        page: String(page),
        page_size: String(pageSize),
      }),
    [severity, confidence, status, targetId, scanId, page],
  );
  const { data, error, loading, reload } = useAsync(loader, [severity, confidence, status, targetId, scanId, page]);

  useEffect(() => {
    setPage(1);
  }, [severity, confidence, status, targetId, scanId]);

  useEffect(() => {
    if (focusId) navigate("finding", focusId);
  }, [focusId]);

  const counts = (data?.findings ?? []).reduce<Record<string, number>>((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Findings</h1>
          <p className="lede">
            <strong>Confirmed</strong> means the scanner observed the condition directly.{" "}
            <strong>Suspected</strong> means the observation is consistent with the issue but not proof
            of exploitability. Every finding links to the captured evidence.
          </p>
        </div>
      </div>

      <div className="split section">
        <Card title="Filters">
          <div className="toolbar" style={{ marginBottom: 0 }}>
            <Select
              label="Severity"
              value={severity}
              onChange={setSeverity}
              options={[{ value: "", label: "Any severity" }, ...SEVERITIES.map((value) => ({ value, label: value }))]}
            />
            <Select
              label="Confidence"
              value={confidence}
              onChange={setConfidence}
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
              onChange={setStatus}
              options={[
                { value: "", label: "Any status" },
                { value: "confirmed", label: "Confirmed" },
                { value: "suspected", label: "Suspected" },
              ]}
            />
            <Select
              label="Target"
              value={targetId}
              onChange={setTargetId}
              options={[
                { value: "", label: "Any target" },
                ...(targets.data?.targets ?? []).map((target: Target) => ({ value: target.id, label: target.name })),
              ]}
            />
            {initialScan || scanId ? (
              <button className="small" onClick={() => setScanId("")}>
                Clear scan filter
              </button>
            ) : null}
          </div>
        </Card>
        <Card title="Mix on this page" subtitle="Filter-aware severity distribution">
          <SeverityBars counts={counts} total={data?.findings.length ?? 0} />
        </Card>
      </div>

      {loading && !data ? <Loading label="Loading findings…" /> : null}
      {error ? <div className="section"><ErrorState message={error} onRetry={reload} /></div> : null}

      {data && data.findings.length === 0 ? (
        <Card>
          <Empty
            title={severity || confidence || status || targetId || scanId ? "No findings match" : "No findings yet"}
            message={
              severity || confidence || status || targetId || scanId
                ? "Loosen the filters to see more."
                : "Run a scan; findings appear as soon as analysis finishes."
            }
            icon="shield"
          />
        </Card>
      ) : null}

      {data && data.findings.length > 0 ? (
        <>
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
                    <td>
                      <div className="cell-main">{finding.title}</div>
                      {finding.triage_status && finding.triage_status !== "open" ? (
                        <div className="cell-sub">triage: {finding.triage_status.replace(/_/g, " ")}</div>
                      ) : null}
                    </td>
                    <td className="mono-cell truncate" style={{ maxWidth: 260 }}>
                      {finding.endpoint_method} {finding.endpoint_path ?? "—"}
                    </td>
                    <td><Badge value={finding.status} /></td>
                    <td className="num">{finding.risk_score.toFixed(1)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination page={page} pageSize={pageSize} total={data.total} onPage={setPage} />
        </>
      ) : null}
    </>
  );
}

export function TriagePanel({
  findingId,
  current,
  onDone,
  notify,
}: {
  findingId: string;
  current: string;
  onDone: () => void;
  notify: (kind: "ok" | "error" | "info", message: string) => void;
}): JSX.Element {
  const [status, setStatus] = useState(current || "open");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    setBusy(true);
    try {
      await api.triage(findingId, status, reason || "Updated from the dashboard.");
      notify("ok", "Triage saved.");
      onDone();
    } catch (err) {
      notify("error", err instanceof ApiError ? err.message : "Triage failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      <label className="field">
        Status
        <select value={status} onChange={(event) => setStatus(event.target.value)}>
          <option value="open">open</option>
          <option value="accepted_risk">accepted risk</option>
          <option value="false_positive">false positive</option>
          <option value="fixed">fixed</option>
        </select>
      </label>
      <label className="field">
        Reason (recorded in the audit trail)
        <input value={reason} onChange={(event) => setReason(event.target.value)} />
      </label>
      <button className="primary" type="submit" disabled={busy}>
        {busy ? "Saving…" : "Save triage"}
      </button>
    </form>
  );
}
