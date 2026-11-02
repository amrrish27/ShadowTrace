import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type { Finding, Scan } from "../api";
import type { PageProps } from "../App";
import { navigate } from "../lib/router";
import { useAsync } from "../useAsync";
import { Badge, Card, Empty, ErrorState, Loading, Modal, Select } from "../ui";

/**
 * Evidence workspace.
 *
 * Evidence is stored per finding, so this page is a redaction-safe viewer over the same
 * persisted record the finding detail page shows — there is no second copy of the data and
 * nothing is rendered as HTML.
 */
export function EvidencePage({ scanId }: PageProps & { scanId?: string }): JSX.Element {
  const scansLoader = useCallback(() => api.scans(), []);
  const scans = useAsync(scansLoader, []);
  const [selectedScan, setSelectedScan] = useState(scanId ?? "");
  const [selectedFinding, setSelectedFinding] = useState<string | null>(null);

  useEffect(() => {
    if (!selectedScan && scans.data?.scans.length) {
      const list = scans.data.scans;
      const completed = list.find((scan: Scan) => scan.state === "completed");
      const first = completed ?? list[0];
      if (first) setSelectedScan(first.id);
    }
  }, [scans.data, selectedScan]);

  const findingsLoader = useCallback(
    () => (selectedScan ? api.findings(selectedScan, { page_size: "100" }) : Promise.resolve({ findings: [], total: 0 })),
    [selectedScan],
  );
  const findings = useAsync<{ findings: Finding[]; total: number }>(findingsLoader, [selectedScan]);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Evidence</h1>
          <p className="lede">
            Captured request and response excerpts for each finding, with credential-shaped values
            redacted before storage. Bodies are rendered as text, never as HTML.
          </p>
        </div>
        <div style={{ flex: 1 }} />
        <div style={{ minWidth: 280 }}>
          <Select
            label="Scan"
            value={selectedScan}
            onChange={setSelectedScan}
            options={[
              { value: "", label: "Choose a scan…" },
              ...(scans.data?.scans ?? []).map((scan: Scan) => ({
                value: scan.id,
                label: `${scan.target_name || "scan"} · ${scan.state} · ${new Date(scan.created_at * 1000).toLocaleString()}`,
              })),
            ]}
          />
        </div>
      </div>

      {!selectedScan ? (
        <Card>
          <Empty
            title="Select a scan"
            message="Evidence belongs to a scan, so pick one to browse what it captured."
            icon="file"
          />
        </Card>
      ) : null}

      {findings.loading ? <Loading label="Loading evidence…" /> : null}
      {findings.error ? <ErrorState message={findings.error} onRetry={findings.reload} /> : null}

      {selectedScan && findings.data && findings.data.findings.length === 0 ? (
        <Card>
          <Empty
            title="No evidence for this scan"
            message="Evidence is attached to findings. A scan that produced no findings captured nothing to show."
            icon="file"
          />
        </Card>
      ) : null}

      {findings.data && findings.data.findings.length > 0 ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Rule</th>
                <th>Finding</th>
                <th>Endpoint</th>
                <th className="num">Risk</th>
                <th className="num">Evidence</th>
              </tr>
            </thead>
            <tbody>
              {findings.data.findings.map((finding) => (
                <tr key={finding.id}>
                  <td><Badge value={finding.severity} /></td>
                  <td className="mono-cell">{finding.rule_id}</td>
                  <td
                    className="cell-main clickable"
                    onClick={() => navigate("finding", finding.id)}
                    style={{ cursor: "pointer" }}
                  >
                    {finding.title}
                  </td>
                  <td className="mono-cell truncate" style={{ maxWidth: 260 }}>
                    {finding.endpoint_method} {finding.endpoint_path ?? "—"}
                  </td>
                  <td className="num">{finding.risk_score.toFixed(1)}</td>
                  <td className="num">
                    <button className="small" onClick={() => setSelectedFinding(finding.id)}>
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {selectedFinding ? (
        <EvidenceModal findingId={selectedFinding} onClose={() => setSelectedFinding(null)} />
      ) : null}
    </>
  );
}

interface EvidencePayload {
  finding: { title: string; rule_id: string; evidence: Record<string, unknown> };
}

function EvidenceModal({ findingId, onClose }: { findingId: string; onClose: () => void }): JSX.Element {
  const loader = useCallback(() => api.finding(findingId) as unknown as Promise<EvidencePayload>, [findingId]);
  const { data, error, loading, reload } = useAsync<EvidencePayload>(loader, [findingId]);

  const parts = useMemo(() => {
    const evidence = (data?.finding.evidence ?? {}) as Record<string, unknown>;
    const request = (evidence.request ?? {}) as Record<string, unknown>;
    const response = (evidence.response ?? {}) as Record<string, unknown>;
    return {
      requestLine: `${String(request.method ?? "GET")} ${String(request.url ?? "")}`,
      status: String(response.status ?? "—"),
      headers: (response.headers ?? {}) as Record<string, string>,
      body: String(response.body_excerpt ?? ""),
      captured: String(evidence.captured ?? ""),
    };
  }, [data]);

  return (
    <Modal
      title={data ? data.finding.title : "Evidence"}
      onClose={onClose}
      footer={
        <>
          <button onClick={() => navigate("finding", findingId)}>Open finding</button>
          <button onClick={onClose}>Close</button>
        </>
      }
    >
      {loading && !data ? <Loading label="Loading evidence…" /> : null}
      {error ? <ErrorState message={error} onRetry={reload} /> : null}
      {data ? (
        <>
          <div className="cell-sub">
            {data.finding.rule_id} · {parts.captured}
          </div>
          <pre className="code">{parts.requestLine}</pre>
          <div className="cell-sub">HTTP {parts.status}</div>
          {Object.keys(parts.headers).length ? (
            <pre className="code">
              {Object.entries(parts.headers)
                .map(([key, value]) => `${key}: ${value}`)
                .join("\n")}
            </pre>
          ) : null}
          <pre className="code redacted">{parts.body || "(no body captured)"}</pre>
        </>
      ) : null}
    </Modal>
  );
}
