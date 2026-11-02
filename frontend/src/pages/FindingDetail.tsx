import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { PageProps } from "../App";
import { relativeTime } from "../lib/format";
import { navigate } from "../lib/router";
import { useAsync } from "../useAsync";
import {
  Badge, Card, Empty, ErrorState, Icon, Loading, Notice, Tabs,
} from "../ui";
import { TriagePanel } from "./Findings";

interface FindingDetail {
  id: string;
  rule_id: string;
  title: string;
  severity: string;
  confidence: string;
  status: string;
  risk_score: number;
  exposure: number;
  rationale: string;
  limitations: string;
  remediation: string;
  evidence: Record<string, unknown>;
  endpoint_method?: string | null;
  endpoint_path?: string | null;
  endpoint_id?: string | null;
  scan_id: string;
  target_id: string;
  created_at?: number;
  [key: string]: unknown;
}

interface Response_ {
  finding: FindingDetail;
  triage: { status: string; reason: string; updated_at: number | null };
  triage_history: { ts: number; status: string; reason: string; user_email: string | null }[];
  endpoint: { id: string; method: string; path_template: string; classification: string; validation_status: string } | null;
  scoring: { severity: string; confidence: string; exposure: number; risk_score: number; explanation: string };
}

type Tab = "evidence" | "impact" | "repro" | "triage";

export function FindingDetailPage({ findingId, notify, session }: PageProps & { findingId: string }): JSX.Element {
  const loader = useCallback(() => api.finding(findingId) as unknown as Promise<Response_>, [findingId]);
  const { data, error, loading, reload } = useAsync<Response_>(loader, [findingId]);
  const [tab, setTab] = useState<Tab>("evidence");

  useEffect(() => {
    setTab("evidence");
  }, [findingId]);

  if (loading && !data) return <Loading label="Loading finding…" />;
  if (error && !data) return <ErrorState message={error} onRetry={reload} />;
  if (!data) return <Empty title="Finding not found" icon="shield" />;

  const finding = data.finding;
  const evidence = (finding.evidence ?? {}) as Record<string, unknown>;
  const request = (evidence.request ?? {}) as Record<string, unknown>;
  const response = (evidence.response ?? {}) as Record<string, unknown>;
  const headers = (response.headers ?? {}) as Record<string, string>;
  const labPath = String(request.url ?? "");

  return (
    <>
      <div className="page-head">
        <div>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <h1>{finding.title}</h1>
            <Badge value={finding.severity} />
            <Badge value={finding.confidence} />
            <Badge value={finding.status} />
          </div>
          <p className="lede">
            <span className="mono">{finding.rule_id}</span> · risk {finding.risk_score.toFixed(1)} · exposure{" "}
            {Number(finding.exposure ?? 0).toFixed(2)} · found{" "}
            {finding.created_at ? relativeTime(finding.created_at) : "—"}
          </p>
        </div>
        <div style={{ flex: 1 }} />
        <button onClick={() => navigate("scan", finding.scan_id)}>
          <Icon name="radar" size={14} /> Open scan
        </button>
        {data.endpoint ? (
          <button onClick={() => navigate("endpoints", data.endpoint?.id ?? "")}>
            <Icon name="route" size={14} /> Endpoint
          </button>
        ) : null}
      </div>

      <Tabs
        tabs={[
          { id: "evidence", label: "Evidence" },
          { id: "impact", label: "Impact & fix" },
          { id: "repro", label: "Reproduction" },
          { id: "triage", label: "Triage" },
        ]}
        active={tab}
        onChange={setTab}
      />

      {tab === "evidence" ? (
        <div className="split">
          <div className="grid" style={{ gap: 14 }}>
            <Card title="Captured request">
              <pre className="code">{`${String(request.method ?? "GET")} ${String(request.url ?? "—")}`}</pre>
            </Card>
            <Card title="Captured response">
              <dl className="kv" style={{ marginBottom: 10 }}>
                <dt>Status</dt>
                <dd className="mono">{String(response.status ?? "—")}</dd>
                <dt>Captured</dt>
                <dd>{String(evidence.captured ?? "—")}</dd>
              </dl>
              {Object.keys(headers).length ? (
                <pre className="code" style={{ marginBottom: 10 }}>
                  {Object.entries(headers)
                    .map(([key, value]) => `${key}: ${value}`)
                    .join("\n")}
                </pre>
              ) : null}
              <pre className="code redacted">{String(response.body_excerpt ?? "(no body captured)")}</pre>
            </Card>
          </div>
          <div className="grid" style={{ gap: 14 }}>
            <Card title="Why this was recorded">
              <p style={{ color: "var(--text-muted)", fontSize: 13 }}>{finding.rationale}</p>
            </Card>
            <Card title="Limitations">
              <p style={{ color: "var(--text-muted)", fontSize: 13 }}>{finding.limitations}</p>
            </Card>
            <Card title="Redaction">
              <Notice kind="info">
                Headers and bodies pass through the redactor before they are stored: credential-shaped
                values become <span className="mono">[redacted]</span>. Copies are truncated, so a long
                body may be cut off.
              </Notice>
            </Card>
          </div>
        </div>
      ) : null}

      {tab === "impact" ? (
        <div className="split">
          <Card title="Remediation">
            <p style={{ color: "var(--text-muted)", fontSize: 13 }}>{finding.remediation}</p>
          </Card>
          <Card title="Scoring">
            <dl className="kv">
              <dt>Severity</dt>
              <dd><Badge value={data.scoring.severity} /></dd>
              <dt>Confidence</dt>
              <dd><Badge value={data.scoring.confidence} /></dd>
              <dt>Exposure</dt>
              <dd>{Number(data.scoring.exposure ?? 0).toFixed(2)}</dd>
              <dt>Risk score</dt>
              <dd>{Number(data.scoring.risk_score ?? 0).toFixed(1)}</dd>
            </dl>
            <p className="cell-sub" style={{ marginTop: 10 }}>{data.scoring.explanation}</p>
          </Card>
        </div>
      ) : null}

      {tab === "repro" ? (
        <Card title="Reproduce safely" subtitle="Only run this against a target you are authorized to test">
          {data.endpoint ? (
            <>
              <pre className="code">{`curl -i -X ${data.endpoint.method} '${labPath || `https://<target>${data.endpoint.path_template}`}'`}</pre>
              <Notice kind="warn" title="Read-only by design">
                The scanner only ever sends GET, HEAD and OPTIONS. If a manual reproduction needs a
                state-changing request, it is your decision and your responsibility — this tool will not
                send one.
              </Notice>
            </>
          ) : (
            <Empty title="No endpoint attached" message="This finding is a property of the whole scan." icon="route" />
          )}
          {labPath.includes("127.0.0.1") || labPath.includes("localhost") ? (
            <Notice kind="info" title="Bundled lab target">
              This endpoint belongs to the local training lab, so the command above is safe to run as-is
              while the lab is running.
            </Notice>
          ) : null}
        </Card>
      ) : null}

      {tab === "triage" ? (
        <div className="split">
          <Card title="Set triage">
            {session.user.role === "viewer" ? (
              <Notice kind="warn">Viewers cannot change triage.</Notice>
            ) : (
              <TriagePanel findingId={finding.id} current={data.triage.status} onDone={reload} notify={notify} />
            )}
          </Card>
          <Card title="History">
            {data.triage_history.length === 0 ? (
              <div className="cell-sub">No triage changes recorded.</div>
            ) : (
              <div className="timeline">
                {data.triage_history.map((entry, index) => (
                  <div className="timeline-item" key={index}>
                    <span className="timeline-time">{relativeTime(entry.ts)}</span>
                    <span>
                      <Badge value={entry.status} /> {entry.reason}
                      {entry.user_email ? <span className="cell-sub"> · {entry.user_email}</span> : null}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      ) : null}
    </>
  );
}
