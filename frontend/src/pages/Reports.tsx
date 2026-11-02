import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { Scan } from "../api";
import type { PageProps } from "../App";
import { relativeTime } from "../lib/format";
import { navigate } from "../lib/router";
import { useAsync } from "../useAsync";
import { Badge, Card, Empty, ErrorState, Icon, Loading, Notice, Select } from "../ui";

const FORMATS = [
  { id: "html", label: "HTML report", detail: "Self-contained, human readable, safe to share with a client." },
  { id: "markdown", label: "Markdown", detail: "Drops into a ticket, wiki or pull request." },
  { id: "json", label: "JSON bundle", detail: "Every persisted field, for automation and archiving." },
  { id: "csv_findings", label: "Findings CSV", detail: "One row per finding, for a spreadsheet or tracker import." },
  { id: "csv_inventory", label: "Inventory CSV", detail: "One row per endpoint, with classification and validation." },
  { id: "openapi_stub", label: "OpenAPI stub", detail: "An OpenAPI 3 document generated from the discovered inventory." },
];

export function ReportsPage({ scanId }: PageProps & { scanId?: string }): JSX.Element {
  const scans = useAsync(useCallback(() => api.scans(), []), []);
  const [selected, setSelected] = useState(scanId ?? "");

  useEffect(() => {
    if (!selected && scans.data?.scans.length) {
      const list = scans.data.scans;
      const completed = list.find((scan: Scan) => scan.state === "completed");
      const first = completed ?? list[0];
      if (first) setSelected(first.id);
    }
  }, [scans.data, selected]);

  const scan = scans.data?.scans.find((item: Scan) => item.id === selected);
  const reportable = scan && (scan.state === "completed" || scan.partial);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Reports</h1>
          <p className="lede">
            Exports are generated from the persisted scan — the same rows the UI reads. A report can
            therefore never contain a number the dashboard does not show.
          </p>
        </div>
        <div style={{ flex: 1 }} />
        <div style={{ minWidth: 300 }}>
          <Select
            label="Scan"
            value={selected}
            onChange={setSelected}
            options={[
              { value: "", label: "Choose a scan…" },
              ...(scans.data?.scans ?? []).map((item: Scan) => ({
                value: item.id,
                label: `${item.target_name || "scan"} · ${item.state} · ${relativeTime(item.created_at)}`,
              })),
            ]}
          />
        </div>
      </div>

      {scans.loading ? <Loading label="Loading scans…" /> : null}
      {scans.error ? <ErrorState message={scans.error} onRetry={scans.reload} /> : null}

      {!scans.loading && !scan ? (
        <Card>
          <Empty title="Pick a scan" message="Reports are produced per scan." icon="download" />
        </Card>
      ) : null}

      {scan ? (
        <>
          <div className="section">
            {reportable ? (
              <Notice kind="info" title={`Report for ${scan.target_name || "this target"}`}>
                {Number(scan.counters.findings ?? 0)} finding(s) across{" "}
                {Number(scan.counters.endpoints_found ?? 0)} endpoint(s). Generated{" "}
                {scan.finished_at ? relativeTime(scan.finished_at) : "when the scan finished"}.
              </Notice>
            ) : (
              <Notice kind="warn" title="This scan has not finished">
                A {scan.state} scan has no complete result set. The export will state that explicitly
                rather than presenting partial data as a finished assessment.
              </Notice>
            )}
          </div>

          <div className="grid cols-3 section">
            {FORMATS.map((format) => (
              <Card key={format.id} title={format.label} subtitle={format.detail}>
                <a className="btn primary" href={api.exportUrl(scan.id, format.id)} download>
                  <Icon name="download" size={14} /> Download
                </a>
              </Card>
            ))}
          </div>

          <Card title="What every export contains" subtitle="Consistent across formats">
            <dl className="kv">
              <dt>Target</dt>
              <dd className="mono">{scan.target_name || scan.target_id}</dd>
              <dt>Scan id</dt>
              <dd className="mono">{scan.id}</dd>
              <dt>State / outcome</dt>
              <dd>
                <Badge value={scan.state} /> {scan.outcome ? <Badge value={scan.outcome} /> : null}
              </dd>
              <dt>Scope</dt>
              <dd className="mono">
                max {String(scan.config?.max_pages ?? "—")} pages · {String(scan.config?.max_requests ?? "—")} requests
              </dd>
              <dt>Counters</dt>
              <dd>
                {Number(scan.counters.endpoints_found ?? 0)} endpoints ·{" "}
                {Number(scan.counters.endpoints_validated ?? 0)} validated ·{" "}
                {Number(scan.counters.findings ?? 0)} findings
              </dd>
              <dt>Methodology</dt>
              <dd>
                Read-only discovery (GET/HEAD/OPTIONS), reconciliation against the baseline, and rule
                evaluation with confidence and limitations recorded per finding.
              </dd>
            </dl>
          </Card>

          <div className="section" style={{ marginTop: 16 }}>
            <Notice kind="warn" title="Exports are evidence, not proof">
              A finding states what was observed. Absence of a finding is not evidence that a problem
              does not exist: the scan only sees what the target exposed to a read-only client.
            </Notice>
          </div>

          <div style={{ marginTop: 12 }}>
            <button onClick={() => navigate("scan", scan.id)}>
              <Icon name="radar" size={14} /> Open scan detail
            </button>
          </div>
        </>
      ) : null}
    </>
  );
}
