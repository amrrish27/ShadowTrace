import { useCallback, useMemo } from "react";
import { api } from "../api";
import type { PageProps } from "../App";
import { href } from "../lib/router";
import { number, relativeTime, SEVERITY_ORDER } from "../lib/format";
import { useAsync } from "../useAsync";
import {
  BarChart, Card, ColumnChart, Donut, Empty, ErrorState, Loading, Notice,
  SeverityBars, Stat, TrendLine,
} from "../ui";

/**
 * Overview.
 *
 * Every number on this page is read from `GET /api/v1/dashboard/overview`, which aggregates
 * the rows the scanner wrote. Nothing here is computed client-side except percentages, and
 * no value is invented when the API omits a key (`normalizeOverview` fills zeros).
 */
export function OverviewPage(_props: PageProps): JSX.Element {
  const loader = useCallback(() => api.overview(), []);
  const { data, error, loading, reload } = useAsync(loader, []);

  const severityCounts = data?.findings_by_severity ?? {};
  const totalFindings = SEVERITY_ORDER.reduce((acc, key) => acc + (severityCounts[key] ?? 0), 0);
  const timeline = useMemo(
    () => (data?.scan_timeline ?? []).map((row) => ({ label: row.day, value: row.scans })),
    [data],
  );
  const endpointsPerScan = useMemo(
    () =>
      (data?.recent_scans ?? [])
        .slice()
        .reverse()
        .map((scan) => ({
          label: relativeTime(scan.created_at),
          hint: scan.target_name,
          value: Number(scan.counters.endpoints_found ?? 0),
        })),
    [data],
  );

  if (loading && !data) return <Loading label="Loading overview…" />;
  if (error && !data) return <ErrorState message={error} onRetry={reload} />;
  if (!data) return <Empty title="No data yet" message="Run a scan to populate the overview." />;

  return (
    <>
      {error ? <div className="section"><ErrorState message={error} onRetry={reload} /></div> : null}

      <div className="page-head">
        <div>
          <h1>Overview</h1>
          <p className="lede">
            What the scanner has seen across every authorized target: coverage, findings by
            severity, and the scans behind them. Every number is read from the API.
          </p>
        </div>
      </div>

      <div className="grid cols-5 section">
        <Stat label="Targets" value={number(data.targets.total)} hint={`${data.targets.approved} approved`} icon="target" />
        <Stat label="Endpoints" value={number(data.endpoints.total)} hint={`${data.endpoints.shadow} shadow`} icon="route" />
        <Stat label="Findings" value={number(totalFindings)} hint={`${data.triage.open ?? 0} open`} icon="shield" />
        <Stat label="Scans" value={number(Object.values(data.scans_by_state).reduce((a, b) => a + b, 0))} hint={`${data.scans_by_state.running ?? 0} running`} icon="radar" />
        <Stat label="Zombies" value={number(data.endpoints.zombie)} hint="documented but missing" icon="alert" />
      </div>

      <div className="split section">
        <Card
          title="Severity mix"
          subtitle="Open findings by severity across every scan"
          actions={<a className="btn small" href={href("findings")}>View findings</a>}
        >
          <Donut
            data={SEVERITY_ORDER.map((severity) => ({ label: severity, value: severityCounts[severity] ?? 0, tone: severity }))}
            centerValue={totalFindings}
            centerLabel="findings"
          />
          <div style={{ marginTop: 16 }}>
            <SeverityBars counts={severityCounts} />
          </div>
        </Card>

        <div className="grid" style={{ gap: 14 }}>
          <Card title="Scan history" subtitle="Scans per day">
            <TrendLine data={timeline} tone="brand" />
          </Card>
          <Card title="Endpoints discovered" subtitle="Per recent scan">
            <ColumnChart data={epointsPerScanSafe(endpointsPerScan)} tone="info" />
          </Card>
        </div>
      </div>

      <div className="split section">
        <Card
          title="Recent findings"
          subtitle="Highest risk first"
          actions={<a className="btn small" href={href("findings")}>All findings</a>}
        >
          {data.recent_findings.length === 0 ? (
            <Empty title="No findings recorded" message="Findings appear as soon as a scan completes analysis." icon="shield" />
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Rule</th>
                    <th>Title</th>
                    <th>Endpoint</th>
                    <th className="num">Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {data.recent_findings.slice(0, 8).map((finding) => (
                    <tr
                      key={finding.id}
                      className="clickable"
                      onClick={() => { window.location.hash = href("finding", finding.id); }}
                    >
                      <td><span className={`badge ${finding.severity}`}>{finding.severity}</span></td>
                      <td className="mono-cell">{finding.rule_id}</td>
                      <td className="cell-main">{finding.title}</td>
                      <td className="mono-cell truncate" style={{ maxWidth: 240 }}>
                        {finding.endpoint_method} {finding.endpoint_path ?? "—"}
                      </td>
                      <td className="num">{finding.risk_score.toFixed(1)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <Card title="Discovery sources" subtitle="Where endpoints were found">
          {data.source_breakdown.length === 0 ? (
            <Empty title="No discovery data" message="Sources are recorded per scan." icon="route" />
          ) : (
            <BarChart
              data={data.source_breakdown.map((row) => ({ label: row.source, value: row.endpoints }))}
              height={18}
            />
          )}
          <div style={{ marginTop: 14, fontSize: 12, color: "var(--text-muted)" }}>
            {data.scans_by_state.queued ? `${data.scans_by_state.queued} scan(s) queued` : "No scans queued"}
          </div>
        </Card>
      </div>

      <Card title="Recent scans" actions={<a className="btn small" href={href("scans")}>Open scans</a>}>
        {data.recent_scans.length === 0 ? (
          <Empty
            title="No scans yet"
            message="Register a target, then run a scan to populate the dashboard."
            action={<a className="btn primary" href={href("targets")}>Add a target</a>}
            icon="radar"
          />
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Target</th>
                  <th>State</th>
                  <th>Started</th>
                  <th className="num">Endpoints</th>
                  <th className="num">Findings</th>
                  <th className="num">Requests</th>
                </tr>
              </thead>
              <tbody>
                {data.recent_scans.map((scan) => (
                  <tr
                    key={scan.id}
                    className="clickable"
                    onClick={() => { window.location.hash = href("scan", scan.id); }}
                  >
                    <td className="cell-main">{scan.target_name}</td>
                    <td><span className={`badge ${scan.state}`}>{scan.state}</span></td>
                    <td>{relativeTime(scan.created_at)}</td>
                    <td className="num">{number(Number(scan.counters.endpoints_found ?? 0))}</td>
                    <td className="num">{number(Number(scan.counters.findings ?? 0))}</td>
                    <td className="num">{number(Number(scan.counters.requests_used ?? 0))}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {totalFindings === 0 && data.scans_by_state.completed ? (
        <div className="section" style={{ marginTop: 16 }}>
          <Notice kind="info" title="No findings is not the same as no problems">
            A completed scan reports only what the rules observed. Review the scan outcome and the
            endpoint inventory before treating a target as clean.
          </Notice>
        </div>
      ) : null}
    </>
  );
}

function epointsPerScanSafe(data: { label: string; value: number; hint?: string }[]): { label: string; value: number; hint?: string }[] {
  return data.filter((item) => Number.isFinite(item.value));
}
