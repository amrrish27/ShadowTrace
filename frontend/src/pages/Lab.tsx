import { useCallback, useState } from "react";
import { api, ApiError } from "../api";
import type { LabMapping, LabScenario, LabStatus } from "../api";
import type { PageProps } from "../App";
import { duration } from "../lib/format";
import { navigate } from "../lib/router";
import { useAsync } from "../useAsync";
import {
  Badge, Card, ConfirmDialog, Empty, ErrorState, Icon, Loading, Notice, RefreshToggle, useInterval,
} from "../ui";

/**
 * Training lab.
 *
 * The page can only do what `app/api/lab.py` exposes: start, stop, restart, reset, register the
 * lab target and queue a scan. There is no endpoint that takes a command, a path or a URL, so
 * nothing on this page can be turned into arbitrary process execution.
 */
export function LabPage({ session, notify }: PageProps): JSX.Element {
  const [live, setLive] = useState(true);
  const [busy, setBusy] = useState("");
  const [confirm, setConfirm] = useState<"" | "reset" | "stop">("");
  const [scanBusy, setScanBusy] = useState(false);

  const status = useAsync(useCallback(() => api.labStatus(), []), []);
  const scenarios = useAsync(useCallback(() => api.labScenarios(), []), []);
  const mappings = useAsync(useCallback(() => api.labMappings(), []), []);

  useInterval(live ? status.reload : () => undefined, live ? 3000 : null);

  const lab: LabStatus | undefined = status.data?.lab;
  const isAdmin = session.user.role === "admin";

  async function action(name: "start" | "stop" | "restart" | "reset"): Promise<void> {
    setBusy(name);
    try {
      if (name === "start") await api.labStart();
      if (name === "stop") await api.labStop();
      if (name === "restart") await api.labRestart();
      if (name === "reset") await api.labReset();
      notify("ok", `Lab ${name === "reset" ? "data reset" : `${name} requested`}.`);
      status.reload();
    } catch (err) {
      notify("error", err instanceof ApiError ? err.message : `Could not ${name} the lab.`);
    } finally {
      setBusy("");
      setConfirm("");
    }
  }

  async function registerTarget(): Promise<void> {
    setScanBusy(true);
    try {
      const response = await api.labTarget();
      notify("ok", response.created ? "Lab target registered and approved." : "Lab target already registered.");
      status.reload();
    } catch (err) {
      notify("error", err instanceof ApiError ? err.message : "Could not register the lab target.");
    } finally {
      setScanBusy(false);
    }
  }

  async function scanLab(): Promise<void> {
    setScanBusy(true);
    try {
      const response = await api.labScan({
        idempotency_key: `ui-lab-${Date.now()}`,
        profile: "standard",
        max_pages: 30,
        max_scripts: 20,
        max_requests: 500,
        max_seconds: 300,
      });
      notify("ok", "Lab scan queued.");
      navigate("scan", response.scan.id);
    } catch (err) {
      notify("error", err instanceof ApiError ? err.message : "Could not queue the lab scan.");
    } finally {
      setScanBusy(false);
    }
  }

  if (status.loading && !lab) return <Loading label="Reading lab status…" />;
  if (status.error && !lab) return <ErrorState message={status.error} onRetry={status.reload} />;
  if (!lab) return <Empty title="Lab unavailable" icon="flask" />;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Training lab</h1>
          <p className="lede">{lab.warning}</p>
        </div>
        <div style={{ flex: 1 }} />
        <RefreshToggle enabled={live} onToggle={setLive} intervalMs={3000} />
        <button onClick={status.reload} disabled={status.loading}>
          <Icon name="refresh" size={14} /> Refresh
        </button>
      </div>

      {!lab.enabled ? (
        <div className="section">
          <Notice kind="warn" title="The lab is disabled on this deployment">
            Set <span className="mono">ST_LAB_ENABLED=true</span> and restart the API to use it. Lab
            control is refused outright when the API runs with <span className="mono">ST_ENV=production</span>.
          </Notice>
        </div>
      ) : null}

      {lab.enabled && !lab.allowlisted ? (
        <div className="section">
          <Notice kind="warn" title="The lab host is not in the operator allow-list">
            {lab.hint}
          </Notice>
        </div>
      ) : null}

      {lab.last_error ? (
        <div className="section">
          <Notice kind="danger" title="Last lab action failed">{lab.last_error}</Notice>
        </div>
      ) : null}

      <div className="grid cols-4 section">
        <Card className="tight">
          <div className="stat">
            <span className="stat-label"><Icon name="flask" size={13} /> Process</span>
            <span className="stat-value" style={{ fontSize: 20 }}>
              {lab.running ? (lab.healthy ? "running" : "starting") : "stopped"}
            </span>
            <span className="stat-hint">{lab.managed ? `managed · pid ${lab.pid}` : "not managed by this API"}</span>
          </div>
        </Card>
        <Card className="tight">
          <div className="stat">
            <span className="stat-label"><Icon name="clock" size={13} /> Uptime</span>
            <span className="stat-value" style={{ fontSize: 20 }}>{lab.running ? duration(lab.uptime_seconds) : "—"}</span>
            <span className="stat-hint">restart resets all demo data</span>
          </div>
        </Card>
        <Card className="tight">
          <div className="stat">
            <span className="stat-label"><Icon name="shield" size={13} /> Health</span>
            <span className="stat-value" style={{ fontSize: 20 }}>{lab.healthy ? "ok" : "unknown"}</span>
            <span className="stat-hint">{lab.lab_id || "no health payload"}</span>
          </div>
        </Card>
        <Card className="tight">
          <div className="stat">
            <span className="stat-label"><Icon name="target" size={13} /> Lab target</span>
            <span className="stat-value" style={{ fontSize: 20 }}>
              {lab.target ? lab.target.authorization_status : "none"}
            </span>
            <span className="stat-hint">
              {lab.target ? (lab.target.scan_ready ? "ready to scan" : "not approved") : "register below"}
            </span>
          </div>
        </Card>
      </div>

      <div className="section">
        <Card title="Control" subtitle="Every action is admin-only and written to the audit log">
          <div className="toolbar" style={{ marginBottom: 10 }}>
            <button className="primary" onClick={() => void action("start")} disabled={!isAdmin || !lab.enabled || lab.running || busy !== ""}>
              <Icon name="play" size={14} /> {busy === "start" ? "Starting…" : "Start"}
            </button>
            <button onClick={() => void action("restart")} disabled={!isAdmin || !lab.enabled || busy !== ""}>
              <Icon name="refresh" size={14} /> {busy === "restart" ? "Restarting…" : "Restart"}
            </button>
            <button className="danger" onClick={() => setConfirm("stop")} disabled={!isAdmin || !lab.running || busy !== ""}>
              <Icon name="stop" size={14} /> Stop
            </button>
            <span style={{ flex: 1 }} />
            <a className="btn" href={lab.url} target="_blank" rel="noreferrer noopener">
              <Icon name="external" size={14} /> Open storefront
            </a>
          </div>
          <div className="toolbar" style={{ marginBottom: 0 }}>
            <button onClick={() => void registerTarget()} disabled={scanBusy || !lab.enabled}>
              <Icon name="target" size={14} /> Register lab target
            </button>
            <button className="primary" onClick={() => void scanLab()} disabled={scanBusy || !lab.enabled || !lab.target?.scan_ready}>
              <Icon name="radar" size={14} /> {scanBusy ? "Working…" : "Scan the lab"}
            </button>
            <button className="danger" onClick={() => setConfirm("reset")} disabled={!isAdmin || !lab.enabled || busy !== ""}>
              <Icon name="trash" size={14} /> Reset lab data
            </button>
          </div>
          <p className="cell-sub" style={{ marginTop: 10 }}>
            <span className="mono">{lab.url}</span> · entrypoint{" "}
            <span className="mono">{lab.entrypoint}</span> · the supervisor runs one fixed command and
            never accepts a path, shell fragment or URL from the browser.
          </p>
        </Card>
      </div>

      <div className="section">
        <Card title="Scenario catalogue" subtitle="What the lab deliberately makes vulnerable">
          {scenarios.loading ? <Loading label="Loading scenarios…" /> : null}
          {scenarios.error ? <ErrorState message={scenarios.error} onRetry={scenarios.reload} /> : null}
          {scenarios.data ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Scenario</th>
                    <th>What it demonstrates</th>
                    <th>Expected rule</th>
                    <th>Demo URL</th>
                  </tr>
                </thead>
                <tbody>
                  {scenarios.data.scenarios.map((scenario: LabScenario) => (
                    <tr key={scenario.id}>
                      <td>
                        <div className="cell-main">{scenario.title}</div>
                        <div className="cell-sub">{scenario.category}</div>
                      </td>
                      <td style={{ maxWidth: 460 }}>
                        <div>{scenario.summary}</div>
                        <div className="cell-sub">Safe: {scenario.safe}</div>
                        {scenario.containment_note ? (
                          <div className="cell-sub">{scenario.containment_note}</div>
                        ) : null}
                      </td>
                      <td>
                        {scenario.expected_rules.map((rule) => (
                          <span key={rule} className="mono-cell" style={{ marginRight: 6 }}>{rule}</span>
                        ))}
                      </td>
                      <td>
                        <a className="mono-cell" href={`${lab.url}${scenario.path}`} target="_blank" rel="noreferrer noopener">
                          {scenario.path}
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </Card>
      </div>

      <div className="section">
        <Card title="Vulnerability → detecting rule" subtitle="Rule metadata read from the live registry">
          {mappings.loading ? <Loading label="Loading mapping…" /> : null}
          {mappings.error ? <ErrorState message={mappings.error} onRetry={mappings.reload} /> : null}
          {mappings.data ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Rule</th>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Confidence model</th>
                    <th>Scenarios</th>
                  </tr>
                </thead>
                <tbody>
                  {mappings.data.rules.map((rule: LabMapping) => (
                    <tr key={rule.rule_id}>
                      <td className="mono-cell">{rule.rule_id}</td>
                      <td className="cell-main">{rule.title}</td>
                      <td><Badge value={rule.severity} /></td>
                      <td><Badge value={rule.status} /></td>
                      <td className="mono-cell">{rule.scenarios.join(", ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </Card>
      </div>

      {lab.log_tail.length ? (
        <Card title="Lab log" subtitle="Last lines written by the lab process">
          <pre className="code">{lab.log_tail.join("\n")}</pre>
        </Card>
      ) : null}

      {confirm === "reset" ? (
        <ConfirmDialog
          title="Reset lab data?"
          message="The lab keeps every record in memory, so a reset restarts the process and returns all demo data to its initial state. Your ShadowTrace data is not touched."
          confirmLabel="Reset lab"
          danger
          busy={busy === "reset"}
          onCancel={() => setConfirm("")}
          onConfirm={() => void action("reset")}
        />
      ) : null}

      {confirm === "stop" ? (
        <ConfirmDialog
          title="Stop the lab?"
          message="The lab process is terminated. Scans queued against the lab will fail with an unreachable target until it is started again."
          confirmLabel="Stop lab"
          danger
          busy={busy === "stop"}
          onCancel={() => setConfirm("")}
          onConfirm={() => void action("stop")}
        />
      ) : null}
    </>
  );
}
