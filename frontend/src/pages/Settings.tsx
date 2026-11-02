import React, { useCallback, useState } from "react";
import { api } from "../api";
import type { WorkerHealth } from "../api";
import type { PageProps } from "../App";
import { relativeTime } from "../lib/format";
import { useAsync } from "../useAsync";
import {
  Badge, Card, Empty, ErrorState, Icon, Loading, Modal, Notice, Select,
} from "../ui";

export function SettingsPage({ session, theme, setTheme, notify }: PageProps): JSX.Element {
  const [changing, setChanging] = useState(false);
  const rules = useAsync(useCallback(() => api.rules(), []), []);
  const isAdmin = session.user.role === "admin";
  const workers = useAsync(useCallback(() => (isAdmin ? api.workers() : Promise.resolve(null)), [isAdmin]), [isAdmin]);
  const settings = useAsync(useCallback(() => (isAdmin ? api.adminSettings() : Promise.resolve(null)), [isAdmin]), [isAdmin]);
  const config = useAsync(useCallback(() => api.runtimeConfig(), []), []);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Settings</h1>
          <p className="lede">
            These values come from the running API&apos;s configuration. Most are deployment settings and
            are intentionally read-only in the browser.
          </p>
        </div>
      </div>

      <div className="split section">
        <Card title="Runtime" subtitle="Read from the live process">
          {config.loading ? <Loading label="Reading configuration…" /> : null}
          {config.error ? <ErrorState message={config.error} onRetry={config.reload} /> : null}
          {config.data ? (
            <dl className="kv">
              <dt>Environment</dt>
              <dd><Badge value={config.data.environment} /></dd>
              <dt>Scanning</dt>
              <dd>{config.data.scanning_enabled ? "enabled" : "disabled by the operator"}</dd>
              {Object.entries(config.data)
                .filter(([key]) => !["environment", "scanning_enabled"].includes(key))
                .map(([key, value]) => (
                  <React.Fragment key={key}>
                    <dt>{key.replace(/_/g, " ")}</dt>
                    <dd className="mono" style={{ fontSize: 12 }}>
                      {typeof value === "object" ? JSON.stringify(value) : String(value)}
                    </dd>
                  </React.Fragment>
                ))}
            </dl>
          ) : null}
        </Card>

        <div className="grid" style={{ gap: 14 }}>
          <Card title="Appearance">
            <label className="field">
              Theme
              <select value={theme} onChange={(event) => setTheme(event.target.value as "dark" | "light")}>
                <option value="dark">Dark</option>
                <option value="light">Light</option>
              </select>
            </label>
            <p className="cell-sub" style={{ marginTop: 8 }}>
              The choice is stored in this browser only. Both themes meet WCAG AA contrast for body text.
            </p>
          </Card>
          <Card title="Your account">
            <dl className="kv">
              <dt>Name</dt>
              <dd>{session.user.name}</dd>
              <dt>Email</dt>
              <dd className="mono">{session.user.email}</dd>
              <dt>Role</dt>
              <dd><Badge value={session.user.role} /></dd>
              <dt>Organization</dt>
              <dd>{session.organization}</dd>
            </dl>
            <p className="cell-sub" style={{ marginTop: 8 }}>
              Sessions expire server-side; sign out from the top bar to revoke this one immediately.
            </p>
            <button className="btn small" style={{ marginTop: 8 }} onClick={() => setChanging(true)}>
              Change password
            </button>
          </Card>
        </div>
      </div>

      {!isAdmin ? (
        <Notice kind="info" title="Administrator view">
          Worker health and deployment limits are visible to administrators only.
        </Notice>
      ) : null}

      {changing ? (
        <ChangePasswordDialog
          onClose={() => setChanging(false)}
          onChanged={() => {
            setChanging(false);
            notify("ok", "Password changed. Other sessions were signed out.");
          }}
        />
      ) : null}

      {isAdmin ? (
        <div className="split section">
          <Card
            title="Scan workers"
            subtitle="A worker writes a heartbeat every poll"
            actions={
              <button className="small" onClick={workers.reload} disabled={workers.loading}>
                <Icon name="refresh" size={13} /> Refresh
              </button>
            }
          >
            {workers.loading ? <Loading label="Reading worker heartbeats…" /> : null}
            {workers.error ? <ErrorState message={workers.error} onRetry={workers.reload} /> : null}
            {workers.data && workers.data.workers.length === 0 ? (
              <Empty
                title="No worker has reported yet"
                message="Start the worker (start.cmd, or python -m app.workers.worker). Until then scans stay queued."
                icon="cog"
              />
            ) : null}
            {workers.data && workers.data.workers.length > 0 ? (
              <>
                <div style={{ marginBottom: 10 }}>
                  <Badge value={workers.data.alive > 0 ? "ok" : "failed"} label={`${workers.data.alive} alive`} />{" "}
                  <span className="cell-sub">
                    of {workers.data.workers.length} · window {workers.data.window_seconds}s
                  </span>
                </div>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Worker</th>
                        <th>Host</th>
                        <th>State</th>
                        <th className="num">Scans</th>
                        <th>Last seen</th>
                      </tr>
                    </thead>
                    <tbody>
                      {workers.data.workers.map((worker: WorkerHealth) => (
                        <tr key={worker.worker_id}>
                          <td className="mono-cell truncate" style={{ maxWidth: 220 }}>{worker.worker_id}</td>
                          <td>{worker.hostname}:{worker.pid ?? "—"}</td>
                          <td><Badge value={worker.alive ? "ok" : "failed"} label={worker.alive ? "alive" : "stale"} /></td>
                          <td className="num">{worker.scans_run}</td>
                          <td>{worker.alive ? `${worker.seconds_since_seen}s ago` : relativeTime(worker.last_seen_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            ) : null}
          </Card>

          <Card title="Limits" subtitle="Enforced server-side, not in the browser">
            {settings.loading ? <Loading label="Reading limits…" /> : null}
            {settings.error ? <ErrorState message={settings.error} onRetry={settings.reload} /> : null}
            {settings.data ? (
              <dl className="kv">
                {Object.entries(settings.data).map(([key, value]) => (
                  <React.Fragment key={key}>
                    <dt>{key.replace(/_/g, " ")}</dt>
                    <dd className="mono" style={{ fontSize: 12 }}>
                      {typeof value === "object" ? JSON.stringify(value) : String(value)}
                    </dd>
                  </React.Fragment>
                ))}
              </dl>
            ) : null}
          </Card>
        </div>
      ) : null}

      <Card
        title="Detection rules"
        subtitle="Every finding cites one of these"
        actions={
          <Select
            label="Sort"
            value="id"
            onChange={() => undefined}
            options={[{ value: "id", label: "By rule id" }]}
          />
        }
      >
        {rules.loading ? <Loading label="Loading rules…" /> : null}
        {rules.error ? <ErrorState message={rules.error} onRetry={rules.reload} /> : null}
        {rules.data ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Title</th>
                  <th>Category</th>
                  <th>Severity</th>
                  <th>Confidence</th>
                  <th>Basis</th>
                </tr>
              </thead>
              <tbody>
                {rules.data.rules.map((rule) => (
                  <tr key={rule.id}>
                    <td className="mono-cell">{rule.id}</td>
                    <td>
                      <div className="cell-main">{rule.title}</div>
                      <div className="cell-sub">{rule.description}</div>
                    </td>
                    <td>{rule.category}</td>
                    <td><Badge value={rule.severity} /></td>
                    <td><Badge value={rule.confidence} /></td>
                    <td><Badge value={rule.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </Card>
    </>
  );
}

function ChangePasswordDialog({
  onClose,
  onChanged,
}: {
  onClose: () => void;
  onChanged: () => void;
}): JSX.Element {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [failure, setFailure] = useState("");
  const [busy, setBusy] = useState(false);
  const mismatch = confirm.length > 0 && next !== confirm;

  const submit = async (event: React.FormEvent): Promise<void> => {
    event.preventDefault();
    if (next !== confirm) {
      setFailure("The two new passwords do not match.");
      return;
    }
    setBusy(true);
    setFailure("");
    try {
      await api.changePassword(current, next);
      onChanged();
    } catch (err) {
      setFailure(err instanceof Error ? err.message : "The password could not be changed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title="Change your password"
      onClose={onClose}
      footer={
        <>
          <button onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="primary" onClick={submit} disabled={busy || mismatch || !current || !next}>
            {busy ? "Saving…" : "Change password"}
          </button>
        </>
      }
    >
      <form onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        <label className="field">
          Current password
          <input
            type="password"
            autoComplete="current-password"
            value={current}
            onChange={(event) => setCurrent(event.target.value)}
            required
            autoFocus
          />
        </label>
        <label className="field">
          New password
          <input
            type="password"
            autoComplete="new-password"
            value={next}
            onChange={(event) => setNext(event.target.value)}
            required
            minLength={12}
          />
        </label>
        <label className="field">
          Repeat new password
          <input
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(event) => setConfirm(event.target.value)}
            required
          />
        </label>
        {mismatch ? <p className="hint" style={{ color: "var(--danger)" }}>The two new passwords do not match.</p> : null}
        {failure ? <Notice kind="danger" title="Refused">{failure}</Notice> : null}
        <p className="hint">Every other session is signed out when the password changes.</p>
      </form>
    </Modal>
  );
}
