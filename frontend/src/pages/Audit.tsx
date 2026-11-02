import { useCallback, useState } from "react";
import { api } from "../api";
import type { AuditEntry } from "../api";
import type { PageProps } from "../App";
import { relativeTime } from "../lib/format";
import { useAsync } from "../useAsync";
import {
  Badge, Card, Empty, ErrorState, Icon, Loading, Notice, SearchInput, Select,
} from "../ui";

const COMMON_ACTIONS = [
  "auth.login",
  "auth.logout",
  "target.created",
  "target.approved",
  "target.updated",
  "target.deleted",
  "scan.created",
  "scan.cancel_requested",
  "scan.retried",
  "scan.deleted",
  "finding.triaged",
  "lab.started",
  "lab.stopped",
  "lab.restarted",
  "lab.reset",
  "lab.target_created",
  "lab.scan_queued",
];

export function AuditPage({ session }: PageProps): JSX.Element {
  const [action, setAction] = useState("");
  const [limit, setLimit] = useState("100");
  const [query, setQuery] = useState("");
  const isAdmin = session.user.role === "admin";

  const loader = useCallback(
    () => (isAdmin ? api.audit({ limit, ...(action ? { action } : {}) }) : Promise.resolve({ entries: [] })),
    [isAdmin, action, limit],
  );
  const { data, error, loading, reload } = useAsync<{ entries: AuditEntry[] }>(loader, [isAdmin, action, limit]);

  // Rendered for everyone: a page keeps its heading even when the body is a refusal, so the
  // document outline (and a screen reader's page summary) stays correct.
  const header = (extra?: React.ReactNode): JSX.Element => (
    <div className="page-head">
      <div>
        <h1>Audit log</h1>
        <p className="lede">
          Sign-ins, target changes, scan lifecycle actions, triage decisions and every lab control
          action. Entries are append-only.
        </p>
      </div>
      {extra ? (
        <>
          <div style={{ flex: 1 }} />
          {extra}
        </>
      ) : null}
    </div>
  );

  if (!isAdmin) {
    return (
      <>
        {header()}
        <Card>
          <Empty
            title="Administrators only"
            message="The audit log records security-sensitive actions and is restricted to administrators."
            icon="list"
          />
        </Card>
      </>
    );
  }

  const entries = (data?.entries ?? []).filter((entry) => {
    if (!query) return true;
    const needle = query.toLowerCase();
    return (
      entry.action.toLowerCase().includes(needle) ||
      (entry.object_id ?? "").toLowerCase().includes(needle) ||
      (entry.actor_id ?? "").toLowerCase().includes(needle)
    );
  });

  return (
    <>
      {header(
        <button onClick={reload} disabled={loading}>
          <Icon name="refresh" size={14} /> Refresh
        </button>,
      )}

      <div className="toolbar">
        <SearchInput value={query} onChange={setQuery} placeholder="Search action, object or actor" />
        <Select
          label="Action"
          value={action}
          onChange={setAction}
          options={[{ value: "", label: "All actions" }, ...COMMON_ACTIONS.map((value) => ({ value, label: value }))]}
        />
        <Select
          label="Rows"
          value={limit}
          onChange={setLimit}
          options={[
            { value: "50", label: "50" },
            { value: "100", label: "100" },
            { value: "250", label: "250" },
          ]}
        />
      </div>

      {loading && !data ? <Loading label="Loading audit entries…" /> : null}
      {error ? <div className="section"><ErrorState message={error} onRetry={reload} /></div> : null}

      {data && entries.length === 0 ? (
        <Card>
          <Empty
            title="No matching audit entries"
            message="Nothing has been recorded for this filter yet."
            icon="list"
          />
        </Card>
      ) : null}

      {entries.length > 0 ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Action</th>
                <th>Actor</th>
                <th>Object</th>
                <th>IP</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <tr key={entry.id}>
                  <td title={new Date(entry.ts * 1000).toLocaleString()}>{relativeTime(entry.ts)}</td>
                  <td><Badge value={entry.action.split(".")[0] ?? "action"} label={entry.action} /></td>
                  <td className="mono-cell">
                    {entry.actor_type}
                    {entry.actor_id ? <span className="cell-sub"> · {entry.actor_id.slice(0, 10)}</span> : null}
                  </td>
                  <td className="mono-cell">
                    {entry.object_type}
                    {entry.object_id ? <div className="cell-sub truncate">{String(entry.object_id).slice(0, 16)}</div> : null}
                  </td>
                  <td className="mono-cell">{entry.ip || "—"}</td>
                  <td className="cell-sub truncate" style={{ maxWidth: 260 }}>
                    {entry.details ? JSON.stringify(entry.details) : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      <div className="section" style={{ marginTop: 16 }}>
        <Notice kind="info" title="Why some actions look different">
          Lab control actions are recorded even when they fail, so an operator can see an attempted
          restart that never came up. Actor ids are organizational identifiers, never session tokens.
        </Notice>
      </div>
    </>
  );
}
