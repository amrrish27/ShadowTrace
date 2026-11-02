import { useCallback, useEffect, useMemo, useState } from "react";
import { api, ApiError } from "../api";
import type { TargetDetail } from "../api";
import type { PageProps } from "../App";
import { href } from "../lib/router";
import { relativeTime } from "../lib/format";
import {
  Badge, Card, ConfirmDialog, Empty, ErrorState, Icon, Loading, Modal, Notice,
  SearchInput, Select, Tabs,
} from "../ui";

type Mode = "ownership" | "admin" | "lab_allowlist";

const EMPTY_FORM = {
  name: "",
  base_url: "",
  ports: "80, 443",
  path_prefixes: "",
  authorization_mode: "admin" as Mode,
  justification: "",
  attestation: "Authorized for security assessment and testing.",
};

function parsePorts(value: string): number[] {
  return value
    .split(/[,\s]+/)
    .map((part) => Number.parseInt(part, 10))
    .filter((port) => Number.isInteger(port) && port > 0 && port <= 65535);
}

export function TargetsPage({ session, notify, focusId }: PageProps & { focusId?: string }): JSX.Element {
  const [targets, setTargets] = useState<TargetDetail[] | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [tab, setTab] = useState<"all" | "approved" | "pending">("all");
  const [creating, setCreating] = useState(false);
  const [detail, setDetail] = useState<TargetDetail | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await api.targets();
      setTargets(response.targets as TargetDetail[]);
      setError("");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not load targets.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!focusId || !targets) return;
    const match = targets.find((target) => target.id === focusId);
    if (match) setDetail(match);
  }, [focusId, targets]);

  const filtered = useMemo(() => {
    const rows = (targets ?? []).filter((target) => {
      if (tab === "approved" && target.authorization_status !== "approved") return false;
      if (tab === "pending" && target.authorization_status === "approved") return false;
      if (statusFilter && target.authorization_status !== statusFilter) return false;
      if (!query) return true;
      const needle = query.toLowerCase();
      return (
        target.name.toLowerCase().includes(needle) ||
        target.base_url.toLowerCase().includes(needle) ||
        target.authorization_mode.toLowerCase().includes(needle)
      );
    });
    return rows;
  }, [targets, tab, statusFilter, query]);

  async function approve(target: TargetDetail): Promise<void> {
    setBusy(true);
    try {
      await api.approveTarget(target.id, `Approved by ${session.user.email} from the dashboard.`);
      notify("ok", `${target.name} approved.`);
      setDetail(null);
      await load();
    } catch (err) {
      notify("error", err instanceof ApiError ? err.message : "Approval failed.");
    } finally {
      setBusy(false);
    }
  }

  async function verify(target: TargetDetail): Promise<void> {
    setBusy(true);
    try {
      await api.verifyTarget(target.id);
      notify("ok", `Ownership challenge recorded for ${target.name}.`);
      await load();
    } catch (err) {
      notify("error", err instanceof ApiError ? err.message : "Verification failed.");
    } finally {
      setBusy(false);
    }
  }

  async function remove(target: TargetDetail): Promise<void> {
    setBusy(true);
    try {
      await api.deleteTarget(target.id);
      notify("ok", `${target.name} deleted.`);
      setDetail(null);
      await load();
    } catch (err) {
      notify("error", err instanceof ApiError ? err.message : "Delete failed.");
    } finally {
      setBusy(false);
    }
  }

  const counts = {
    all: targets?.length ?? 0,
    approved: (targets ?? []).filter((target) => target.authorization_status === "approved").length,
    pending: (targets ?? []).filter((target) => target.authorization_status !== "approved").length,
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Targets</h1>
          <p className="lede">
            Only approved targets can be scanned. A target that resolves to a private address also
            needs an operator allow-list entry; the API records that decision as a signed grant.
          </p>
        </div>
        <div className="spacer" style={{ flex: 1 }} />
        <button className="primary" onClick={() => setCreating(true)}>
          <Icon name="plus" size={14} /> Register target
        </button>
        <button onClick={() => void load()} disabled={loading}>
          <Icon name="refresh" size={14} /> Refresh
        </button>
      </div>

      {error ? <div className="section"><ErrorState message={error} onRetry={load} /></div> : null}

      <Tabs
        tabs={[
          { id: "all", label: "All", count: counts.all },
          { id: "approved", label: "Approved", count: counts.approved },
          { id: "pending", label: "Pending", count: counts.pending },
        ]}
        active={tab}
        onChange={setTab}
      />

      <div className="toolbar">
        <SearchInput value={query} onChange={setQuery} placeholder="Search name, URL or mode" />
        <Select
          label="Filter by authorization status"
          value={statusFilter}
          onChange={setStatusFilter}
          options={[
            { value: "", label: "Any status" },
            { value: "approved", label: "Approved" },
            { value: "pending", label: "Pending" },
            { value: "rejected", label: "Rejected" },
          ]}
        />
      </div>

      {loading && !targets ? <Loading label="Loading targets…" /> : null}

      {targets && filtered.length === 0 ? (
        <Card>
          <Empty
            title={targets.length === 0 ? "No targets registered" : "No targets match the filter"}
            message={
              targets.length === 0
                ? "Register the site or API you are authorized to test. Nothing is scanned until an admin approves it."
                : "Adjust the search or status filter to see more."
            }
            action={
              targets.length === 0 ? (
                <button className="primary" onClick={() => setCreating(true)}>
                  <Icon name="plus" size={14} /> Register target
                </button>
              ) : null
            }
            icon="target"
          />
        </Card>
      ) : null}

      {filtered.length > 0 ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Target</th>
                <th>Mode</th>
                <th>Status</th>
                <th>Scan-ready</th>
                <th>Last scan</th>
                <th className="num">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((target) => (
                <tr key={target.id} className="clickable" onClick={() => setDetail(target)}>
                  <td>
                    <div className="cell-main">{target.name}</div>
                    <div className="mono-cell cell-sub">{target.base_url}</div>
                  </td>
                  <td><Badge value={target.authorization_mode} /></td>
                  <td><Badge value={target.authorization_status} /></td>
                  <td>
                    {target.scan_ready ? (
                      <Badge value="approved" label="ready" />
                    ) : (
                      <Badge value="pending" label="approval needed" />
                    )}
                  </td>
                  <td>{target.last_scan_at ? relativeTime(target.last_scan_at) : "never"}</td>
                  <td className="num" onClick={(event) => event.stopPropagation()}>
                    <a className="btn small" href={href("scans")}>
                      Scans
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {creating ? (
        <CreateTargetModal
          onClose={() => setCreating(false)}
          onCreated={async (message) => {
            notify("ok", message);
            setCreating(false);
            await load();
          }}
          notify={notify}
          isAdmin={session.user.role === "admin"}
        />
      ) : null}

      {detail ? (
        <TargetDetailModal
          target={detail}
          busy={busy}
          isAdmin={session.user.role === "admin"}
          onClose={() => setDetail(null)}
          onApprove={() => void approve(detail)}
          onVerify={() => void verify(detail)}
          onDelete={() => void remove(detail)}
          notify={notify}
          onSaved={async () => {
            setDetail(null);
            await load();
          }}
        />
      ) : null}
    </>
  );
}

function CreateTargetModal({
  onClose,
  onCreated,
  notify,
  isAdmin,
}: {
  onClose: () => void;
  onCreated: (message: string) => void;
  notify: (kind: "ok" | "error" | "info", message: string) => void;
  isAdmin: boolean;
}): JSX.Element {
  const [form, setForm] = useState(() => ({
    ...EMPTY_FORM,
    authorization_mode: (isAdmin ? "admin" : "ownership") as Mode,
  }));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const patch = (update: Partial<typeof EMPTY_FORM>): void => setForm((current) => ({ ...current, ...update }));

  function handleBaseUrlChange(url: string): void {
    let newPorts = form.ports;
    let newMode = form.authorization_mode;
    const trimmed = url.trim();
    if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
      try {
        const u = new URL(trimmed);
        const urlPort = u.port ? parseInt(u.port, 10) : (u.protocol === "https:" ? 443 : 80);
        const current = parsePorts(form.ports);
        if (!current.includes(urlPort)) {
          newPorts = String(urlPort);
        }
        if (u.hostname === "127.0.0.1" || u.hostname === "localhost") {
          newMode = "lab_allowlist";
        } else if (newMode === "lab_allowlist") {
          newMode = isAdmin ? "admin" : "ownership";
        }
      } catch (_) {}
    }
    patch({ base_url: url, ports: newPorts, authorization_mode: newMode });
  }

  async function submit(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const trimmedUrl = form.base_url.trim();
      let ports = parsePorts(form.ports);

      // Auto-include base_url port in authorized ports so submission never fails with port mismatch
      let detectedPort: number | null = null;
      try {
        const u = new URL(trimmedUrl);
        detectedPort = u.port ? parseInt(u.port, 10) : (u.protocol === "https:" ? 443 : 80);
      } catch (_) {}

      if (detectedPort && !ports.includes(detectedPort)) {
        ports.push(detectedPort);
      }
      if (ports.length === 0) {
        ports = detectedPort ? [detectedPort] : [80, 443];
      }

      // Auto-switch away from lab_allowlist if registering an external internet target
      let authMode = form.authorization_mode;
      if (trimmedUrl) {
        try {
          const u = new URL(trimmedUrl);
          if (u.hostname !== "127.0.0.1" && u.hostname !== "localhost" && authMode === "lab_allowlist") {
            authMode = isAdmin ? "admin" : "ownership";
          }
        } catch (_) {}
      }

      const payload: Record<string, unknown> = {
        name: form.name.trim(),
        base_url: trimmedUrl,
        ports,
        path_prefixes: form.path_prefixes
          .split(/[,\s]+/)
          .map((part) => part.trim())
          .filter(Boolean),
        authorization_mode: authMode,
        attestation: form.attestation.trim(),
      };
      if (form.justification.trim()) payload.justification = form.justification.trim();
      const response = await api.createTarget(payload);
      const status = (response.target as TargetDetail).authorization_status;
      onCreated(
        status === "approved"
          ? `${response.target.name} registered and approved.`
          : `${response.target.name} registered — an admin must approve it before scanning.`,
      );
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Could not register the target.";
      setError(message);
      notify("error", message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title="Register a target"
      onClose={onClose}
      footer={
        <>
          <button onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="primary" onClick={submit} disabled={busy || !form.name || !form.base_url}>
            {busy ? "Registering…" : "Register target"}
          </button>
        </>
      }
    >
      <form onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        <label className="field">
          Name
          <input value={form.name} onChange={(event) => patch({ name: event.target.value })} required autoFocus />
        </label>
        <label className="field">
          Base URL
          <input
            value={form.base_url}
            onChange={(event) => handleBaseUrlChange(event.target.value)}
            placeholder="https://example.com"
            required
          />
        </label>
        <div className="field-row">
          <label className="field">
            Authorized ports
            <input value={form.ports} onChange={(event) => patch({ ports: event.target.value })} />
          </label>
          <label className="field">
            Authorization mode
            <select
              value={form.authorization_mode}
              onChange={(event) => patch({ authorization_mode: event.target.value as Mode })}
            >
              <option value="ownership">ownership — you control the host</option>
              <option value="admin">admin — an administrator asserted it</option>
              <option value="lab_allowlist">lab_allowlist — operator-allow-listed lab</option>
            </select>
          </label>
        </div>
        <label className="field">
          Path prefixes (optional, one per line or comma separated)
          <input value={form.path_prefixes} onChange={(event) => patch({ path_prefixes: event.target.value })} />
        </label>
        <label className="field">
          Attestation
          <textarea
            value={form.attestation}
            onChange={(event) => patch({ attestation: event.target.value })}
            placeholder="Describe the written authorization for testing this target."
          />
        </label>
        <label className="field">
          Justification (optional)
          <input value={form.justification} onChange={(event) => patch({ justification: event.target.value })} />
        </label>
        {error ? <ErrorState title="Registration failed" message={error} /> : null}
        <Notice kind="info">
          {isAdmin
            ? "Targets you register in admin mode are approved immediately. Loopback and RFC1918 hosts also need an operator allow-list entry."
            : "A target registered by an analyst stays pending until an administrator approves it."}
        </Notice>
      </form>
    </Modal>
  );
}

function TargetDetailModal({
  target,
  busy,
  isAdmin,
  onClose,
  onApprove,
  onVerify,
  onDelete,
  onSaved,
  notify,
}: {
  target: TargetDetail;
  busy: boolean;
  isAdmin: boolean;
  onClose: () => void;
  onApprove: () => void;
  onVerify: () => void;
  onDelete: () => void;
  onSaved: () => Promise<void>;
  notify: (kind: "ok" | "error" | "info", message: string) => void;
}): JSX.Element {
  const [editing, setEditing] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [form, setForm] = useState({
    name: target.name,
    base_url: target.base_url,
    ports: Array.isArray(target.ports) ? target.ports.join(", ") : String(target.ports ?? ""),
    path_prefixes: Array.isArray(target.path_prefixes) ? target.path_prefixes.join(", ") : String(target.path_prefixes ?? ""),
    authorization_mode: (target.authorization_mode as Mode) ?? "ownership",
  });
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState("");

  async function save(): Promise<void> {
    setSaving(true);
    setSaveError("");
    try {
      const { target: updated } = await api.updateTarget(target.id, {
        name: form.name,
        base_url: form.base_url,
        ports: parsePorts(form.ports),
        path_prefixes: form.path_prefixes.split(/[,\s]+/).filter(Boolean),
        authorization_mode: form.authorization_mode,
      });
      // Changing what gets attacked invalidates the approval server-side. Say so, rather
      // than reporting a bare success and leaving the next scan to fail with a 409.
      notify(
        "ok",
        updated.authorization_status === "approved"
          ? "Target updated."
          : "Target updated — its security scope changed, so an administrator must approve it again before it can be scanned.",
      );
      await onSaved();
    } catch (err) {
      setSaveError(err instanceof ApiError ? err.message : "Could not update the target.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <Modal
        title={target.name}
        onClose={onClose}
        footer={
          <>
            <button className="danger" onClick={() => setConfirmDelete(true)} disabled={busy}>
              <Icon name="trash" size={13} /> Delete
            </button>
            <div style={{ flex: 1 }} />
            {editing ? (
              <>
                <button onClick={() => setEditing(false)} disabled={saving}>
                  Cancel edit
                </button>
                <button className="primary" onClick={() => void save()} disabled={saving}>
                  {saving ? "Saving…" : "Save changes"}
                </button>
              </>
            ) : (
              <>
                <button onClick={() => setEditing(true)}>Edit</button>
                {isAdmin && target.authorization_status !== "approved" ? (
                  <button className="primary" onClick={onApprove} disabled={busy}>
                    Approve
                  </button>
                ) : null}
                <button onClick={onVerify} disabled={busy}>
                  Verify ownership
                </button>
              </>
            )}
          </>
        }
      >
        {editing ? (
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <label className="field">
              Name
              <input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} />
            </label>
            <label className="field">
              Base URL
              <input value={form.base_url} onChange={(event) => setForm({ ...form, base_url: event.target.value })} />
            </label>
            <div className="field-row">
              <label className="field">
                Ports
                <input value={form.ports} onChange={(event) => setForm({ ...form, ports: event.target.value })} />
              </label>
              <label className="field">
                Mode
                <select
                  value={form.authorization_mode}
                  onChange={(event) => setForm({ ...form, authorization_mode: event.target.value as Mode })}
                  disabled={!isAdmin}
                >
                  <option value="ownership">ownership</option>
                  <option value="admin">admin</option>
                  <option value="lab_allowlist">lab_allowlist</option>
                </select>
              </label>
            </div>
            <label className="field">
              Path prefixes
              <input
                value={form.path_prefixes}
                onChange={(event) => setForm({ ...form, path_prefixes: event.target.value })}
              />
            </label>
            {saveError ? <ErrorState title="Update failed" message={saveError} /> : null}
            <Notice kind="warn">
              Changing the host or port of a target with an active scan is refused. Only an admin can
              change the authorization mode.
            </Notice>
          </div>
        ) : (
          <>
            <dl className="kv">
              <dt>Base URL</dt>
              <dd className="mono">{target.base_url}</dd>
              <dt>Host</dt>
              <dd className="mono">{target.host}</dd>
              <dt>Mode</dt>
              <dd><Badge value={target.authorization_mode} /></dd>
              <dt>Status</dt>
              <dd><Badge value={target.authorization_status} /></dd>
              <dt>Lab grant</dt>
              <dd>{target.lab_granted ? "signed grant present" : "none"}</dd>
              <dt>Scan-ready</dt>
              <dd>{target.scan_ready ? "yes" : "needs approval"}</dd>
              <dt>Created</dt>
              <dd>{target.created_at ? relativeTime(target.created_at) : "—"}</dd>
              <dt>Verified</dt>
              <dd>{target.verified_at ? relativeTime(target.verified_at) : "not verified"}</dd>
            </dl>
            <Notice kind="info" title="What is stored">
              The grant is a truncated signature over the target id, scheme, host and port. The
              signature itself is never returned by the API or shown here.
            </Notice>
            <TargetBaselinesSection targetId={target.id} notify={notify} />
            <TargetHarSection targetId={target.id} notify={notify} />
          </>
        )}
      </Modal>
      {confirmDelete ? (
        <ConfirmDialog
          title="Delete target?"
          message={`Deleting ${target.name} removes it and its scans from this organization. This cannot be undone.`}
          confirmLabel="Delete target"
          danger
          busy={busy}
          onCancel={() => setConfirmDelete(false)}
          onConfirm={onDelete}
        />
      ) : null}
    </>
  );
}

function TargetBaselinesSection({
  targetId,
  notify,
}: {
  targetId: string;
  notify: (kind: "ok" | "error" | "info", message: string) => void;
}): JSX.Element {
  const [baselines, setBaselines] = useState<
    { id: string; source: string; source_ref: string; endpoint_count: number; created_at: number }[]
  >([]);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const res = await api.listBaselines(targetId);
      setBaselines(res.baselines || []);
    } catch (_) {}
  }, [targetId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleFileUpload(event: React.ChangeEvent<HTMLInputElement>): Promise<void> {
    const file = event.target.files?.[0];
    if (!file) return;
    setUploading(true);
    setError("");
    try {
      const text = await file.text();
      const res = await api.createBaseline(targetId, {
        source: "upload",
        content: text,
      });
      notify("ok", `Baseline uploaded (${res.endpoint_count} endpoints).`);
      await load();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Failed to upload baseline.";
      setError(message);
      notify("error", message);
    } finally {
      setUploading(false);
      event.target.value = "";
    }
  }

  return (
    <div style={{ marginTop: 16, borderTop: "1px solid var(--border)", paddingTop: 14 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
        <strong>API Baselines ({baselines.length})</strong>
        <label className="btn small" style={{ cursor: uploading ? "wait" : "pointer", margin: 0 }}>
          <Icon name="plus" size={12} /> {uploading ? "Uploading…" : "Upload OpenAPI/Postman"}
          <input
            type="file"
            accept=".json,.yaml,.yml"
            style={{ display: "none" }}
            onChange={(e) => void handleFileUpload(e)}
            disabled={uploading}
          />
        </label>
      </div>
      {error ? <Notice kind="danger">{error}</Notice> : null}
      {baselines.length === 0 ? (
        <div className="cell-sub">No baselines uploaded yet. Upload an OpenAPI or Postman spec to establish ground truth.</div>
      ) : (
        <div className="list">
          {baselines.map((b) => (
            <div className="list-row" key={b.id} style={{ fontSize: 13 }}>
              <span className="mono truncate" style={{ flex: 1 }}>{b.source_ref}</span>
              <span className="cell-sub">{b.endpoint_count} endpoints ({b.source})</span>
              <span className="cell-sub">{relativeTime(b.created_at)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function TargetHarSection({
  targetId,
  notify,
}: {
  targetId: string;
  notify: (kind: "ok" | "error" | "info", message: string) => void;
}): JSX.Element {
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState("");
  const [lastResult, setLastResult] = useState<string | null>(null);

  async function handleFileUpload(event: React.ChangeEvent<HTMLInputElement>): Promise<void> {
    const file = event.target.files?.[0];
    if (!file) return;
    setUploading(true);
    setError("");
    setLastResult(null);
    try {
      const text = await file.text();
      const res = await api.importHar(targetId, text, file.name);
      const msg = `HAR imported: ${res.entries_in_scope} in-scope entries, ${res.endpoints_found} endpoints extracted.`;
      setLastResult(msg);
      notify("ok", msg);
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Failed to import HAR file.";
      setError(message);
      notify("error", message);
    } finally {
      setUploading(false);
      event.target.value = "";
    }
  }

  return (
    <div style={{ marginTop: 16, borderTop: "1px solid var(--border)", paddingTop: 14 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
        <strong>HAR Traffic Import</strong>
        <label className="btn small" style={{ cursor: uploading ? "wait" : "pointer", margin: 0 }}>
          <Icon name="upload" size={12} /> {uploading ? "Importing…" : "Upload HAR file"}
          <input
            type="file"
            accept=".har,.json"
            style={{ display: "none" }}
            onChange={(e) => void handleFileUpload(e)}
            disabled={uploading}
          />
        </label>
      </div>
      {error ? <Notice kind="danger">{error}</Notice> : null}
      {lastResult ? <Notice kind="ok">{lastResult}</Notice> : null}
      <div className="cell-sub">
        Upload a recorded HTTP Archive (HAR) file from browser DevTools or proxy to import real traffic endpoints.
      </div>
    </div>
  );
}
