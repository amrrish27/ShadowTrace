/**
 * Member administration: who can sign in, with what role, and how to add or remove them.
 *
 * This page exists so that account management does not require a terminal. It drives the
 * admin-only endpoints in `backend/app/api/users.py` exactly: list, invite (a single-use
 * token is shown once), change role, deactivate/reactivate. Every action there is audited
 * server-side; this file adds no authority of its own — the API re-checks the caller's role
 * on every call, so hiding the nav entry is a courtesy, not the control.
 */
import { useCallback, useState } from "react";
import { api } from "../api";
import type { MemberRow, Role } from "../api";
import type { PageProps } from "../App";
import { relativeTime } from "../lib/format";
import { useAsync } from "../useAsync";
import { Badge, Card, Empty, ErrorState, Icon, Loading, Modal, Notice } from "../ui";

const ROLES: { value: Role; hint: string }[] = [
  { value: "admin", hint: "full control, including members and the audit log" },
  { value: "analyst", hint: "register targets, run scans, triage findings" },
  { value: "viewer", hint: "read-only" },
];

export function MembersPage({ session, notify }: PageProps): JSX.Element {
  const isAdmin = session.user.role === "admin";
  const loader = useCallback(
    () => (isAdmin ? api.users() : Promise.resolve({ users: [] as MemberRow[] })),
    [isAdmin],
  );
  const { data, error, loading, reload } = useAsync<{ users: MemberRow[] }>(loader, [isAdmin]);
  const [inviting, setInviting] = useState(false);
  const [busyId, setBusyId] = useState("");
  const [invite, setInvite] = useState<{ email: string; role: Role; token: string } | null>(null);

  const header = (
    <div className="page-head">
      <div>
        <h1>Members</h1>
        <p className="lede">
          Who can sign in to this organization, with which role. Invitations create the account
          when the invitee chooses a password — no terminal and no shared secret.
        </p>
      </div>
    </div>
  );

  if (!isAdmin) {
    return (
      <>
        {header}
        <Card>
          <Empty
            title="Administrators only"
            message="Member management is restricted to administrators of this organization."
            icon="shield"
          />
        </Card>
      </>
    );
  }

  const act = async (member: MemberRow, payload: { role?: Role; is_active?: boolean }) => {
    setBusyId(member.id);
    try {
      await api.updateUser(member.id, payload);
      notify("ok", `Updated ${member.email}`);
      reload();
    } catch (err) {
      notify("error", err instanceof Error ? err.message : "The change was refused.");
    } finally {
      setBusyId("");
    }
  };

  const users = data?.users ?? [];

  return (
    <>
      {header}

      <Card
        title="Members"
        subtitle="Accounts that can sign in to this organization"
        actions={
          <button className="btn primary small" onClick={() => setInviting(true)}>
            <Icon name="plus" /> Invite member
          </button>
        }
      >
        {loading ? (
          <Loading label="Loading members…" />
        ) : error ? (
          <ErrorState message={error} onRetry={reload} />
        ) : users.length === 0 ? (
          <Empty title="No members" message="Invite the first teammate." icon="shield" />
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Email</th>
                  <th>Name</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Last sign-in</th>
                  <th className="num">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((member) => {
                  const isSelf = member.id === session.user.id;
                  return (
                    <tr key={member.id}>
                      <td>
                        {member.email}
                        {isSelf ? <span className="muted"> (you)</span> : null}
                      </td>
                      <td>{member.name}</td>
                      <td>
                        <select
                          aria-label={`Role for ${member.email}`}
                          value={member.role}
                          disabled={isSelf || busyId === member.id}
                          onChange={(event) => act(member, { role: event.target.value as Role })}
                        >
                          {ROLES.map((role) => (
                            <option key={role.value} value={role.value} title={role.hint}>
                              {role.value}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td>
                        <Badge value={member.is_active ? "active" : "disabled"} />
                      </td>
                      <td>{member.last_login_at ? relativeTime(member.last_login_at) : "never"}</td>
                      <td className="num">
                        <button
                          className="btn small"
                          disabled={isSelf || busyId === member.id}
                          onClick={() => act(member, { is_active: !member.is_active })}
                        >
                          {member.is_active ? "Deactivate" : "Reactivate"}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Notice kind="info" title="How passwords work">
        Passwords are never shown to an administrator and never stored in readable form — the
        database holds a salted hash. To give someone access, invite them: they choose their own
        password from the one-time link. If an account is locked out, reset it from this page with
        <strong> Send reset link</strong> or set a new password from the sign-in screen.
      </Notice>

      {inviting ? (
        <InviteDialog
          onClose={() => setInviting(false)}
          onInvited={(result) => {
            setInviting(false);
            setInvite({ email: result.email, role: result.role, token: result.token });
            reload();
          }}
        />
      ) : null}

      {invite ? (
        <Modal
          title="Invitation created"
          onClose={() => setInvite(null)}
          footer={
            <button className="primary" onClick={() => setInvite(null)}>
              Done
            </button>
          }
        >
          <p>
            Send this single-use link to <strong>{invite.email}</strong>. It expires in 7 days and
            is shown only once — only its hash is stored.
          </p>
          <pre className="code" data-testid="invite-link">{`${window.location.origin}/#/accept-invite?token=${invite.token}`}</pre>
          <p className="muted">
            The account exists as soon as they set a password from that link; role: {invite.role}.
          </p>
        </Modal>
      ) : null}
    </>
  );
}

function InviteDialog({
  onClose,
  onInvited,
}: {
  onClose: () => void;
  onInvited: (result: { email: string; role: Role; token: string }) => void;
}): JSX.Element {
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("analyst");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");

  const submit = async (event: React.FormEvent): Promise<void> => {
    event.preventDefault();
    setBusy(true);
    setFailure("");
    try {
      const result = await api.inviteUser({ email: email.trim().toLowerCase(), role });
      onInvited(result);
    } catch (err) {
      setFailure(err instanceof Error ? err.message : "The invitation was refused.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title="Invite a member"
      onClose={onClose}
      footer={
        <>
          <button onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="primary" onClick={submit} disabled={busy || !email}>
            {busy ? "Inviting…" : "Create invitation"}
          </button>
        </>
      }
    >
      <form onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        <label className="field">
          Email
          <input
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            required
            autoFocus
          />
        </label>
        <label className="field">
          Role
          <select value={role} onChange={(event) => setRole(event.target.value as Role)}>
            {ROLES.map((option) => (
              <option key={option.value} value={option.value}>
                {option.value} — {option.hint}
              </option>
            ))}
          </select>
        </label>
        {failure ? <Notice kind="danger" title="Refused">{failure}</Notice> : null}
      </form>
    </Modal>
  );
}
