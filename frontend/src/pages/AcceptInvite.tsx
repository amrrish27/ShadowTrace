/**
 * Accept an invitation: the invitee chooses their own password and is signed in immediately.
 *
 * This is the counterpart to the Members page. Without it an invitation token would have no
 * consumer, and creating an account would still mean running a CLI command -- which is exactly
 * what this release removes. The API (`POST /api/v1/auth/accept-invite`) validates the token,
 * applies the password policy, creates the user with the invited role, marks the invitation
 * accepted, writes `auth.invitation_accepted` and issues a session. Nothing here decides any of
 * that; this screen only collects the password.
 */
import { useState } from "react";
import { api, ApiError, setCsrfToken } from "../api";
import type { Session } from "../App";
import { Icon } from "../ui";

export function AcceptInvite({
  token,
  onSignedIn,
}: {
  token: string;
  onSignedIn: (session: Session) => void;
}): JSX.Element {
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const mismatch = confirm.length > 0 && password !== confirm;

  async function submit(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    if (password !== confirm) {
      setError("The two passwords do not match.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      await api.acceptInvite({ token, password, name: name.trim() || "Team member" });
      const me = await api.me();
      setCsrfToken(me.csrf_token);
      onSignedIn({ user: me.user, organization: me.organization });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "The invitation could not be accepted.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-shell">
      <div className="login-card">
        <div className="brand" style={{ padding: 0, marginBottom: 14 }}>
          <span className="brand-mark">S</span>
          <div>
            <div className="brand-name">ShadowTrace</div>
            <div className="brand-sub">Accept your invitation</div>
          </div>
        </div>
        <h1>Choose your password</h1>
        <p className="lede">
          Your account is created when you submit this form. The password is stored as a salted
          hash — nobody, including administrators, can read it back.
        </p>
        <form onSubmit={submit}>
          <label className="field">
            Your name
            <input
              autoComplete="name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="How your name appears to teammates"
            />
          </label>
          <label className="field">
            New password
            <input
              type="password"
              autoComplete="new-password"
              required
              minLength={12}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </label>
          <label className="field">
            Repeat password
            <input
              type="password"
              autoComplete="new-password"
              required
              value={confirm}
              onChange={(event) => setConfirm(event.target.value)}
            />
          </label>
          {mismatch ? <p className="hint" style={{ color: "var(--danger)" }}>The two passwords do not match.</p> : null}
          {error ? (
            <div className="error-state" role="alert">
              <Icon name="alert" size={16} />
              <div>
                <div className="title">Could not accept the invitation</div>
                <div className="detail">{error}</div>
              </div>
            </div>
          ) : null}
          <button className="primary" type="submit" disabled={busy || mismatch || !password}>
            {busy ? "Creating your account…" : "Create account and sign in"}
          </button>
          <p className="hint">
            Minimum 12 characters. Reuse of your email or the product name is refused.
          </p>
        </form>
      </div>
    </div>
  );
}
