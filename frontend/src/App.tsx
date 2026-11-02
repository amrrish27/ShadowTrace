import React, { useCallback, useEffect, useMemo, useState } from "react";
import { api, ApiError, setCsrfToken } from "./api";
import type { MeResponse } from "./api";
import { href, NAV, navigate, useRoute } from "./lib/router";
import { Icon, Toaster } from "./ui";
import type { Toast } from "./ui";
import { OverviewPage } from "./pages/Overview";
import { TargetsPage } from "./pages/Targets";
import { ScansPage } from "./pages/Scans";
import { ScanDetailPage } from "./pages/ScanDetail";
import { FindingsPage } from "./pages/Findings";
import { FindingDetailPage } from "./pages/FindingDetail";
import { EndpointsPage } from "./pages/Endpoints";
import { EvidencePage } from "./pages/Evidence";
import { ReportsPage } from "./pages/Reports";
import { LabPage } from "./pages/Lab";
import { SettingsPage } from "./pages/Settings";
import { MembersPage } from "./pages/Members";
import { AcceptInvite } from "./pages/AcceptInvite";
import { AuditPage } from "./pages/Audit";

export type Theme = "dark" | "light";

export interface Session {
  user: MeResponse["user"];
  organization: string;
}

const THEME_KEY = "shadowtrace.theme";

function initialTheme(): Theme {
  try {
    const stored = window.localStorage.getItem(THEME_KEY);
    if (stored === "light" || stored === "dark") return stored;
  } catch {
    /* storage can be blocked; the dark default is fine */
  }
  return "dark";
}

export function applyTheme(theme: Theme): void {
  document.documentElement.setAttribute("data-theme", theme);
  try {
    window.localStorage.setItem(THEME_KEY, theme);
  } catch {
    /* ignore */
  }
}

export function Login({ onSignedIn }: { onSignedIn: (session: Session) => void }): JSX.Element {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.login(email.trim().toLowerCase(), password);
      const me = await api.me();
      setCsrfToken(me.csrf_token);
      onSignedIn({ user: me.user, organization: me.organization });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Sign-in failed. Check the API is running.");
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
            <div className="brand-sub">API shadow-endpoint discovery</div>
          </div>
        </div>
        <h1>Sign in</h1>
        <p className="lede">Authorized testing only. Every scan is attested, audited and scoped.</p>
        <form onSubmit={submit}>
          <label className="field">
            Email
            <input
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
          </label>
          <label className="field">
            Password
            <input
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </label>
          {error ? (
            <div className="error-state" role="alert">
              <Icon name="alert" size={16} />
              <div>
                <div className="title">Sign-in failed</div>
                <div className="detail">{error}</div>
              </div>
            </div>
          ) : null}
          <button className="primary" type="submit" disabled={busy}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
          <p className="hint">
            Accounts are created by an administrator. Scanning is limited to targets you are authorized to test.
          </p>
        </form>
      </div>
    </div>
  );
}

function useToasts(): { toasts: Toast[]; push: (kind: Toast["kind"], message: string) => void; dismiss: (id: number) => void } {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);
  const push = useCallback(
    (kind: Toast["kind"], message: string) => {
      const id = Date.now() + Math.floor(Math.random() * 1000);
      setToasts((current) => [...current.slice(-3), { id, kind, message }]);
      window.setTimeout(() => dismiss(id), kind === "error" ? 9000 : 5000);
    },
    [dismiss],
  );
  return { toasts, push, dismiss };
}

export interface PageProps {
  session: Session;
  notify: (kind: Toast["kind"], message: string) => void;
  theme: Theme;
  setTheme: (theme: Theme) => void;
}

function renderPage(route: ReturnType<typeof useRoute>, props: PageProps): JSX.Element {
  const [first, second] = route.params;
  switch (route.name) {
    case "targets":
      return <TargetsPage {...props} focusId={first} />;
    case "scans":
      return <ScansPage {...props} focusId={first} />;
    case "scan":
      return <ScanDetailPage {...props} scanId={first ?? ""} />;
    case "findings":
      return <FindingsPage {...props} focusId={first} initialScan={second} />;
    case "finding":
      return <FindingDetailPage {...props} findingId={first ?? ""} />;
    case "endpoints":
      return <EndpointsPage {...props} focusId={first} />;
    case "evidence":
      return <EvidencePage {...props} scanId={first} />;
    case "reports":
      return <ReportsPage {...props} scanId={first} />;
    case "lab":
      return <LabPage {...props} />;
    case "settings":
      return <SettingsPage {...props} />;
    case "members":
      return <MembersPage {...props} />;
    case "audit":
      return <AuditPage {...props} />;
    default:
      return <OverviewPage {...props} />;
  }
}

const PAGE_TITLES: Record<string, { title: string; sub: string }> = {
  overview: { title: "Overview", sub: "Posture across every authorized target" },
  targets: { title: "Targets", sub: "Register, verify and approve what may be scanned" },
  scans: { title: "Scans", sub: "Queue, follow and compare assessments" },
  scan: { title: "Scan detail", sub: "Configuration, progress, findings and exports" },
  findings: { title: "Findings", sub: "Confirmed and suspected issues with evidence" },
  finding: { title: "Finding", sub: "Evidence, impact and remediation" },
  endpoints: { title: "Endpoints", sub: "Every endpoint the scanner has seen" },
  evidence: { title: "Evidence", sub: "Captured responses, redacted for safe sharing" },
  reports: { title: "Reports", sub: "Exports built from persisted scan data" },
  lab: { title: "Training lab", sub: "Bundled, loopback-only vulnerable application" },
  settings: { title: "Settings", sub: "Runtime limits, workers and deployment" },
  members: { title: "Members", sub: "Who can sign in, with which role" },
  audit: { title: "Audit log", sub: "Security-sensitive actions in this organization" },
};

export function App(): JSX.Element {
  const route = useRoute();
  const [session, setSession] = useState<Session | null>(null);
  const [booting, setBooting] = useState(true);
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [menuOpen, setMenuOpen] = useState(false);
  const { toasts, push, dismiss } = useToasts();

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  useEffect(() => {
    let active = true;
    api
      .me()
      .then((me) => {
        if (!active) return;
        setCsrfToken(me.csrf_token);
        setSession({ user: me.user, organization: me.organization });
      })
      .catch(() => {
        /* not signed in; the login screen is rendered */
      })
      .finally(() => {
        if (active) setBooting(false);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    setMenuOpen(false);
  }, [route.name, route.params.join("/")]);

  const signOut = useCallback(async () => {
    try {
      await api.logout();
    } catch {
      /* the cookie may already be gone */
    }
    setSession(null);
    navigate("overview");
  }, []);

  const pageProps = useMemo<PageProps | null>(
    () => (session ? { session, notify: push, theme, setTheme } : null),
    [session, push, theme],
  );

  if (booting) {
    return (
      <div className="loading" style={{ justifyContent: "center", minHeight: "60vh" }}>
        <span className="spinner" /> Restoring your session…
      </div>
    );
  }

  if (!session || !pageProps) {
    // An invitation link is a pre-authentication route: it must not require a session.
    const token = route.name === "accept-invite" ? (route.query.get("token") ?? "") : "";
    if (token) return <AcceptInvite token={token} onSignedIn={setSession} />;
    return <Login onSignedIn={setSession} />;
  }

  const meta = PAGE_TITLES[route.name] ?? PAGE_TITLES["overview"] ?? { title: "Overview", sub: "" };
  const initials = (session.user.name || session.user.email)
    .split(/[\s@.]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() ?? "")
    .join("");

  const groups = Array.from(new Set(NAV.map((item) => item.group)));

  return (
    <div className="shell">
      <aside className={`sidebar ${menuOpen ? "open" : ""}`} aria-label="Main navigation">
        <div className="brand">
          <span className="brand-mark">S</span>
          <div>
            <div className="brand-name">ShadowTrace</div>
            <div className="brand-sub">{session.organization}</div>
          </div>
        </div>
        {groups.map((group) => (
          <React.Fragment key={group}>
            <div className="nav-group">{group}</div>
            {NAV.filter((item) => item.group === group).map((item) => {
              const active =
                route.name === item.name || (item.name === "scans" && route.name === "scan") ||
                (item.name === "findings" && route.name === "finding") ||
                (item.name === "scans" && route.name === "evidence");
              return (
                <a
                  key={item.name}
                  className={`nav-item ${active ? "active" : ""}`}
                  href={href(item.name)}
                  aria-current={active ? "page" : undefined}
                >
                  <span className="nav-icon">
                    <Icon name={item.icon} size={16} />
                  </span>
                  {item.label}
                </a>
              );
            })}
          </React.Fragment>
        ))}
      </aside>

      <div className="main">
        <header className="topbar">
          <button className="ghost menu-toggle" onClick={() => setMenuOpen((open) => !open)} aria-label="Toggle navigation">
            <Icon name="menu" size={18} />
          </button>
          <div>
            <div className="topbar-title">{meta.title}</div>
            <div className="topbar-sub">{meta.sub}</div>
          </div>
          <div className="spacer topbar-spacer" />
          <div className="topbar-actions">
            <button
              className="small"
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
              aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
              title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
            >
              <Icon name={theme === "dark" ? "sun" : "moon"} size={14} />
              {theme === "dark" ? "Light" : "Dark"}
            </button>
            <div className="user-chip">
              <span className="avatar" aria-hidden="true">
                {initials || "?"}
              </span>
              <span className="meta">
                <div>{session.user.name}</div>
                <div className="mail">
                  {session.user.email} · {session.user.role}
                </div>
              </span>
            </div>
            <button className="small" onClick={signOut}>
              Sign out
            </button>
          </div>
        </header>
        <main className="content">{renderPage(route, pageProps)}</main>
      </div>
      <Toaster toasts={toasts} onDismiss={dismiss} />
    </div>
  );
}
