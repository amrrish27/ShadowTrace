/**
 * Presentational building blocks.
 *
 * Everything here is pure: no data fetching, no globals, no timers. Charts are drawn as
 * hand-rolled SVG so the dashboard needs no charting dependency (and keeps working offline).
 */
import React, { useEffect, useId, useRef, useState } from "react";

/* ----------------------------------------------------------------- icons */

const ICON_PATHS: Record<string, string> = {
  grid: "M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z",
  target: "M12 2v3m0 14v3M2 12h3m14 0h3M12 8a4 4 0 100 8 4 4 0 000-8z",
  radar: "M12 3a9 9 0 109 9M12 12l6-6M12 7a5 5 0 105 5",
  shield: "M12 3l7 3v6c0 4-3 7-7 8-4-1-7-4-7-8V6l7-3z",
  route: "M6 19a3 3 0 100-6 3 3 0 000 6zM18 8a3 3 0 100-6 3 3 0 000 6zM6 13V9a3 3 0 013-3h6",
  file: "M6 2h8l4 4v16H6zM14 2v5h4",
  download: "M12 3v12m0 0l-4-4m4 4l4-4M4 21h16",
  flask: "M9 3h6M10 3v6l-5 9a2 2 0 002 3h10a2 2 0 002-3l-5-9V3",
  cog: "M12 15a3 3 0 100-6 3 3 0 000 6zM19 12a7 7 0 00-.1-1l2-1-2-3-2 1a7 7 0 00-2-1V4h-4v2a7 7 0 00-2 1L7 6 5 9l2 1a7 7 0 000 2l-2 1 2 3 2-1a7 7 0 002 1v2h4v-2a7 7 0 002-1l2 1 2-3-2-1c.06-.33.1-.66.1-1z",
  list: "M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01",
  search: "M11 19a8 8 0 100-16 8 8 0 000 16zM21 21l-4.3-4.3",
  refresh: "M20 12a8 8 0 10-3 6.2M20 5v5h-5",
  play: "M6 4l14 8-14 8z",
  stop: "M6 6h12v12H6z",
  x: "M6 6l12 12M18 6L6 18",
  check: "M4 12l5 5L20 6",
  alert: "M12 3l9 16H3zM12 9v5m0 3h.01",
  external: "M14 4h6v6M20 4L10 14M6 4H4v16h16v-2",
  clock: "M12 21a9 9 0 100-18 9 9 0 000 18zM12 7v5l3 2",
  chevronLeft: "M15 5l-7 7 7 7",
  chevronRight: "M9 5l7 7-7 7",
  sun: "M12 17a5 5 0 100-10 5 5 0 000 10zM12 1v2m0 18v2M4 4l1.5 1.5M18.5 18.5L20 20M1 12h2m18 0h2M4 20l1.5-1.5M18.5 5.5L20 4",
  moon: "M21 12.8A9 9 0 1111.2 3 7 7 0 0021 12.8z",
  menu: "M3 6h18M3 12h18M3 18h18",
  trash: "M4 7h16M9 7V4h6v3M6 7l1 14h10l1-14",
  plus: "M12 5v14M5 12h14",
  users: "M16 20v-1a4 4 0 00-4-4H6a4 4 0 00-4 4v1M9 11a4 4 0 100-8 4 4 0 000 8zM22 20v-1a4 4 0 00-3-3.9M16 3.1a4 4 0 010 7.8",
};

export function Icon({ name, size = 16 }: { name: string; size?: number }): JSX.Element {
  return (
    <svg
      aria-hidden="true"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d={ICON_PATHS[name] ?? ICON_PATHS.grid} />
    </svg>
  );
}

/* ---------------------------------------------------------------- atoms */

export function Badge({ value, label }: { value: string; label?: string }): JSX.Element {
  const key = (value || "unknown").toLowerCase();
  return (
    <span className={`badge ${key}`}>
      <span className="dot" aria-hidden="true" />
      {label ?? value.replace(/_/g, " ")}
    </span>
  );
}

export function Tooltip({ text, children }: { text: string; children: React.ReactNode }): JSX.Element {
  return (
    <span className="tooltip" tabIndex={0}>
      {children}
      <span className="tip" role="tooltip">
        {text}
      </span>
    </span>
  );
}

export function Stat({
  label,
  value,
  hint,
  tone,
  icon,
}: {
  label: string;
  value: React.ReactNode;
  hint?: string;
  tone?: string;
  icon?: string;
}): JSX.Element {
  return (
    <div className="card tight">
      <div className="stat">
        <span className="stat-label">
          {icon ? <Icon name={icon} size={13} /> : null}
          {label}
        </span>
        <span className={`stat-value ${tone ? `sev-${tone}` : ""}`}>{value}</span>
        {hint ? <span className="stat-hint">{hint}</span> : null}
      </div>
    </div>
  );
}

export function Card({
  title,
  subtitle,
  actions,
  children,
  className = "",
}: {
  title?: string;
  subtitle?: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}): JSX.Element {
  return (
    <section className={`card ${className}`}>
      {title ? (
        <header className="card-head">
          <div>
            {/* A real heading, not a styled div: screen readers need the section in the
                outline, and the card title is the only label the section has. */}
            <h2 className="card-title">{title}</h2>
            {subtitle ? <div className="card-sub">{subtitle}</div> : null}
          </div>
          <div className="spacer" />
          {actions}
        </header>
      ) : null}
      {children}
    </section>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }): JSX.Element {
  return (
    <div className="loading" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" />
      {label}
    </div>
  );
}

export function Empty({
  title,
  message,
  action,
  icon = "search",
}: {
  title: string;
  message?: string;
  action?: React.ReactNode;
  icon?: string;
}): JSX.Element {
  return (
    <div className="empty">
      <div className="empty-icon">
        <Icon name={icon} size={26} />
      </div>
      {/* Not an <h3>: an empty state is a label inside a section, and a stray H3 before
          the first H2 breaks the document outline for screen-reader navigation. */}
      <p className="empty-title">{title}</p>
      {message ? <p>{message}</p> : null}
      {action}
    </div>
  );
}

export function ErrorState({
  title = "Something went wrong",
  message,
  onRetry,
}: {
  title?: string;
  message: string;
  onRetry?: () => void;
}): JSX.Element {
  return (
    <div className="error-state" role="alert">
      <Icon name="alert" size={18} />
      <div className="grow" style={{ flex: 1 }}>
        <div className="title">{title}</div>
        <div className="detail">{message}</div>
      </div>
      {onRetry ? (
        <button className="small" onClick={onRetry}>
          <Icon name="refresh" size={13} /> Retry
        </button>
      ) : null}
    </div>
  );
}

export function Notice({
  kind = "warn",
  title,
  children,
}: {
  kind?: "warn" | "danger" | "ok" | "info";
  title?: string;
  children: React.ReactNode;
}): JSX.Element {
  const icon = kind === "ok" ? "check" : kind === "info" ? "clock" : "alert";
  return (
    <div className={`notice ${kind}`}>
      <Icon name={icon} size={16} />
      <div>
        {title ? <div className="notice-title">{title}</div> : null}
        <div>{children}</div>
      </div>
    </div>
  );
}

export function Progress({ value, tone }: { value: number; tone?: "ok" | "warn" | "danger" }): JSX.Element {
  const clamped = Math.max(0, Math.min(100, Math.round(value)));
  return (
    <div
      className={`progress ${tone ?? ""}`}
      role="progressbar"
      aria-valuenow={clamped}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <span style={{ width: `${clamped}%` }} />
    </div>
  );
}

export function SeverityBars({ counts, total }: { counts: Record<string, number>; total?: number }): JSX.Element {
  const severities = ["critical", "high", "medium", "low", "info"];
  const sum = total ?? severities.reduce((acc, key) => acc + (counts[key] ?? 0), 0);
  return (
    <div className="sev-bars">
      {severities.map((severity) => {
        const count = counts[severity] ?? 0;
        const share = sum ? Math.round((count / sum) * 100) : 0;
        return (
          <div className="sev-row" key={severity}>
            <span style={{ textTransform: "capitalize", color: "var(--text-muted)" }}>{severity}</span>
            <span className="sev-track">
              <span className={`sev-fill ${severity}`} style={{ width: `${share}%` }} />
            </span>
            <span className="num" style={{ textAlign: "right" }}>
              {count}
            </span>
          </div>
        );
      })}
    </div>
  );
}

/* --------------------------------------------------------------- modal */

export function Modal({
  title,
  children,
  footer,
  onClose,
}: {
  title: string;
  children: React.ReactNode;
  footer?: React.ReactNode;
  onClose: () => void;
}): JSX.Element {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const onKey = (event: KeyboardEvent): void => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    ref.current?.focus();
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="modal-backdrop" onClick={onClose} role="presentation">
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        ref={ref}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="modal-head">
          <h2>{title}</h2>
        </div>
        <div className="modal-body">{children}</div>
        {footer ? <div className="modal-foot">{footer}</div> : null}
      </div>
    </div>
  );
}

/** Confirmation dialog. Used before every destructive action in the UI. */
export function ConfirmDialog({
  title,
  message,
  confirmLabel = "Confirm",
  danger,
  busy,
  onConfirm,
  onCancel,
  children,
}: {
  title: string;
  message: string;
  confirmLabel?: string;
  danger?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  children?: React.ReactNode;
}): JSX.Element {
  return (
    <Modal
      title={title}
      onClose={onCancel}
      footer={
        <>
          <button onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button className={danger ? "danger" : "primary"} onClick={onConfirm} disabled={busy}>
            {busy ? "Working…" : confirmLabel}
          </button>
        </>
      }
    >
      <p style={{ color: "var(--text-muted)" }}>{message}</p>
      {children}
    </Modal>
  );
}

/* -------------------------------------------------------------- toasts */

export interface Toast {
  id: number;
  kind: "ok" | "error" | "info";
  message: string;
}

export function Toaster({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: number) => void }): JSX.Element {
  return (
    <div className="toasts" aria-live="polite">
      {toasts.map((toast) => (
        <div key={toast.id} className={`toast ${toast.kind}`} role={toast.kind === "error" ? "alert" : "status"}>
          <div style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
            <span style={{ flex: 1 }}>{toast.message}</span>
            <button className="ghost small" onClick={() => onDismiss(toast.id)} aria-label="Dismiss">
              <Icon name="x" size={12} />
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}

/* -------------------------------------------------------------- charts */

const CHART_COLORS: Record<string, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
  info: "var(--info)",
  brand: "var(--brand)",
  ok: "var(--ok)",
};

/** Horizontal bars — used for severity and discovery-source distributions. */
export function BarChart({
  data,
  height = 24,
  colors = {},
}: {
  data: { label: string; value: number; tone?: string }[];
  height?: number;
  colors?: Record<string, string>;
}): JSX.Element {
  const max = Math.max(1, ...data.map((item) => item.value));
  return (
    <div className="chart" role="img" aria-label={data.map((item) => `${item.label}: ${item.value}`).join(", ")}>
      {data.map((item) => {
        const width = Math.max(2, Math.round((item.value / max) * 100));
        const color = colors[item.label] ?? CHART_COLORS[item.tone ?? ""] ?? "var(--brand)";
        return (
          <div key={item.label} style={{ display: "grid", gridTemplateColumns: "110px 1fr 40px", gap: 10, alignItems: "center", marginBottom: 8 }}>
            <span className="truncate" style={{ fontSize: 12, color: "var(--text-muted)" }} title={item.label}>
              {item.label}
            </span>
            <span style={{ height, background: "var(--bg-raised)", borderRadius: 6, overflow: "hidden" }}>
              <span style={{ display: "block", height: "100%", width: `${width}%`, background: color, borderRadius: 6 }} />
            </span>
            <span style={{ textAlign: "right", fontSize: 12, fontVariantNumeric: "tabular-nums" }}>{item.value}</span>
          </div>
        );
      })}
    </div>
  );
}

/** Vertical bars over time — scan history and endpoint discovery per scan. */
export function ColumnChart({
  data,
  height = 150,
  tone = "brand",
  emptyLabel = "No data yet",
}: {
  data: { label: string; value: number; hint?: string }[];
  height?: number;
  tone?: string;
  emptyLabel?: string;
}): JSX.Element {
  if (!data.length) {
    return <div className="empty" style={{ padding: 18 }}>{emptyLabel}</div>;
  }
  const max = Math.max(1, ...data.map((item) => item.value));
  const width = 100;
  const gap = 100 / data.length;
  const barWidth = Math.max(3, gap * 0.55);
  return (
    <div className="chart" role="img" aria-label={data.map((item) => `${item.label}: ${item.value}`).join(", ")}>
      <svg viewBox={`0 0 ${width} 100`} preserveAspectRatio="none" style={{ height }}>
        <line x1="0" y1="99" x2="100" y2="99" className="chart-axis" vectorEffect="non-scaling-stroke" />
        {data.map((item, index) => {
          const barHeight = Math.max(0.8, (item.value / max) * 94);
          const x = index * gap + (gap - barWidth) / 2;
          return (
            <rect
              key={`${item.label}-${index}`}
              className="chart-bar"
              x={x}
              y={99 - barHeight}
              width={barWidth}
              height={barHeight}
              rx={0.8}
              fill={CHART_COLORS[tone] ?? "var(--brand)"}
            >
              <title>{`${item.hint ?? item.label}: ${item.value}`}</title>
            </rect>
          );
        })}
      </svg>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10.5, color: "var(--text-dim)", marginTop: 4 }}>
        <span>{data[0]?.label}</span>
        <span>max {max}</span>
        <span>{data[data.length - 1]?.label}</span>
      </div>
    </div>
  );
}

/** Donut for a small set of proportions (vulnerability mix). */
export function Donut({
  data,
  size = 132,
  thickness = 16,
  centerLabel,
  centerValue,
}: {
  data: { label: string; value: number; tone?: string }[];
  size?: number;
  thickness?: number;
  centerLabel?: string;
  centerValue?: React.ReactNode;
}): JSX.Element {
  const total = data.reduce((acc, item) => acc + item.value, 0);
  const radius = (size - thickness) / 2;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;
  const uid = useId().replace(/[:]/g, "");
  return (
    <div style={{ display: "flex", gap: 16, alignItems: "center", flexWrap: "wrap" }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={data.map((item) => `${item.label}: ${item.value}`).join(", ")}>
        <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
          <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="var(--bg-raised)" strokeWidth={thickness} />
          {total === 0 ? null : (
            data.map((item) => {
              const length = (item.value / total) * circumference;
              const dash = `${length} ${circumference - length}`;
              const element = (
                <circle
                  key={`${uid}-${item.label}`}
                  cx={size / 2}
                  cy={size / 2}
                  r={radius}
                  fill="none"
                  stroke={CHART_COLORS[item.tone ?? item.label] ?? "var(--brand)"}
                  strokeWidth={thickness}
                  strokeDasharray={dash}
                  strokeDashoffset={-offset}
                  strokeLinecap="butt"
                >
                  <title>{`${item.label}: ${item.value}`}</title>
                </circle>
              );
              offset += length;
              return element;
            })
          )}
        </g>
        <text x="50%" y="47%" textAnchor="middle" className="chart-value" style={{ fontSize: 18 }}>
          {centerValue ?? total}
        </text>
        <text x="50%" y="60%" textAnchor="middle" className="chart-label">
          {centerLabel ?? "findings"}
        </text>
      </svg>
      <div className="chart-legend" style={{ flexDirection: "column", alignItems: "flex-start", gap: 6 }}>
        {data.map((item) => (
          <span key={item.label}>
            <span className="swatch" style={{ background: CHART_COLORS[item.tone ?? item.label] ?? "var(--brand)" }} />
            <span style={{ textTransform: "capitalize" }}>{item.label}</span>
            <strong style={{ color: "var(--text)" }}>{item.value}</strong>
          </span>
        ))}
      </div>
    </div>
  );
}

/** Line/area chart for a trend (scans or findings per day). */
export function TrendLine({
  data,
  height = 160,
  tone = "brand",
  emptyLabel = "Not enough history yet",
}: {
  data: { label: string; value: number }[];
  height?: number;
  tone?: string;
  emptyLabel?: string;
}): JSX.Element {
  if (data.length < 2) {
    return <div className="empty" style={{ padding: 18 }}>{emptyLabel}</div>;
  }
  const max = Math.max(1, ...data.map((item) => item.value));
  const points = data.map((item, index) => {
    const x = (index / (data.length - 1)) * 100;
    const y = 98 - (item.value / max) * 90;
    return { x, y, ...item };
  });
  const path = points.map((point, index) => `${index === 0 ? "M" : "L"}${point.x.toFixed(2)} ${point.y.toFixed(2)}`).join(" ");
  const area = `${path} L100 100 L0 100 Z`;
  const color = CHART_COLORS[tone] ?? "var(--brand)";
  return (
    <div className="chart" role="img" aria-label={data.map((item) => `${item.label}: ${item.value}`).join(", ")}>
      <svg viewBox="0 0 100 100" preserveAspectRatio="none" style={{ height }}>
        <line x1="0" y1="98" x2="100" y2="98" className="chart-axis" vectorEffect="non-scaling-stroke" />
        <path d={area} fill={color} opacity={0.14} />
        <path d={path} fill="none" stroke={color} strokeWidth={1.6} vectorEffect="non-scaling-stroke" />
        {points.map((point) => (
          <circle key={point.label} cx={point.x} cy={point.y} r={1.4} fill={color}>
            <title>{`${point.label}: ${point.value}`}</title>
          </circle>
        ))}
      </svg>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10.5, color: "var(--text-dim)", marginTop: 4 }}>
        <span>{data[0]?.label ?? ""}</span>
        <span>{data[data.length - 1]?.label ?? ""}</span>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------- controls */

export function SearchInput({
  value,
  onChange,
  placeholder = "Search…",
  label = "Search",
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  label?: string;
}): JSX.Element {
  return (
    <div className="search">
      <span className="search-icon">
        <Icon name="search" size={14} />
      </span>
      <input
        type="search"
        aria-label={label}
        placeholder={placeholder}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
    </div>
  );
}

export function Select({
  value,
  onChange,
  options,
  label,
}: {
  value: string;
  onChange: (value: string) => void;
  options: { value: string; label: string }[];
  label: string;
}): JSX.Element {
  return (
    <select aria-label={label} value={value} onChange={(event) => onChange(event.target.value)}>
      {options.map((option) => (
        <option key={option.value} value={option.value}>
          {option.label}
        </option>
      ))}
    </select>
  );
}

export function Pagination({
  page,
  pageSize,
  total,
  onPage,
}: {
  page: number;
  pageSize: number;
  total: number;
  onPage: (page: number) => void;
}): JSX.Element {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  return (
    <div className="pagination">
      <span>
        {from}–{to} of {total}
      </span>
      <button className="small" onClick={() => onPage(page - 1)} disabled={page <= 1} aria-label="Previous page">
        <Icon name="chevronLeft" size={13} />
      </button>
      <span>
        {page} / {pages}
      </span>
      <button className="small" onClick={() => onPage(page + 1)} disabled={page >= pages} aria-label="Next page">
        <Icon name="chevronRight" size={13} />
      </button>
    </div>
  );
}

export function Tabs<T extends string>({
  tabs,
  active,
  onChange,
}: {
  tabs: { id: T; label: string; count?: number }[];
  active: T;
  onChange: (id: T) => void;
}): JSX.Element {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          role="tab"
          aria-selected={active === tab.id}
          className={`tab ${active === tab.id ? "active" : ""}`}
          onClick={() => onChange(tab.id)}
        >
          {tab.label}
          {tab.count !== undefined ? <span className="count">{tab.count}</span> : null}
        </button>
      ))}
    </div>
  );
}

/** Auto-refresh switch with an explicit interval, used on live pages. */
export function RefreshToggle({
  enabled,
  onToggle,
  intervalMs = 4000,
}: {
  enabled: boolean;
  onToggle: (next: boolean) => void;
  intervalMs?: number;
}): JSX.Element {
  return (
    <Tooltip text={`Poll every ${Math.round(intervalMs / 1000)}s while the page is open`}>
      <button
        className="small"
        aria-pressed={enabled}
        onClick={() => onToggle(!enabled)}
        title={enabled ? "Pause live refresh" : "Resume live refresh"}
      >
        <Icon name="refresh" size={13} />
        {enabled ? "Live" : "Paused"}
      </button>
    </Tooltip>
  );
}

/** Re-render on an interval; the callback is expected to be stable (useCallback). */
export function useInterval(callback: () => void, delayMs: number | null): void {
  const saved = useRef(callback);
  useEffect(() => {
    saved.current = callback;
  }, [callback]);
  useEffect(() => {
    if (delayMs === null) return undefined;
    const handle = window.setInterval(() => saved.current(), delayMs);
    return () => window.clearInterval(handle);
  }, [delayMs]);
}

/** Local state kept in sync with a prop, for editable forms. */
export function useDraft<T>(initial: T): [T, (patch: Partial<T>) => void, () => void] {
  const [value, setValue] = useState<T>(initial);
  const patch = (update: Partial<T>): void => setValue((current) => ({ ...current, ...update }));
  const reset = (): void => setValue(initial);
  return [value, patch, reset];
}
