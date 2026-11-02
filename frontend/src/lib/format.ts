/** Formatting helpers shared by every page. Pure functions only. */

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITY_ORDER)[number];

export const SEVERITY_LABEL: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export function severityRank(value: string): number {
  const index = SEVERITY_ORDER.indexOf(value as Severity);
  return index === -1 ? SEVERITY_ORDER.length : index;
}

/** Compact relative time: "just now", "4m", "3h", "2d" — falls back to a date. */
export function relativeTime(epochSeconds: number | null | undefined, nowMs = Date.now()): string {
  if (!epochSeconds) return "—";
  const delta = Math.max(0, Math.floor(nowMs / 1000 - epochSeconds));
  if (delta < 10) return "just now";
  if (delta < 60) return `${delta}s ago`;
  if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
  if (delta < 86_400) return `${Math.floor(delta / 3600)}h ago`;
  if (delta < 604_800) return `${Math.floor(delta / 86_400)}d ago`;
  return new Date(epochSeconds * 1000).toLocaleDateString();
}

/** "1m 12s" for a duration in seconds; the scan detail page uses it for elapsed time. */
export function duration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || Number.isNaN(seconds)) return "—";
  const total = Math.max(0, Math.round(seconds));
  if (total < 60) return `${total}s`;
  const minutes = Math.floor(total / 60);
  const rest = total % 60;
  if (minutes < 60) return `${minutes}m ${rest}s`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

export function elapsedSeconds(started: number | null, finished: number | null, nowSeconds = Date.now() / 1000): number | null {
  if (!started) return null;
  return Math.max(0, (finished ?? nowSeconds) - started);
}

export function percent(part: number, whole: number): number {
  if (!whole) return 0;
  return Math.min(100, Math.round((part / whole) * 100));
}

export function number(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return value.toLocaleString();
}

/** Human label for the machine-readable scan outcome produced by the scanner. */
export const OUTCOME_HINT: Record<string, string> = {
  ok: "The scan reached the target and analysed what it found.",
  policy_blocked: "Every request was refused by scanning policy; nothing was assessed.",
  unreachable: "The target could not be reached, so no page could be assessed.",
  timeout: "The scan hit its time budget before finishing.",
  cancelled: "An operator cancelled the scan.",
  empty: "The target answered but revealed no endpoints.",
  error: "The scan stopped on an internal error.",
};

export const STATE_HINT: Record<string, string> = {
  queued: "Waiting for a worker to claim the scan.",
  running: "A worker is scanning now.",
  cancelling: "Cancellation requested; the worker stops within a few seconds.",
  completed: "Finished. Review the counters for what was actually assessed.",
  failed: "Did not finish. The error below is what the worker recorded.",
  cancelled: "Cancelled by an operator or the API.",
  timed_out: "Exceeded its time budget.",
};
