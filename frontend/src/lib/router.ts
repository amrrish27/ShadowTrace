/**
 * Tiny hash router.
 *
 * Hash routing is deliberate: the SPA is served by the API as static files behind the same
 * origin, and a hash route needs no server-side rewrite rule (and no extra dependency).
 */
import { useEffect, useState } from "react";

export interface Route {
  name: string;
  params: string[];
  query: URLSearchParams;
}

export const NAV = [
  { name: "overview", label: "Overview", icon: "grid", group: "Monitor" },
  { name: "targets", label: "Targets", icon: "target", group: "Monitor" },
  { name: "scans", label: "Scans", icon: "radar", group: "Monitor" },
  { name: "findings", label: "Findings", icon: "shield", group: "Analyse" },
  { name: "endpoints", label: "Endpoints", icon: "route", group: "Analyse" },
  { name: "evidence", label: "Evidence", icon: "file", group: "Analyse" },
  { name: "reports", label: "Reports", icon: "download", group: "Analyse" },
  { name: "lab", label: "Lab", icon: "flask", group: "Operate" },
  { name: "settings", label: "Settings", icon: "cog", group: "Operate" },
  { name: "members", label: "Members", icon: "users", group: "Operate" },
  { name: "audit", label: "Audit log", icon: "list", group: "Operate" },
] as const;

export function parseHash(hash: string): Route {
  const raw = hash.replace(/^#\/?/, "");
  const [path, search = ""] = raw.split("?");
  const segments = (path ?? "").split("/").filter(Boolean).map(decodeURIComponent);
  const name = segments[0] ?? "overview";
  return { name, params: segments.slice(1), query: new URLSearchParams(search) };
}

export function href(name: string, ...params: (string | number)[]): string {
  const tail = params.length ? "/" + params.map((value) => encodeURIComponent(String(value))).join("/") : "";
  return `#/${name}${tail}`;
}

export function navigate(name: string, ...params: (string | number)[]): void {
  window.location.hash = href(name, ...params);
}

export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(() => parseHash(window.location.hash));
  useEffect(() => {
    const onChange = (): void => setRoute(parseHash(window.location.hash));
    window.addEventListener("hashchange", onChange);
    if (!window.location.hash) window.location.hash = "#/overview";
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}
