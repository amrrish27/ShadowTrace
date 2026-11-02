import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { Endpoint, Target } from "../api";
import type { PageProps } from "../App";
import { navigate } from "../lib/router";
import { useAsync } from "../useAsync";
import {
  Badge, Card, Empty, ErrorState, Loading, Modal, Pagination, SearchInput, Select,
} from "../ui";

export function EndpointsPage({ focusId }: PageProps & { focusId?: string }): JSX.Element {
  const [query, setQuery] = useState("");
  const [classification, setClassification] = useState("");
  const [validation, setValidation] = useState("");
  const [method, setMethod] = useState("");
  const [targetId, setTargetId] = useState("");
  const [sort, setSort] = useState("path");
  const [order, setOrder] = useState("asc");
  const [page, setPage] = useState(1);
  const [detailId, setDetailId] = useState<string | null>(focusId ?? null);
  const pageSize = 25;

  const targets = useAsync(useCallback(() => api.targets(), []), []);

  const loader = useCallback(
    () =>
      api.allEndpoints({
        ...(query ? { q: query } : {}),
        ...(classification ? { classification } : {}),
        ...(validation ? { validation_status: validation } : {}),
        ...(method ? { method } : {}),
        ...(targetId ? { target_id: targetId } : {}),
        sort,
        order,
        page: String(page),
        page_size: String(pageSize),
      }),
    [query, classification, validation, method, targetId, sort, order, page],
  );
  const { data, error, loading, reload } = useAsync(loader, [query, classification, validation, method, targetId, sort, order, page]);

  useEffect(() => {
    setPage(1);
  }, [query, classification, validation, method, targetId]);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Endpoints</h1>
          <p className="lede">
            The inventory is keyed by method and path template, so the same endpoint reached with
            different ids or parameter values appears once. Source shows how it was found.
          </p>
        </div>
      </div>

      <div className="toolbar">
        <SearchInput value={query} onChange={setQuery} placeholder="Search path" />
        <Select
          label="Classification"
          value={classification}
          onChange={setClassification}
          options={[
            { value: "", label: "Any classification" },
            { value: "shadow", label: "Shadow" },
            { value: "candidate", label: "Candidate" },
            { value: "discovered", label: "Discovered" },
            { value: "documented", label: "Documented" },
            { value: "zombie", label: "Zombie" },
          ]}
        />
        <Select
          label="Validation"
          value={validation}
          onChange={setValidation}
          options={[
            { value: "", label: "Any validation" },
            { value: "live", label: "Live" },
            { value: "auth_required", label: "Auth required" },
            { value: "error", label: "Error" },
            { value: "not_found", label: "Not found" },
            { value: "unvalidated", label: "Unvalidated" },
          ]}
        />
        <Select
          label="Method"
          value={method}
          onChange={setMethod}
          options={[
            { value: "", label: "Any method" },
            ...["GET", "POST", "PUT", "PATCH", "DELETE"].map((value) => ({ value, label: value })),
          ]}
        />
        <Select
          label="Target"
          value={targetId}
          onChange={setTargetId}
          options={[
            { value: "", label: "Any target" },
            ...(targets.data?.targets ?? []).map((target: Target) => ({ value: target.id, label: target.name })),
          ]}
        />
        <Select
          label="Sort"
          value={`${sort}:${order}`}
          onChange={(value) => {
            const [nextSort = "path", nextOrder = "asc"] = value.split(":");
            setSort(nextSort);
            setOrder(nextOrder);
          }}
          options={[
            { value: "path:asc", label: "Path A→Z" },
            { value: "path:desc", label: "Path Z→A" },
            { value: "status:desc", label: "Status high→low" },
            { value: "last_seen:desc", label: "Most recent" },
          ]}
        />
      </div>

      {loading && !data ? <Loading label="Loading endpoints…" /> : null}
      {error ? <div className="section"><ErrorState message={error} onRetry={reload} /></div> : null}

      {data && data.endpoints.length === 0 ? (
        <Card>
          <Empty
            title={query || classification || validation || method || targetId ? "No endpoints match" : "No endpoints recorded"}
            message={
              query || classification || validation || method || targetId
                ? "Loosen the filters to see more."
                : "Run a scan; the inventory fills as endpoints are discovered."
            }
            icon="route"
          />
        </Card>
      ) : null}

      {data && data.endpoints.length > 0 ? (
        <>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Method</th>
                  <th>Path</th>
                  <th>Classification</th>
                  <th>Validation</th>
                  <th className="num">Status</th>
                  <th>Source</th>
                  <th>First seen</th>
                </tr>
              </thead>
              <tbody>
                {data.endpoints.map((endpoint: Endpoint) => (
                  <tr key={endpoint.id} className="clickable" onClick={() => setDetailId(endpoint.id)}>
                    <td className="mono-cell">{endpoint.method}</td>
                    <td className="mono-cell truncate" style={{ maxWidth: 380 }}>
                      {endpoint.path_template}
                      {endpoint.query_template ? (
                        <span style={{ color: "var(--text-dim)" }}>?{endpoint.query_template}</span>
                      ) : null}
                    </td>
                    <td><Badge value={endpoint.classification} /></td>
                    <td>
                      <Badge
                        value={
                          endpoint.validation_status === "unvalidated" && ["POST", "PUT", "PATCH", "DELETE"].includes(endpoint.method)
                            ? "declared, unconfirmed"
                            : endpoint.validation_status
                        }
                      />
                    </td>
                    <td className="num">{endpoint.response_status ?? "—"}</td>
                    <td className="cell-sub">{endpoint.source_types || "—"}</td>
                    <td className="cell-sub">
                      {endpoint.first_seen_at ? new Date(Number(endpoint.first_seen_at) * 1000).toLocaleDateString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination page={page} pageSize={pageSize} total={data.total} onPage={setPage} />
        </>
      ) : null}

      {detailId ? <EndpointModal endpointId={detailId} onClose={() => setDetailId(null)} /> : null}
    </>
  );
}

interface EndpointDetailPayload {
  endpoint: Endpoint & { host?: string };
  observations?: {
    url: string;
    method: string;
    status_code: number | null;
    content_type: string;
    checked_at: number;
    error: string;
  }[];
  findings?: { id: string; rule_id: string; title: string; severity: string }[];
  [key: string]: unknown;
}

function EndpointModal({ endpointId, onClose }: { endpointId: string; onClose: () => void }): JSX.Element {
  const loader = useCallback(() => api.endpoint(endpointId) as unknown as Promise<EndpointDetailPayload>, [endpointId]);
  const { data, error, loading, reload } = useAsync<EndpointDetailPayload>(loader, [endpointId]);

  return (
    <Modal
      title={data ? `${data.endpoint.method} ${data.endpoint.path_template}` : "Endpoint"}
      onClose={onClose}
      footer={<button onClick={onClose}>Close</button>}
    >
      {loading && !data ? <Loading label="Loading endpoint…" /> : null}
      {error ? <ErrorState message={error} onRetry={reload} /> : null}
      {data ? (
        <>
          <dl className="kv">
            <dt>Host</dt>
            <dd className="mono">{data.endpoint.host ?? "—"}</dd>
            <dt>Classification</dt>
            <dd><Badge value={data.endpoint.classification} /></dd>
            <dt>Validation</dt>
            <dd>
              <Badge
                value={
                  data.endpoint.validation_status === "unvalidated" && ["POST", "PUT", "PATCH", "DELETE"].includes(data.endpoint.method)
                    ? "declared, unconfirmed"
                    : data.endpoint.validation_status
                }
              />
            </dd>
            <dt>Last status</dt>
            <dd>{data.endpoint.response_status ?? "—"}</dd>
            <dt>Sources</dt>
            <dd>{data.endpoint.source_types || "—"}</dd>
          </dl>
                    <h3 style={{ marginTop: 8 }}>Sources & Evidence</h3>
          {((data as any).sources ?? []).length === 0 ? (
            <div className="cell-sub">No source evidence recorded.</div>
          ) : (
            <div className="list">
              {((data as any).sources ?? []).map((source: any, index: number) => (
                <div className="list-row" key={index} style={{ flexDirection: "column", alignItems: "flex-start", gap: 4 }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center", width: "100%" }}>
                    <Badge value={source.source_type} />
                    <span className="mono truncate" style={{ fontSize: 13 }}>{source.source_url || "Direct / Target"}</span>
                    {source.location ? <span className="cell-sub" style={{ marginLeft: "auto", fontSize: 12 }}>{source.location}</span> : null}
                  </div>
                  {source.snippet ? (
                    <pre style={{ margin: "4px 0 0", fontSize: 12, background: "var(--bg-elevated)", padding: 6, borderRadius: 4, width: "100%", overflowX: "auto" }}>
                      <code>{source.snippet}</code>
                    </pre>
                  ) : null}
                </div>
              ))}
            </div>
          )}
          <h3 style={{ marginTop: 8 }}>Observations</h3>
          {(data.observations ?? []).length === 0 ? (
            <div className="cell-sub">No stored observations for this endpoint.</div>
          ) : (
            <div className="list">
              {(data.observations ?? []).slice(0, 12).map((observation, index) => (
                <div className="list-row" key={index}>
                  <span className="mono truncate" style={{ fontSize: 12 }}>{observation.url}</span>
                  <span className="cell-sub" style={{ marginLeft: "auto" }}>
                    {observation.error ? observation.error : `HTTP ${observation.status_code}`}
                  </span>
                </div>
              ))}
            </div>
          )}
          {(data.findings ?? []).length ? (
            <>
              <h3 style={{ marginTop: 8 }}>Findings</h3>
              <div className="list">
                {(data.findings ?? []).map((finding) => (
                  <button
                    className="list-row"
                    key={finding.id}
                    onClick={() => navigate("finding", finding.id)}
                    style={{ textAlign: "left" }}
                  >
                    <Badge value={finding.severity} />
                    <span className="grow">{finding.title}</span>
                    <span className="mono-cell">{finding.rule_id}</span>
                  </button>
                ))}
              </div>
            </>
          ) : null}
        </>
      ) : null}
    </Modal>
  );
}
