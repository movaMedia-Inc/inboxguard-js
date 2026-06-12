/**
 * Official InboxGuard TypeScript/JavaScript SDK.
 *
 *   import { InboxGuard } from "inboxguard";
 *   const ig = new InboxGuard({ apiKey: "ig_live_..." });
 *   const report = await ig.scanDomain("example.com");
 *   console.log(report.score.total, report.score.grade);
 *
 * Docs: https://inboxguard.io/llms-full.txt · OpenAPI: https://inboxguard.io/openapi.json
 */

export interface ScanScore {
  /** Overall 0–100 score. */
  total: number;
  grade: "A" | "B" | "C" | "D" | "F";
  /** Points contributed by each check (spf, dmarc, ptr, dkim, bimi, mtaSts, tlsRpt, blocklist). */
  breakdown: Record<string, number>;
}

/** One finding inside a check. */
export interface Issue {
  severity: "info" | "warn" | "critical";
  message: string;
}

/**
 * A single check result: `healthy` + `issues` plus check-specific fields
 * (SPF `lookupCount`, DMARC `policy`, DKIM `keys[]`, blocklist `hits[]`, …).
 * Note: `mxTls` reports `status` ('unsupported'|'pass'|'fail'|'partial')
 * instead of `healthy`; `bimi` uses `found`/`logoReachable`/`displayEligible`.
 */
export interface DomainCheck {
  healthy?: boolean;
  issues?: Issue[];
  [key: string]: unknown;
}

/** POST /scan-domain response. Checks are TOP-LEVEL keys — there is no `checks` wrapper. */
export interface ScanResult {
  domain: string;
  score: ScanScore;
  /** Version of the scoring model that produced `score`. */
  scoringVersion: number;
  spf: DomainCheck;
  dmarc: DomainCheck;
  ptr: DomainCheck;
  dkim: DomainCheck;
  mtaSts: DomainCheck;
  tlsRpt: DomainCheck;
  mxTls: DomainCheck;
  bimi: DomainCheck;
  blocklist: DomainCheck;
  durationMs: number;
  plan: { tier: string; trialing: boolean; blocklistsChecked: number | string };
}

/** One monitored domain as returned by GET /domains (snake_case fields). */
export interface DomainSummary {
  id: string;
  domain: string;
  status: string;
  /** On-demand scans used this month against the plan's per-domain quota. */
  quota_used: number;
  created_at: string;
  latest_score: number | null;
  latest_scan_at: string | null;
  open_alerts: number;
}

export interface DomainList {
  items: DomainSummary[];
  total: number;
}

/** GET /domains/{id} response. */
export interface DomainDetail {
  domain: {
    id: string;
    domain: string;
    status: string;
    quota_used: number;
    created_at: string;
    updated_at: string;
  };
  /**
   * Latest scan with all per-check JSON. NOTE: stored check keys here are
   * snake_case (`mta_sts`, `tls_rpt`, `mx_tls`), unlike the live
   * /scan-domain response.
   */
  latestScan:
    | ({
        id: string;
        run_at: string;
        score: number;
        spf: DomainCheck;
        dmarc: DomainCheck;
        ptr: DomainCheck;
        dkim: DomainCheck;
        mta_sts: DomainCheck;
        tls_rpt: DomainCheck;
        mx_tls: DomainCheck;
        blocklist: DomainCheck;
      } & Record<string, unknown>)
    | null;
  history: Array<{ id: string; run_at: string; score: number }>;
  alerts: Array<{
    id: string;
    kind: string;
    severity: "critical" | "warn" | "info";
    message: string;
    created_at: string;
    resolved_at: string | null;
  }>;
  postmaster: {
    state: "not_connected" | "connected_no_data" | "active";
    verified: boolean;
    latest: Record<string, unknown> | null;
  };
}

/** Thin scan-history row from GET /scans (snake_case fields). */
export interface ScanListItem {
  id: string;
  domain_id: string;
  domain: string;
  run_at: string;
  score: number;
}

export interface ScanListPage {
  items: ScanListItem[];
  /** run_at of the last item when the page is full — pass as `before` to walk older scans; null when done. */
  nextCursor: string | null;
}

/** GET /domains/{id}/dmarc-reports response. */
export interface DmarcReportsResponse {
  domain: { id: string; name: string };
  days: number;
  /** The org's hosted RUA mailbox — publish this in the domain's DMARC record. */
  ruaInbox: { address: string; configured: boolean; dmarcSnippet: string };
  daily: Array<{
    date: string;
    source: string;
    spfAligned: number;
    dkimAligned: number;
    passCount: number;
    failCount: number;
  }>;
  topSenders: Array<{
    sourceIp: string;
    headerFrom: string;
    count: number;
    passCount: number;
    failCount: number;
  }>;
  totals: { volume: number; pass: number; fail: number; sources: number };
}

/** A single DNS record inside a fix-plan op. */
export interface DnsRecord {
  /** Provider-side record id (present on existing records; needed for update/delete). */
  id?: string;
  /** Fully-qualified record name, e.g. _dmarc.example.com. */
  name: string;
  type: "TXT" | "CNAME" | "A" | "AAAA" | "MX";
  value: string;
  ttl?: number | null;
  priority?: number | null;
}

/**
 * One change in a DNS fix plan. `noop` ops describe records already correct.
 * Pass the `ops` array from getDnsFixPlan to applyDnsFix verbatim.
 */
export interface DnsOp {
  kind: "create" | "update" | "delete" | "noop";
  reason?: string;
  before: DnsRecord | null;
  after: DnsRecord | null;
}

/**
 * GET /domains/{id}/dns-diff response — the DNS fix plan. Read-only.
 * When `connected` is false (or no connected registrar manages the apex),
 * `ops`/`manualReview` are empty and `reason` explains why.
 */
export interface DnsDiffResult {
  connected: boolean;
  /** Pass to applyDnsFix. Null when no connection covers the zone. */
  connectionId?: string | null;
  provider?: string | null;
  identity?: string | null;
  apex?: string;
  scan?: { id: string; runAt: string };
  /** The record changes to apply — pass verbatim to applyDnsFix. */
  ops: DnsOp[];
  /** Fixes needing a human decision (SPF sender list, DKIM keys, BIMI logo). */
  manualReview: Array<Record<string, unknown>>;
  /** Present when `ops` is empty: why no auto-fix is available. */
  reason?: string;
}

/** POST /domains/{id}/dns-apply response — per-op outcome (NOT transactional). */
export interface DnsApplyResult {
  /** Remediation plan id (audit trail). */
  planId: string;
  connectionId: string;
  provider: string;
  apex: string;
  results: Array<{
    kind: "create" | "update" | "delete";
    name: string | null;
    type: string | null;
    ok: boolean;
    /** Present when `ok` is false. */
    error?: string;
    stepId?: string;
  }>;
}

/** One alert row (snake_case fields). Open when `resolved_at` is null. */
export interface Alert {
  id: string;
  /** Alert category, e.g. score_drop, check_failed, blocklist_listed. */
  kind: string;
  severity: "critical" | "warn" | "info";
  message: string;
  details?: Record<string, unknown> | null;
  entity_type: string;
  entity_id: string;
  created_at: string;
  resolved_at: string | null;
  escalated_at?: string | null;
}

export interface AlertList {
  items: Alert[];
  total: number;
}

export interface InboxGuardOptions {
  /** API key (ig_live_… / ig_test_…). Optional — scanDomain works anonymously. */
  apiKey?: string;
  /** Override the API base URL. Defaults to https://api.inboxguard.io. */
  baseUrl?: string;
  /** Request timeout in ms (default 30000). */
  timeoutMs?: number;
  /** Custom fetch implementation (defaults to global fetch). */
  fetch?: typeof fetch;
}

/** Structured API error. `code` mirrors the API's error codes (RATE_LIMIT, DNS_TEMPORARY_FAILURE, …). */
export class InboxGuardError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly requestId?: string,
    public readonly retryAfterSeconds?: number,
  ) {
    super(message);
    this.name = "InboxGuardError";
  }
}

export interface ScanOptions {
  dkimSelectors?: string[];
  /**
   * Idempotency-Key header for safe retries: the same key from the same
   * caller within 1 hour replays the stored response instead of re-running
   * (and re-billing) the scan.
   */
  idempotencyKey?: string;
}

export class InboxGuard {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: InboxGuardOptions = {}) {
    this.baseUrl = (opts.baseUrl ?? "https://api.inboxguard.io").replace(/\/$/, "");
    this.apiKey = opts.apiKey;
    this.timeoutMs = opts.timeoutMs ?? 30_000;
    const f = opts.fetch ?? (globalThis.fetch as typeof fetch | undefined);
    if (!f) throw new Error("No fetch implementation available; pass `fetch` in options (Node <18).");
    this.fetchImpl = f;
  }

  /** Run a deliverability scan. Works anonymously (5/hour per IP) or authenticated. */
  scanDomain(domain: string, opts: ScanOptions = {}): Promise<ScanResult> {
    const headers: Record<string, string> = {};
    if (opts.idempotencyKey) headers["Idempotency-Key"] = opts.idempotencyKey;
    return this.request<ScanResult>("POST", "/scan-domain", {
      body: { domain, dkimSelectors: opts.dkimSelectors },
      headers,
    });
  }

  /** Service health (no auth). */
  health(): Promise<{ status: string; db: string }> {
    return this.request("GET", "/health");
  }

  /** List ALL monitored domains (auth required). The API has no pagination here. */
  listDomains(): Promise<DomainList> {
    return this.request("GET", "/domains");
  }

  /**
   * Convenience: resolve a domain NAME (e.g. "example.com") to its monitored
   * DomainSummary by listing domains and matching case-insensitively.
   * Returns null when the domain isn't tracked in the account.
   */
  async findDomain(domain: string): Promise<DomainSummary | null> {
    const { items } = await this.listDomains();
    const needle = domain.trim().toLowerCase();
    return items.find((d) => d.domain.toLowerCase() === needle) ?? null;
  }

  /** Full detail for one monitored domain by id (UUID from listDomains/findDomain). */
  getDomain(id: string): Promise<DomainDetail> {
    return this.request("GET", `/domains/${encodeURIComponent(id)}`);
  }

  deleteDomain(id: string): Promise<{ ok: boolean; deleted?: { id: string; domain: string } }> {
    return this.request("DELETE", `/domains/${encodeURIComponent(id)}`);
  }

  /**
   * Scan history (thin rows), most recent first. Filter with `domainId`
   * (UUID); page with `before` (pass the previous response's `nextCursor`).
   */
  listScans(params: { domainId?: string; before?: string; limit?: number } = {}): Promise<ScanListPage> {
    return this.request("GET", "/scans", { query: params });
  }

  /**
   * DMARC aggregate (RUA) report data for one monitored domain:
   * GET /domains/{domainId}/dmarc-reports?days=N (1–90, default 30).
   * Resolve the domainId from a name with findDomain(). Requires a plan with
   * DMARC ingest (403 otherwise).
   */
  listDmarcReports(params: { domainId: string; days?: number }): Promise<DmarcReportsResponse> {
    const { domainId, days } = params;
    return this.request("GET", `/domains/${encodeURIComponent(domainId)}/dmarc-reports`, {
      query: { days },
    });
  }

  /**
   * Preview the DNS fix plan for a tracked domain (read-only): the exact
   * record changes to fix it, derived from its latest scan + the connected
   * registrar. Resolves the domain NAME to its id via findDomain(), then hits
   * GET /domains/{id}/dns-diff. Returns the `ops` to pass verbatim to
   * applyDnsFix, plus `manualReview` items needing a human decision.
   *
   * @throws InboxGuardError if the domain isn't tracked in the account.
   */
  async getDnsFixPlan(domain: string): Promise<DnsDiffResult> {
    const dom = await this.findDomain(domain);
    if (!dom) {
      throw new InboxGuardError(404, "NOT_FOUND", `${domain} is not tracked in this account.`);
    }
    return this.request("GET", `/domains/${encodeURIComponent(dom.id)}/dns-diff`);
  }

  /**
   * Apply a DNS fix plan — DESTRUCTIVE: publishes records at the connected
   * registrar. Two-step: pass the `connectionId` and `ops` from getDnsFixPlan
   * verbatim. The server re-derives the diff and rejects any op that no longer
   * matches (400, stale plan). Resolves the domain NAME to its id via
   * findDomain(), then POSTs /domains/{id}/dns-apply. Requires an owner/admin
   * key with `full` scope (403 otherwise). Re-scan afterward to confirm.
   *
   * @throws InboxGuardError if the domain isn't tracked in the account.
   */
  async applyDnsFix(params: { domain: string; connectionId: string; ops: DnsOp[] }): Promise<DnsApplyResult> {
    const dom = await this.findDomain(params.domain);
    if (!dom) {
      throw new InboxGuardError(404, "NOT_FOUND", `${params.domain} is not tracked in this account.`);
    }
    return this.request("POST", `/domains/${encodeURIComponent(dom.id)}/dns-apply`, {
      body: { connectionId: params.connectionId, ops: params.ops },
    });
  }

  /**
   * List alerts. `resolved`: false (default) = open only, true = resolved
   * only, "all" = both. `severity`: critical | warn | info | all.
   */
  listAlerts(
    params: {
      resolved?: boolean | "all";
      severity?: "critical" | "warn" | "info" | "all";
      entityType?: "domain" | "org" | "user" | "all";
      limit?: number;
    } = {},
  ): Promise<AlertList> {
    const { resolved, severity, entityType, limit } = params;
    return this.request("GET", "/alerts", {
      query: {
        resolved: resolved === undefined ? undefined : String(resolved),
        severity,
        entityType,
        limit,
      },
    });
  }

  private async request<T>(
    method: string,
    path: string,
    opts: { body?: unknown; query?: Record<string, unknown>; headers?: Record<string, string> } = {},
  ): Promise<T> {
    const url = new URL(this.baseUrl + path);
    for (const [k, v] of Object.entries(opts.query ?? {})) {
      if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
    }
    const headers: Record<string, string> = {
      accept: "application/json",
      ...(opts.headers ?? {}),
    };
    if (this.apiKey) headers.authorization = `Bearer ${this.apiKey}`;
    if (opts.body !== undefined) headers["content-type"] = "application/json";

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let resp: Response;
    try {
      resp = await this.fetchImpl(url.toString(), {
        method,
        headers,
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    const text = await resp.text();
    const data = text ? JSON.parse(text) : {};
    if (!resp.ok) {
      const err = (data as { error?: { code?: string; message?: string; requestId?: string; retryAfterSeconds?: number } }).error ?? {};
      throw new InboxGuardError(
        resp.status,
        err.code ?? "ERROR",
        err.message ?? `Request failed with status ${resp.status}`,
        err.requestId,
        err.retryAfterSeconds ?? (resp.headers.get("retry-after") ? Number(resp.headers.get("retry-after")) : undefined),
      );
    }
    return data as T;
  }
}

export default InboxGuard;
