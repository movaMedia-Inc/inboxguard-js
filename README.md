# InboxGuard — TypeScript / JavaScript SDK

Official SDK for the [InboxGuard](https://inboxguard.io) email deliverability API:
scan SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, and DNS blocklists for any domain.

## Install

```bash
npm install inboxguard
```

## Usage

```ts
import { InboxGuard } from "inboxguard";

// Anonymous scan (5/hour per IP) — no key required:
const ig = new InboxGuard();
const report = await ig.scanDomain("example.com");
console.log(report.score.total, report.score.grade); // e.g. 88 "B"
// Checks are TOP-LEVEL keys on the report (no `checks` wrapper); each has
// `healthy` and `issues: [{severity, message}]`.
for (const name of ["spf", "dkim", "dmarc", "ptr", "mtaSts", "tlsRpt", "bimi", "blocklist"] as const) {
  console.log(name, report[name]?.healthy, report[name]?.issues);
}

// Authenticated (full blocklist set, history, more domains):
const auth = new InboxGuard({ apiKey: "ig_live_xxxxxxxxxxxxxxxxxxxxxxxx" });
const { items, total } = await auth.listDomains(); // all domains; no pagination
console.log(total, items[0]?.latest_score, items[0]?.open_alerts);

// Resolve a domain name to its monitored row, then drill in:
const dom = await auth.findDomain("example.com");
if (dom) {
  const scans = await auth.listScans({ domainId: dom.id, limit: 20 });
  console.log(scans.items.map((s) => [s.run_at, s.score]), scans.nextCursor);

  const dmarc = await auth.listDmarcReports({ domainId: dom.id, days: 30 });
  console.log(dmarc.ruaInbox.address, dmarc.totals, dmarc.topSenders[0]);
}

// Open alerts (rows use `kind`, `severity`, `resolved_at`):
const alerts = await auth.listAlerts({ resolved: false, severity: "critical" });
console.log(alerts.total, alerts.items[0]?.kind);
```

### Fix DNS, don't just report it

Scans now return `remediations` (the exact record to publish per failing check,
with an `autoFixable` flag) and a `dnssec` block. For tracked domains with a
connected registrar you can remediate end to end — preview, apply, re-scan:

```ts
const auth = new InboxGuard({ apiKey: "ig_live_xxxxxxxxxxxxxxxxxxxxxxxx" });

// 1. Scan and read the fix list.
const report = await auth.scanDomain("example.com");
console.log(report.remediations, report.dnssec.enabled);

// 2. Preview the DNS fix plan (read-only). Resolves the name → id for you.
const plan = await auth.getDnsFixPlan("example.com");
console.log(plan.connected, plan.ops, plan.manualReview);

// 3. Apply it (DESTRUCTIVE — needs an owner/admin `full` key). Pass the
//    connectionId + ops from the plan verbatim; the server re-validates them.
if (plan.connected && plan.connectionId && plan.ops.length) {
  const result = await auth.applyDnsFix({
    domain: "example.com",
    connectionId: plan.connectionId,
    ops: plan.ops,
  });
  console.log(result.results); // per-op outcome (not transactional)

  // 4. Re-scan to confirm.
  console.log((await auth.scanDomain("example.com")).score.total);
}
```

## Authentication

Pass an API key (`ig_live_…` / `ig_test_…`) as `apiKey`. Mint one in the
dashboard (**Settings → API keys**) or via the API. See
<https://inboxguard.io/auth.md>.

## Errors

Failed requests throw `InboxGuardError` with `status`, `code`, `message`,
`requestId`, and (on 429) `retryAfterSeconds`.

```ts
import { InboxGuardError } from "inboxguard";
try {
  await ig.scanDomain("example.com");
} catch (e) {
  if (e instanceof InboxGuardError && e.code === "RATE_LIMIT") {
    console.log("retry after", e.retryAfterSeconds, "s");
  }
}
```

## Reference

- OpenAPI: <https://inboxguard.io/openapi.json>
- Full docs: <https://inboxguard.io/llms-full.txt>
- MCP server: `https://api.inboxguard.io/mcp`

MIT © movaMedia, Inc.
