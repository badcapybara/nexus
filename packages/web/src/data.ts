export interface MockFinding {
  id: string;
  title: string;
  component: string;
  scope: string;
  severity: { score: number; level: string; vector: string };
  status: "proven" | "validated" | "remediated";
  summary: string;
  hypothesis: { file: string; reasoning: string };
  steps: string[];
  evidence: { repro: string; transcript: string };
  impact: string;
  remediation: string;
  retest?: { before: string; after: string };
}

export const RUN = {
  target: "World Monitor",
  repo: "github.com/koala73/worldmonitor",
  commit: "0d5c618e",
  date: "29 Sep 2026",
  model: "qwen3.5:9b · local",
  policy: "PoC confined to local instance · live target read-only",
  ps: "SIH26163 · NTRO",
};

export const STATS = [
  { value: "4", label: "confirmed findings" },
  { value: "2", label: "critical / high" },
  { value: "1", label: "fix verified" },
  { value: "100%", label: "repro pass rate" },
];

export const BENCHMARK = [
  { metric: "Recall (seeded mutants)", value: "5 / 6" },
  { metric: "Precision", value: "67 %" },
  { metric: "Time to first finding", value: "4 m 12 s" },
  { metric: "Held-out test · issue #5061", value: "found" },
];

export const FINDINGS: MockFinding[] = [
  {
    id: "F-001",
    title: "Internal entitlement endpoint reachable without internal-auth",
    component: "GET /api/internal-entitlements",
    scope: "Authorization & access control",
    severity: {
      score: 9.1,
      level: "CRITICAL",
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    status: "remediated",
    summary:
      "The internal entitlements route answers unauthenticated requests when the internal-auth shared-secret header is omitted, exposing subscription state for arbitrary user identifiers.",
    hypothesis: {
      file: "api/internal-entitlements.ts",
      reasoning:
        "Handler calls authenticateInternalRequest() only when the x-internal-secret header is present — absence short-circuits to the happy path instead of rejecting.",
    },
    steps: [
      "curl -s https://<target>/api/internal-entitlements?userId=usr_2048",
      "Observe HTTP 200 with entitlement JSON and no credentials supplied.",
      "Repeat with any userId — records for other accounts are returned (horizontal access).",
    ],
    evidence: {
      repro: "bash findings/F-001/repro.sh",
      transcript:
        "> GET /api/internal-entitlements?userId=usr_2048 HTTP/1.1\n< HTTP/1.1 200 OK\n< content-type: application/json\n\n{\"userId\":\"usr_2048\",\"plan\":\"pro\",\"seats\":5,\"renewsAt\":\"2027-01-14\"}",
    },
    impact:
      "Any internet caller can enumerate subscription and seat data for all customers — a confidentiality breach affecting every account on the platform.",
    remediation:
      "Fail closed: require and verify the internal secret on every request before touching the entitlement store. Return 401 on absence or mismatch.",
    retest: { before: "exploit confirmed", after: "blocked after patch" },
  },
  {
    id: "F-002",
    title: "PRO entitlement skipped on shipping-intelligence cache-hit path",
    component: "GET /api/v2/shipping/route-intelligence",
    scope: "API security",
    severity: {
      score: 7.5,
      level: "HIGH",
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    status: "proven",
    summary:
      "The premium-gated shipping endpoint validates the API key but bypasses isCallerPremium() when a warm cache entry exists, serving PRO-tier intelligence to free-tier keys.",
    hypothesis: {
      file: "server/gateway.ts:2103",
      reasoning:
        "Cache-hit branch (peek.response) returns before the entitlement gate that only runs on cache-miss — order of checks inverted for this route.",
    },
    steps: [
      "Authenticate with a valid free-tier X-WorldMonitor-Key.",
      "GET /api/v2/shipping/route-intelligence?origin=SGSIN&destination=NLRTM (prime the cache).",
      "First response: 403. Immediate repeat: 200 with full PRO payload.",
    ],
    evidence: {
      repro: "bash findings/F-002/repro.sh",
      transcript:
        "> GET /api/v2/shipping/route-intelligence?origin=SGSIN&destination=NLRTM\n> x-worldmonitor-key: wm_<free-tier>\n< HTTP/1.1 200 OK  (2nd request, cache hit)\n< x-wm-tier: pro\n\n{\"route\":[…],\"riskScore\":71,\"eta\":\"31h\"}",
    },
    impact:
      "Free-tier and leaked keys harvest premium commercial intelligence at will; revenue-gated data becomes effectively public once warmed by any caller.",
    remediation:
      "Move isCallerPremium() ahead of cache lookup, or store tier with the cache entry and re-check on every hit.",
    retest: { before: "exploit confirmed", after: "patch ready · re-test scheduled" },
  },
  {
    id: "F-003",
    title: "Cross-user read of notification preferences (IDOR)",
    component: "GET /api/user-prefs",
    scope: "Authorization & access control",
    severity: {
      score: 6.5,
      level: "MEDIUM",
      vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    },
    status: "validated",
    summary:
      "The user-preferences route honours a client-supplied userId query parameter without comparing it to the authenticated session subject.",
    hypothesis: {
      file: "api/user-prefs.ts:42",
      reasoning:
        "Handler reads userId from the query string; session.sub is available in scope but never compared — classic ownership-check omission.",
    },
    steps: [
      "Sign in as user A; capture the wm-session cookie.",
      "GET /api/user-prefs?userId=<user B id> with A's cookie.",
      "Response contains user B's notification endpoints and display preferences.",
    ],
    evidence: {
      repro: "bash findings/F-003/repro.sh",
      transcript:
        "> GET /api/user-prefs?userId=usr_9130 Cookie: wm-session=<A>\n< HTTP/1.1 200 OK\n\n{\"userId\":\"usr_9130\",\"emailDigest\":true,\"channels\":[\"slack\",\"sms\"]}",
    },
    impact:
      "Authenticated users read other users' contact channels and delivery preferences — reconnaissance for account-takeover follow-ups.",
    remediation:
      "Derive the user id exclusively from the verified session claim; reject any request whose userId parameter disagrees.",
  },
  {
    id: "F-004",
    title: "High-severity advisory in transitive dependency chain",
    component: "feed-parser → brace-expansion (advisory GHSA-patch-series)",
    scope: "Supply chain / dependency risk",
    severity: {
      score: 5.3,
      level: "MEDIUM",
      vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
    status: "validated",
    summary:
      "SBOM generation and OSV matching surface a high-severity advisory two levels below a top-level feed-parsing dependency; no fix is published upstream.",
    hypothesis: {
      file: "package-lock.json (transitive)",
      reasoning:
        "PS scope explicitly includes supply-chain risk — osv-scanner over the pinned lockfile flags an unfixed advisory reachable from the RSS ingestion path.",
    },
    steps: [
      "Generate SBOM: syft dir:. -o spdx-json > sbom.json",
      "osv-scanner --sbom=sbom.json",
      "Observe 1 high-severity advisory, path: feed-parser@x.y → brace-expansion@1.1.x.",
    ],
    evidence: {
      repro: "bash findings/F-004/repro.sh",
      transcript:
        "$ osv-scanner --sbom=sbom.json\nGoogle OSV-Scanner\n┌────────────┬─────────────────────┬──────┐\n│ Package    │ feed-parser→brace…  │ 7.5H │\n└────────────┴─────────────────────┴──────\n1 vulnerability found",
    },
    impact:
      "Unfixed transitive CVE sits on the content-ingestion path; a published exploit would compromise feed processing for all deployments.",
    remediation:
      "Pin the patched fork, override the transitive version via package overrides, or replace the feed parser until upstream ships a fix.",
  },
];

export const COVERAGE = [
  { area: "Authentication & session management", status: "tested", findings: ["F-003"] },
  { area: "Authorization & access control", status: "finding", findings: ["F-001", "F-003"] },
  { area: "Input validation & data handling", status: "tested", findings: [] },
  { area: "API security", status: "finding", findings: ["F-002"] },
  { area: "Client-side security controls", status: "tested", findings: [] },
  { area: "Secure communication mechanisms", status: "tested", findings: [] },
  { area: "Data storage & privacy protections", status: "tested", findings: [] },
  { area: "Supply chain / dependency risk", status: "finding", findings: ["F-004"] },
];

export const PIPELINE = [
  { n: "01", name: "Discover", desc: "OpenAPI + source scan → 335 endpoints with forceKey / premium-gated flags." },
  { n: "02", name: "Analyze", desc: "Agent reads auth code and forms a falsifiable hypothesis per class." },
  { n: "03", name: "Validate", desc: "Exactly one targeted probe — status code and headers become evidence." },
  { n: "04", name: "Prove", desc: "repro.sh + hashed transcript — evaluators re-run it with one command." },
  { n: "05", name: "Remediate", desc: "Minimal unified-diff patch proposed at the root cause." },
  { n: "06", name: "Re-test", desc: "Patch applied — PoC must now fail. Fix is verified, not claimed." },
];
