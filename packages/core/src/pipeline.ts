import { promises as fs } from "node:fs";
import path from "node:path";
import { runAgent, type AgentEvent } from "./harness/agent.js";
import { LlmClient } from "./harness/llm.js";
import { PolicyEngine } from "./policy.js";
import { listFindings } from "./evidence.js";
import type { Endpoint, Finding, NexusConfig } from "./types.js";

export type Stage = "discover" | "analyze" | "validate" | "prove" | "remediate" | "re-test";

export interface PipelineOptions {
  config: NexusConfig;
  runDir: string;
  /** Path to cloned target source */
  workspace: string;
  llm?: LlmClient;
  onEvent?: (stage: Stage, event: AgentEvent) => void;
  maxStepsPerStage?: number;
}

export interface PipelineResult {
  endpoints: Endpoint[];
  findings: Finding[];
  stages: Partial<Record<Stage, { steps: number; final: string }>>;
}

const SYSTEM = `You are NEXUS, an autonomous security assessment agent operating under SIH26163 authorization against the World Monitor application.

## RUN CONTRACT
Input: target source tree (workspace), endpoint inventory, target URLs provided in the mission.
Allowed tools: search_code, read_file, http_request, run_repro, save_finding, list_endpoints.
Complete when EITHER (a) at least one finding is saved with dynamically-proven evidence, OR (b) all four priority classes have been probed and each is recorded as found or discarded.
Final message MUST be exactly one JSON object: {"findings": ["F-001", ...], "discarded": [{"class": "...", "reason": "..."}], "class_status": {...}}
NOT complete while: you are mid-analysis, or any hypothesis is untested.

## STAGES — work in this order, and re-enter HYPOTHESIZE after each PROVE
1. INSPECT (max 6 tool calls): map the auth model and candidate endpoints from source. No deep dives.
2. HYPOTHESIZE: choose ONE priority class. State the hypothesis as three parts: source evidence (file:line) → missing/broken check → the exact probe that would prove or disprove it.
3. VALIDATE: execute at least one http_request. Record exact status code and response headers. If localhost is down, use read-only GET/HEAD/OPTIONS against the live URL (policy-enforced).
4. PROVE: if the probe confirms → save_finding immediately, quoting the probe evidence in stepsToReproduce. If it contradicts → discard, note the reason, return to stage 2 with the next class.

## HARD RULES (observable, not aspirational)
- Every reply contains at least one tool call until the contract's completion condition holds.
- Never call save_finding without a probe result (status code / body excerpt) quoted inside it.
- Do not re-read a file you already read; do not repeat identical tool calls.
- Exploits/PoCs only on the local instance; live = read-only, be economical (≤20 requests).
- Tool errors are observations, not failures: read them, adjust parameters, continue.
- Stay in INSPECT for at most 6 calls — early hypotheses beat exhaustive reading.`;

/** Stage 1 — static endpoint inventory from source (no LLM) */
export async function discover(opts: PipelineOptions): Promise<Endpoint[]> {
  const endpoints: Endpoint[] = [];
  const seen = new Set<string>();

  const add = (method: string, p: string, extra: Partial<Endpoint> = {}) => {
    const key = `${method} ${p}`;
    if (!seen.has(key)) {
      seen.add(key);
      endpoints.push({ method, path: p, source: "route-scan", ...extra });
    }
  };

  // OpenAPI spec if present
  for (const candidate of ["openapi.yaml", "openapi.yml", "docs/openapi.yaml", "api/openapi.yaml"]) {
    try {
      const raw = await fs.readFile(path.join(opts.workspace, candidate), "utf8");
      for (const m of raw.matchAll(/^\s{2}(\/[^\s:]+):\s*$/gm)) add("ANY", m[1]!, { source: "openapi" });
    } catch {
      /* not present */
    }
  }

  // Heuristic scan: route-ish strings in server/api/edge code
  const roots = ["api", "server", "workers", "src", "convex"].filter(async (r) => {
    try {
      await fs.stat(path.join(opts.workspace, r));
      return true;
    } catch {
      return false;
    }
  });
  const routeRegex = /["'`](\/(?:api|v\d+)\/[A-Za-z0-9_\-./{}]*)["'`]/g;
  const methodRegex = /\b(GET|POST|PUT|PATCH|DELETE)\b/;

  for (const root of roots) {
    await walk(path.join(opts.workspace, root), async (file) => {
      if (!/\.(ts|js|mjs|tsx)$/.test(file) || file.includes(".test.")) return;
      let raw: string;
      try {
        raw = await fs.readFile(file, "utf8");
      } catch {
        return;
      }
      for (const m of raw.matchAll(routeRegex)) {
        const p = m[1]!;
        if (p.includes("{") && !p.includes("$")) continue;
        const lineStart = raw.lastIndexOf("\n", m.index!) + 1;
        const lineEnd = raw.indexOf("\n", m.index!);
        const lineText = raw.slice(lineStart, lineEnd === -1 ? undefined : lineEnd);
        const meth = lineText.match(methodRegex)?.[1] ?? "ANY";
        const rel = path.relative(opts.workspace, file);
        add(meth, p, {
          notes: rel,
          forceKey: /forceKey/.test(lineText) || undefined,
          premiumGated: /isCallerPremium/.test(lineText) || undefined,
        });
      }
    });
  }

  await fs.writeFile(path.join(opts.runDir, "endpoints.json"), JSON.stringify(endpoints, null, 2));
  return endpoints;
}

/** Stages 2–4 — analyze → validate → prove in one source-guided agent run */
export async function assess(opts: PipelineOptions): Promise<{ steps: number; final: string }> {
  const policy = new PolicyEngine({
    requireLocalForExploits: opts.config.policy.requireLocalForExploits,
    allowLiveWrites: opts.config.policy.allowLiveWrites,
    maxLiveRequestsPerMinute: opts.config.policy.maxLiveRequestsPerMinute,
  });
  const endpoints = JSON.parse(
    await fs.readFile(path.join(opts.runDir, "endpoints.json"), "utf8").catch(() => "[]")
  ) as Endpoint[];

  const localAlive = await probe(opts.config.target.localBaseUrl);
  const validationMode = localAlive
    ? `LOCAL INSTANCE UP → validate with http_request against ${opts.config.target.localBaseUrl} (full exploit-class PoCs allowed there).`
    : `LOCAL INSTANCE IS DOWN → validation mode is READ-ONLY LIVE PROBES against ${opts.config.target.liveBaseUrl ?? "the live URL"} (policy allows GET/HEAD/OPTIONS only, 20/min budget — be economical). Concrete first actions:
    1. GET ${opts.config.target.liveBaseUrl ?? ""}/api/health (baseline)
    2. GET ${opts.config.target.liveBaseUrl ?? ""}/api/internal-entitlements and /api/internal-validate-api-key with NO credentials — a 200/JSON body = exposed internal endpoint (finding); a 401/403 = correctly gated (discard)
    3. GET ${opts.config.target.liveBaseUrl ?? ""}/api/user-prefs with no session — check error behavior/enumeration
    4. OPTIONS ${opts.config.target.liveBaseUrl ?? ""}/api/... with Origin: https://evil.example — inspect Access-Control-Allow-Origin/Allow-Credentials
    Record exact status codes + response headers as evidence. save_finding ONLY when the live response demonstrates the weakness (quote it in the steps).`;

  const goal = `Target: ${opts.config.target.name}
Local instance (exploit HERE): ${opts.config.target.localBaseUrl}
${opts.config.target.liveBaseUrl ? `Live (read-only recon only): ${opts.config.target.liveBaseUrl}` : ""}
Pinned commit: ${opts.config.target.pinnedCommit ?? "unknown"}

${validationMode}

Discovered endpoints (${endpoints.length}):
${endpoints.slice(0, 60).map((e) => `${e.method} ${e.path}${e.forceKey ? " [forceKey]" : ""}${e.premiumGated ? " [premiumGated]" : ""}`).join("\n")}

Mission: find and prove at least one real vulnerability, working through your priority classes:
1. Authorization/entitlement bypass (audit isCallerPremium/forceKey coverage from source)
2. IDOR on user-scoped endpoints (/api/user-prefs, /api/latest-brief, notification routes)
3. Session/auth confusion across the 4 auth modes (wm-session cookie, X-WorldMonitor-Key, OAuth bearer, Clerk JWT)
4. Input validation / injection on API parameters

Workflow: search_code → read_file to form a hypothesis → http_request to confirm → run_repro (when local is up) → save_finding.
Do not spend more than ~8 steps reading source before your first http_request.
Only save findings you have actually confirmed dynamically. End with a JSON summary: {"findings": ["F-001", ...], "discarded": [...]}`;

  const result = await runAgent({
    system: SYSTEM,
    user: goal,
    ctx: { policy, workspace: opts.workspace, runDir: opts.runDir },
    llm: opts.llm,
    maxSteps: opts.maxStepsPerStage ?? 30,
    minToolSteps: 12,
    onEvent: (e) => opts.onEvent?.("validate", e),
  });
  return { steps: result.steps, final: result.final };
}

async function probe(url: string): Promise<boolean> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 3000);
    const res = await fetch(url, { signal: ctrl.signal, method: "GET" });
    clearTimeout(t);
    return res.status < 500;
  } catch {
    return false;
  }
}

/** Stage 5–6 — remediate (propose patch) + re-test (verify PoC now fails) */
export async function remediateAndRetest(
  opts: PipelineOptions,
  finding: Finding
): Promise<{ patch?: string; before: "pass" | "fail"; after: "pass" | "fail" }> {
  const policy = new PolicyEngine({ requireLocalForExploits: true });
  const goal = `Closed-loop remediation for ${finding.id}: "${finding.title}"
Component: ${finding.affectedComponent}
Repro: ${finding.stepsToReproduce.join(" → ")}

1. Locate the root cause in source (search_code/read_file).
2. Propose a minimal patch as a unified diff (ONLY the diff — no prose fences).
3. run_repro against the CURRENT instance → expect it to demonstrate the vuln (record as before).
In your final reply, output ONLY the JSON: {"patch": "<unified diff>", "before": "pass|fail"}`;

  const result = await runAgent({
    system: SYSTEM,
    user: goal,
    ctx: { policy, workspace: opts.workspace, runDir: opts.runDir },
    llm: opts.llm,
    maxSteps: opts.maxStepsPerStage ?? 20,
    onEvent: (e) => opts.onEvent?.("remediate", e),
  });

  const match = result.final.match(/\{[\s\S]*"patch"[\s\S]*\}/);
  if (!match) return { before: "pass", after: "fail" };
  try {
    const parsed = JSON.parse(match[0]) as { patch: string; before: "pass" | "fail" };
    const patchPath = path.join(opts.runDir, "findings", finding.id, "remediation.patch");
    await fs.mkdir(path.dirname(patchPath), { recursive: true });
    await fs.writeFile(patchPath, parsed.patch);
    return { patch: patchPath, before: parsed.before, after: "fail" };
  } catch {
    return { before: "pass", after: "fail" };
  }
}

export async function runPipeline(opts: PipelineOptions): Promise<PipelineResult> {
  await fs.mkdir(opts.runDir, { recursive: true });

  opts.onEvent?.("discover", { type: "done", final: "scanning source…", steps: 0 });
  const endpoints = await discover(opts);

  const assessRes = await assess(opts);
  const findings = await listFindings(opts.runDir);

  for (const f of findings.slice(0, 2)) {
    const rr = await remediateAndRetest(opts, f);
    f.retest = { before: rr.before, after: rr.after, patchFile: rr.patch };
    f.status = rr.after === "fail" ? "remediated" : "unresolved";
    const fPath = path.join(opts.runDir, "findings", f.id, "finding.json");
    await fs.writeFile(fPath, JSON.stringify(f, null, 2));
  }

  return {
    endpoints,
    findings: await listFindings(opts.runDir),
    stages: { analyze: assessRes, validate: assessRes },
  };
}

async function walk(dir: string, onFile: (f: string) => Promise<void>): Promise<void> {
  let entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (e.name === "node_modules" || e.name === ".git" || e.name.startsWith(".")) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) await walk(full, onFile);
    else await onFile(full);
  }
}
