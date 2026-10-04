import { promises as fs } from "node:fs";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { PolicyEngine, PolicyViolation } from "../policy.js";
import type { LlmToolSpec } from "./llm.js";

const execFileAsync = promisify(execFile);

export interface ToolContext {
  policy: PolicyEngine;
  /** Root of the cloned target source */
  workspace: string;
  /** Where NEXUS writes findings/evidence */
  runDir: string;
}

export interface ToolResult {
  ok: boolean;
  output: string;
}

export interface Tool {
  spec: LlmToolSpec;
  execute(args: Record<string, unknown>, ctx: ToolContext): Promise<ToolResult>;
}

const MAX_OUTPUT = 8_000;

/**
 * Head+tail truncation with an explicit continuation hint (harness pattern from Pi/Claude Code):
 * errors and response tails matter, so keep both ends and tell the model how to get the middle.
 */
function clip(s: string): string {
  if (s.length <= MAX_OUTPUT) return s;
  const head = s.slice(0, 6_200);
  const tail = s.slice(-1_400);
  return `${head}\n…[${s.length - 7_600} chars elided — narrow the query (line range, smaller pattern) to retrieve this region]…\n${tail}`;
}

function safeResolve(root: string, p: string): string {
  const abs = path.resolve(root, p);
  if (abs !== root && !abs.startsWith(root + path.sep)) {
    throw new Error(`path escapes workspace: ${p}`);
  }
  return abs;
}

export const searchCodeTool: Tool = {
  spec: {
    type: "function",
    function: {
      name: "search_code",
      description:
        "Regex search across the target's source code. Returns file:line matches. Use for source-guided hypothesis generation (find auth checks, route handlers, validators).",
      parameters: {
        type: "object",
        properties: {
          pattern: { type: "string", description: "regex to search" },
          include: { type: "string", description: "glob filter, e.g. '*.ts' or 'api/**'" },
          maxResults: { type: "number" },
        },
        required: ["pattern"],
      },
    },
  },
  async execute(args, ctx) {
    const pattern = String(args.pattern ?? "");
    const include = args.include ? String(args.include) : undefined;
    try {
      const rgArgs = ["-n", "--no-heading", "-S", "-e", pattern];
      if (include) rgArgs.push("-g", include);
      rgArgs.push(".");
      const { stdout } = await execFileAsync("rg", rgArgs, {
        cwd: ctx.workspace,
        maxBuffer: 10 * 1024 * 1024,
      });
      const lines = stdout.split("\n").filter(Boolean);
      const max = Number(args.maxResults ?? 40);
      return { ok: true, output: clip(lines.slice(0, max).join("\n")) };
    } catch (e) {
      const err = e as { stdout?: string; code?: number };
      if (err.code === 1 && err.stdout === "") return { ok: true, output: "(no matches)" };
      if (err.stdout) return { ok: true, output: clip(String(err.stdout)) };
      return { ok: false, output: `search failed: ${String(e)}` };
    }
  },
};

export const readFileTool: Tool = {
  spec: {
    type: "function",
    function: {
      name: "read_file",
      description: "Read a source file (optionally a line range) from the target workspace.",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string" },
          startLine: { type: "number" },
          endLine: { type: "number" },
        },
        required: ["path"],
      },
    },
  },
  async execute(args, ctx) {
    try {
      const abs = safeResolve(ctx.workspace, String(args.path));
      const raw = await fs.readFile(abs, "utf8");
      const lines = raw.split("\n");
      const start = Math.max(0, (Number(args.startLine ?? 1) || 1) - 1);
      const end = Math.min(lines.length, Number(args.endLine ?? lines.length) || lines.length);
      const body = lines
        .slice(start, end)
        .map((l: string, i: number) => `${start + i + 1}\t${l}`)
        .join("\n");
      return { ok: true, output: clip(body) };
    } catch (e) {
      return { ok: false, output: String(e) };
    }
  },
};

export const httpRequestTool: Tool = {
  spec: {
    type: "function",
    function: {
      name: "http_request",
      description:
        "Send an HTTP request to probe the target. Policy-gated: non-local targets are read-only and rate-limited.",
      parameters: {
        type: "object",
        properties: {
          url: { type: "string" },
          method: { type: "string", enum: ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"] },
          headers: { type: "object" },
          body: { type: "string" },
        },
        required: ["url", "method"],
      },
    },
  },
  async execute(args, ctx) {
    const url = String(args.url);
    const method = String(args.method ?? "GET").toUpperCase();
    try {
      ctx.policy.authorizeRequest(url, method);
      const res = await fetch(url, {
        method,
        headers: {
          "user-agent": "NEXUS-Security-Agent/0.1 (SIH26163 authorized assessment)",
          ...(args.headers && typeof args.headers === "object"
            ? (args.headers as Record<string, string>)
            : {}),
        },
        body: method === "GET" || method === "HEAD" ? undefined : args.body ? String(args.body) : undefined,
        redirect: "manual",
      });
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => (headers[k] = v));
      const text = await res.text().catch(() => "");
      return {
        ok: true,
        output: clip(
          `HTTP ${res.status} ${res.statusText}\n${JSON.stringify(headers, null, 2)}\n\n${text}`
        ),
      };
    } catch (e) {
      if (e instanceof PolicyViolation) return { ok: false, output: e.message };
      return { ok: false, output: `request failed: ${String(e)}` };
    }
  },
};

export const runReproTool: Tool = {
  spec: {
    type: "function",
    function: {
      name: "run_repro",
      description:
        "Execute a repro script (bash) inside the run directory against the LOCAL instance. Blocked by policy for any non-local target.",
      parameters: {
        type: "object",
        properties: {
          script: { type: "string", description: "bash script content; $NEXUS_TARGET is set to local base URL" },
        },
        required: ["script"],
      },
    },
  },
  async execute(args, ctx) {
    const target = process.env.NEXUS_TARGET ?? "http://localhost:3000";
    try {
      ctx.policy.authorizeExploit(target);
      const reproDir = path.join(ctx.runDir, "tmp");
      await fs.mkdir(reproDir, { recursive: true });
      const file = path.join(reproDir, `repro-${Date.now()}.sh`);
      await fs.writeFile(file, `#!/usr/bin/env bash\nset -euo pipefail\nNEXUS_TARGET="${target}"\n${String(args.script)}\n`, {
        mode: 0o700,
      });
      const { stdout, stderr } = await execFileAsync("bash", [file], {
        cwd: ctx.runDir,
        timeout: 30_000,
      });
      return { ok: true, output: clip(`exit 0\n${stdout}\n${stderr}`) };
    } catch (e) {
      if (e instanceof PolicyViolation) return { ok: false, output: e.message };
      const err = e as { stdout?: string; stderr?: string; message?: string };
      return { ok: false, output: clip(`exit != 0\n${err.stdout ?? ""}\n${err.stderr ?? ""}\n${err.message ?? ""}`) };
    }
  },
};

export const saveFindingTool: Tool = {
  spec: {
    type: "function",
    function: {
      name: "save_finding",
      description:
        "Persist a validated finding with all SIH26163 deliverable fields (title, component, CVSS, repro steps, impact, remediation).",
      parameters: {
        type: "object",
        properties: {
          title: { type: "string" },
          description: { type: "string" },
          affectedComponent: { type: "string" },
          scopeArea: {
            type: "string",
            enum: [
              "auth-session",
              "authorization",
              "input-validation",
              "api-security",
              "client-side",
              "secure-communication",
              "data-storage-privacy",
              "supply-chain",
              "out-of-scope",
            ],
          },
          cvssVector: { type: "string" },
          cvssScore: { type: "number" },
          stepsToReproduce: { type: "array", items: { type: "string" } },
          businessImpact: { type: "string" },
          remediation: { type: "string" },
          hypothesisSourceFile: { type: "string" },
          hypothesisReasoning: { type: "string" },
        },
        required: [
          "title",
          "description",
          "affectedComponent",
          "scopeArea",
          "cvssVector",
          "cvssScore",
          "stepsToReproduce",
          "businessImpact",
          "remediation",
        ],
      },
    },
  },
  async execute(args, ctx) {
    const { saveFinding } = await import("../evidence.js");
    try {
      const f = await saveFinding(ctx.runDir, args as unknown as Parameters<typeof saveFinding>[1]);
      return { ok: true, output: `saved finding ${f.id} (${f.severity.level} ${f.severity.score})` };
    } catch (e) {
      return { ok: false, output: String(e) };
    }
  },
};

export const listEndpointsTool: Tool = {
  spec: {
    type: "function",
    function: {
      name: "list_endpoints",
      description: "Return the discovered endpoint inventory for the target (from source scan/OpenAPI).",
      parameters: { type: "object", properties: {} },
    },
  },
  async execute(_args, ctx) {
    try {
      const raw = await fs.readFile(path.join(ctx.runDir, "endpoints.json"), "utf8");
      return { ok: true, output: clip(raw) };
    } catch {
      return { ok: false, output: "no endpoints.json — run `nexus discover` first" };
    }
  },
};

export const defaultTools: Tool[] = [
  searchCodeTool,
  readFileTool,
  httpRequestTool,
  runReproTool,
  saveFindingTool,
  listEndpointsTool,
];
