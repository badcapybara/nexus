import { LlmClient, type LlmMessage, type LlmToolSpec } from "./llm.js";
import { defaultTools, type Tool, type ToolContext } from "./tools.js";
import { Journal } from "./journal.js";

export interface AgentRunOptions {
  system: string;
  user: string;
  tools?: Tool[];
  maxSteps?: number;
  /** Force tool_choice=required for at least this many turns */
  minToolSteps?: number;
  /** Soft context budget in chars (~chars/4 = tokens); older tool output is trimmed to fit */
  contextBudgetChars?: number;
  toolTimeoutMs?: number;
  llm?: LlmClient;
  ctx: ToolContext;
  onEvent?: (event: AgentEvent) => void;
}

export type AgentEvent =
  | { type: "thought"; content: string }
  | { type: "tool_call"; name: string; args: string }
  | { type: "tool_result"; name: string; ok: boolean; output: string }
  | { type: "nudge"; kind: string }
  | { type: "compaction"; fromChars: number; toChars: number }
  | { type: "done"; final: string; steps: number };

export interface AgentRunResult {
  final: string;
  steps: number;
  transcript: LlmMessage[];
}

function estChars(transcript: LlmMessage[]): number {
  return transcript.reduce((n, m) => n + (m.content?.length ?? 0) + JSON.stringify(m.tool_calls ?? []).length, 0);
}

/**
 * Pairing-safe soft compaction: never removes messages (keeps tool_call/result pairs intact),
 * instead head+tail-trims older tool outputs and stale assistant text. The model is told the
 * output was pruned and can re-run the tool if it needs the detail again.
 */
function compact(transcript: LlmMessage[], budgetChars: number): { from: number; to: number } | null {
  const from = estChars(transcript);
  if (from <= budgetChars) return null;

  // Protect: system[0], goal[1], and the last 6 messages stay full.
  const keepTail = 6;
  for (let i = transcript.length - keepTail - 1; i >= 2; i--) {
    const m = transcript[i];
    if (!m) continue;
    if (estChars(transcript) <= budgetChars) break;
    if (m.role === "tool" && m.content && m.content.length > 1200) {
      const head = m.content.slice(0, 600);
      const tail = m.content.slice(-250);
      m.content = `${head}\n…[harness pruned middle of this observation (${m.content.length} chars) — re-run the tool with narrower parameters if you need it again]…\n${tail}`;
    } else if (m.role === "assistant" && !m.tool_calls && m.content && m.content.length > 800) {
      m.content = m.content.slice(0, 500) + "…[pruned stale analysis]";
    }
  }
  return { from, to: estChars(transcript) };
}

/** Minimal required-field validation against the tool's declared JSON schema */
function validateArgs(spec: LlmToolSpec, args: Record<string, unknown>): string | null {
  const required = (spec.function.parameters as { required?: string[] }).required ?? [];
  const missing = required.filter((k) => args[k] === undefined || args[k] === "");
  if (missing.length) {
    return `INVALID ARGUMENTS for ${spec.function.name}: missing required field(s) ${missing.join(", ")}. Fix the arguments and call again.`;
  }
  return null;
}

const TOOL_TIMEOUT_DEFAULT_MS = 30_000;

export async function runAgent(opts: AgentRunOptions): Promise<AgentRunResult> {
  const llm = opts.llm ?? new LlmClient();
  const tools = opts.tools ?? defaultTools;
  const maxSteps = opts.maxSteps ?? 20;
  const minToolSteps = opts.minToolSteps ?? 0;
  const budget = opts.contextBudgetChars ?? 40_000;
  const toolTimeout = opts.toolTimeoutMs ?? TOOL_TIMEOUT_DEFAULT_MS;
  const specs: LlmToolSpec[] = tools.map((t) => t.spec);
  const byName = new Map(tools.map((t) => [t.spec.function.name, t]));
  const journal = new Journal(opts.ctx.runDir);

  const transcript: LlmMessage[] = [
    { role: "system", content: opts.system },
    { role: "user", content: opts.user },
  ];

  const callCounts = new Map<string, number>();

  for (let step = 0; step < maxSteps; step++) {
    // context pressure → soft-trim before the call (never breaks pairs)
    const trimmed = compact(transcript, budget);
    if (trimmed) {
      opts.onEvent?.({ type: "compaction", fromChars: trimmed.from, toChars: trimmed.to });
      journal.log({ type: "compaction", step, fromChars: trimmed.from, toChars: trimmed.to });
    }

    const res = await llm.chat(transcript, specs.length ? specs : undefined, {
      toolChoice: step < minToolSteps ? "required" : "auto",
      maxTokens: 4096,
    });
    journal.log({
      type: "llm_call",
      step,
      finishReason: res.finishReason,
      toolCalls: res.toolCalls.length,
      contentLen: res.content.length,
    });

    if (res.toolCalls.length === 0) {
      const truncated = res.finishReason === "length";
      const tooEarly = step < minToolSteps;
      if ((truncated || tooEarly) && step + 1 < maxSteps) {
        const kind = truncated ? "truncated" : "early-stop";
        transcript.push({ role: "assistant", content: res.content });
        transcript.push({
          role: "user",
          content: truncated
            ? "Your response was truncated before you called a tool. Continue — call the next tool now."
            : "Continue the investigation. Call a tool now (search_code / read_file / http_request / run_repro / save_finding). Do not summarize or stop — your mission is not complete.",
        });
        opts.onEvent?.({ type: "nudge", kind });
        journal.log({ type: "nudge", step, kind });
        continue;
      }
      opts.onEvent?.({ type: "done", final: res.content, steps: step + 1 });
      journal.log({ type: "run_end", step: "final", finalLen: res.content.length });
      return { final: res.content, steps: step + 1, transcript };
    }

    transcript.push({ role: "assistant", content: res.content, tool_calls: res.toolCalls });

    for (const call of res.toolCalls) {
      let output: string;
      let ok = false;
      const name = call.function.name;
      const t0 = Date.now();
      opts.onEvent?.({ type: "tool_call", name, args: call.function.arguments });
      journal.log({ type: "tool_call", step, name, args: call.function.arguments.slice(0, 2000) });

      const tool = byName.get(name);
      if (!tool) {
        output = `Error: tool '${name}' not registered. Available: ${[...byName.keys()].join(", ")}`;
      } else {
        let args: Record<string, unknown> = {};
        let argsErr: string | null = null;
        try {
          args = JSON.parse(call.function.arguments || "{}");
          argsErr = validateArgs(tool.spec, args);
        } catch {
          argsErr = "INVALID JSON arguments — parse failed. Fix the JSON and call again.";
        }
        if (argsErr) {
          output = argsErr;
        } else {
          // circuit breaker: identical repeated call
          const key = `${name}:${call.function.arguments}`;
          const count = (callCounts.get(key) ?? 0) + 1;
          callCounts.set(key, count);
          if (count >= 2) {
            output =
              `DUPLICATE CALL (attempt ${count}) — you already have this result earlier in the transcript. Do not repeat identical calls; act on what you have or change parameters.`;
          } else {
            try {
              const exec = tool.execute(args, opts.ctx);
              const result = await Promise.race([
                exec,
                new Promise<{ ok: boolean; output: string }>((resolve) =>
                  setTimeout(() => resolve({ ok: false, output: `Error: tool '${name}' timed out after ${toolTimeout}ms` }), toolTimeout)
                ),
              ]);
              ok = result.ok;
              output = result.output;
            } catch (e) {
              output = `tool error (observation, not fatal): ${String(e)}`;
            }
          }
        }
      }
      const ms = Date.now() - t0;
      opts.onEvent?.({ type: "tool_result", name, ok, output });
      journal.log({ type: "tool_result", step, name, ok, ms, outLen: output.length });
      transcript.push({ role: "tool", tool_call_id: call.id, content: output });
    }
  }

  const final = "(max steps reached)";
  opts.onEvent?.({ type: "done", final, steps: maxSteps });
  journal.log({ type: "run_end", step: "max-steps", finalLen: 0 });
  return { final, steps: maxSteps, transcript };
}
