import { appendFileSync, mkdirSync } from "node:fs";
import path from "node:path";

export type JournalEvent =
  | { type: "run_start"; runId: string; goal: string }
  | { type: "llm_call"; step: number; finishReason: string; toolCalls: number; contentLen: number }
  | { type: "tool_call"; step: number; name: string; args: string }
  | { type: "tool_result"; step: number; name: string; ok: boolean; ms: number; outLen: number }
  | { type: "compaction"; step: number; fromChars: number; toChars: number }
  | { type: "nudge"; step: number; kind: string }
  | { type: "run_end"; step: string; finalLen: number };

/**
 * Append-only journal: one JSON line per event, flushed on every write.
 * Crash-safe audit trail (harness research: journal first — cheapest, highest leverage).
 */
export class Journal {
  private runId = `run-${Date.now().toString(36)}`;

  constructor(private dir: string) {
    mkdirSync(dir, { recursive: true });
    this.log({ type: "run_start", runId: this.runId, goal: "" });
  }

  log(e: JournalEvent): void {
    try {
      appendFileSync(path.join(this.dir, "journal.jsonl"), JSON.stringify({ ts: new Date().toISOString(), ...e }) + "\n");
    } catch {
      /* journal must never kill the run */
    }
  }
}
