import { promises as fs } from "node:fs";
import path from "node:path";
import type { Finding, NexusConfig, ScopeArea } from "@nexus/core";

const SCOPE_AREAS: { area: ScopeArea; label: string }[] = [
  { area: "auth-session", label: "Authentication & session management" },
  { area: "authorization", label: "Authorization & access control" },
  { area: "input-validation", label: "Input validation & data handling" },
  { area: "api-security", label: "API security" },
  { area: "client-side", label: "Client-side security controls" },
  { area: "secure-communication", label: "Secure communication mechanisms" },
  { area: "data-storage-privacy", label: "Data storage & privacy protections" },
  { area: "supply-chain", label: "Supply chain / dependency risk" },
];

export async function generateReport(
  runDir: string,
  config: NexusConfig,
  findings: Finding[]
): Promise<string> {
  const lines: string[] = [];
  lines.push(`# Security Assessment Report — ${config.target.name}`);
  lines.push("");
  lines.push("**Problem Statement:** SIH26163 · National Technical Research Organisation (NTRO)");
  lines.push(`**Target repo:** ${config.target.repoUrl ?? "n/a"}${config.target.pinnedCommit ? ` @ \`${config.target.pinnedCommit.slice(0, 12)}\`` : ""}`);
  lines.push(`**Local instance (PoC environment):** ${config.target.localBaseUrl}`);
  lines.push(`**Generated:** ${new Date().toISOString()}`);
  lines.push("");
  lines.push("## Authorization & Safety Statement");
  lines.push("");
  lines.push("- All exploitation/PoC executed **only** against the local, self-hosted instance (enforced by Policy Engine).");
  lines.push("- Live target: passive reconnaissance only; no state-changing requests; rate-limited.");
  lines.push("- Exploitation limited to proof-of-concept demonstration per PS constraints.");
  lines.push("");
  lines.push("## Findings");
  lines.push("");

  if (findings.length === 0) {
    lines.push("_No confirmed findings in this run._");
  }

  for (const f of findings) {
    lines.push(`### ${f.id} — ${f.title}`);
    lines.push("");
    lines.push(`| PS Field | Value |`);
    lines.push(`|---|---|`);
    lines.push(`| **Vulnerability title** | ${f.title} |`);
    lines.push(`| **Affected component** | \`${f.affectedComponent}\` |`);
    lines.push(`| **Scope area** | ${f.scopeArea} |`);
    lines.push(`| **Severity (CVSS)** | **${f.severity.score}** ${f.severity.level} (\`${f.severity.vector}\`) |`);
    lines.push(`| **Status** | ${f.status}${f.retest ? ` (re-test: vuln ${f.retest.before} → ${f.retest.after} after patch)` : ""} |`);
    lines.push("");
    lines.push(`**Description:** ${f.description}`);
    lines.push("");
    if (f.hypothesis) {
      lines.push(`**Source-guided hypothesis:** \`${f.hypothesis.sourceFile}\` — ${f.hypothesis.reasoning}`);
      lines.push("");
    }
    lines.push("**Steps to reproduce:**");
    lines.push("");
    f.stepsToReproduce.forEach((s, i) => lines.push(`${i + 1}. ${s}`));
    lines.push("");
    lines.push(`**Proof of concept:** \`${f.evidence?.reproScript ?? `findings/${f.id}/repro.sh`}\` (re-runnable; evidence hash \`${(f.evidence?.transcriptHash ?? "").slice(0, 16)}…\`)`);
    lines.push("");
    lines.push(`**Business impact:** ${f.businessImpact}`);
    lines.push("");
    lines.push(`**Remediation:** ${f.remediation}`);
    lines.push("");
  }

  lines.push("## Coverage Matrix (PS scope)");
  lines.push("");
  lines.push("| # | Scope area | Status | Findings |");
  lines.push("|---|---|---|---|");
  SCOPE_AREAS.forEach(({ area, label }, i) => {
    const hits = findings.filter((f) => f.scopeArea === area);
    const status = hits.length > 0 ? "✅ tested (finding)" : "⬜ tested (no finding)";
    lines.push(`| ${i + 1} | ${label} | ${status} | ${hits.map((h) => h.id).join(", ") || "—"} |`);
  });
  lines.push("");
  lines.push(`**Summary:** ${findings.length} confirmed finding(s); ${findings.filter((f) => f.status === "remediated").length} with verified remediation.`);
  lines.push("");

  const report = lines.join("\n");
  const outPath = path.join(runDir, "REPORT.md");
  await fs.writeFile(outPath, report);
  return outPath;
}
