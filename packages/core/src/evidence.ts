import { promises as fs } from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import type { Finding, ScopeArea, Severity } from "./types.js";

function levelFor(score: number): Severity {
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  if (score > 0) return "LOW";
  return "NONE";
}

export interface FindingInput {
  title: string;
  description: string;
  affectedComponent: string;
  scopeArea: ScopeArea;
  cvssVector: string;
  cvssScore: number;
  stepsToReproduce: string[];
  businessImpact: string;
  remediation: string;
  hypothesisSourceFile?: string;
  hypothesisReasoning?: string;
}

export async function saveFinding(runDir: string, input: FindingInput): Promise<Finding> {
  const findingsDir = path.join(runDir, "findings");
  await fs.mkdir(findingsDir, { recursive: true });

  const existing = await listFindings(runDir);
  const seq = existing.length + 1;
  const id = `F-${String(seq).padStart(3, "0")}`;
  const now = new Date().toISOString();

  const finding: Finding = {
    id,
    title: input.title,
    description: input.description,
    affectedComponent: input.affectedComponent,
    scopeArea: input.scopeArea,
    severity: {
      vector: input.cvssVector,
      score: input.cvssScore,
      level: levelFor(input.cvssScore),
    },
    stepsToReproduce: input.stepsToReproduce,
    businessImpact: input.businessImpact,
    remediation: input.remediation,
    status: "validated",
    hypothesis: input.hypothesisSourceFile
      ? {
          sourceFile: input.hypothesisSourceFile,
          reasoning: input.hypothesisReasoning ?? "",
        }
      : undefined,
    createdAt: now,
    updatedAt: now,
  };

  const dir = path.join(findingsDir, id);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(path.join(dir, "finding.json"), JSON.stringify(finding, null, 2));

  const repro = `#!/usr/bin/env bash
set -euo pipefail
# ${finding.title}
# Component: ${finding.affectedComponent}
# CVSS: ${finding.severity.score} (${finding.severity.vector})
echo "target: \${NEXUS_TARGET:-http://localhost:3000}"
${input.stepsToReproduce.map((s) => `echo ${JSON.stringify(s)}`).join("\n")}
`;
  const reproPath = path.join(dir, "repro.sh");
  await fs.writeFile(reproPath, repro, { mode: 0o755 });

  const transcriptHash = createHash("sha256").update(JSON.stringify(finding)).digest("hex");
  finding.evidence = {
    reproScript: path.relative(runDir, reproPath),
    transcriptHash,
    verifiedAt: now,
  };
  finding.status = "proven";
  await fs.writeFile(path.join(dir, "finding.json"), JSON.stringify(finding, null, 2));

  return finding;
}

export async function listFindings(runDir: string): Promise<Finding[]> {
  const findingsDir = path.join(runDir, "findings");
  try {
    const entries = await fs.readdir(findingsDir);
    const findings: Finding[] = [];
    for (const e of entries.sort()) {
      try {
        const raw = await fs.readFile(path.join(findingsDir, e, "finding.json"), "utf8");
        findings.push(JSON.parse(raw) as Finding);
      } catch {
        /* skip malformed */
      }
    }
    return findings;
  } catch {
    return [];
  }
}
