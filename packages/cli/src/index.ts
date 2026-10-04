#!/usr/bin/env node
import { Command } from "commander";
import { promises as fs } from "node:fs";
import path from "node:path";
import {
  discover,
  assess,
  runPipeline,
  listFindings,
  LlmClient,
  type NexusConfig,
  type Stage,
} from "@nexus/core";
import { generateReport } from "./report.js";
import { serveDashboard } from "./serve.js";

const program = new Command();
program.name("nexus").description("NEXUS — source-guided autonomous security assessment (SIH26163)").version("0.1.0");

async function loadConfig(runDir: string): Promise<NexusConfig> {
  const raw = await fs.readFile(path.join(runDir, "nexus.config.json"), "utf8");
  return JSON.parse(raw) as NexusConfig;
}

function logEvent(stage: Stage, event: { type: string; name?: string; args?: string; ok?: boolean; output?: string; final?: string; steps?: number }) {
  const tag = `[${stage}]`;
  if (event.type === "tool_call") {
    console.log(`${tag} → ${event.name} ${(event.args ?? "").slice(0, 140)}`);
  } else if (event.type === "tool_result") {
    console.log(`${tag} ← ${event.name} ${event.ok ? "ok" : "ERR"} ${(event.output ?? "").slice(0, 100).replace(/\n/g, " ")}`);
  } else if (event.type === "done") {
    console.log(`${tag} done (${event.steps} steps)`);
  }
}

program
  .command("init")
  .argument("<runDir>", "directory to initialize (will hold config, endpoints, findings)")
  .option("--local <url>", "local instance base URL", "http://localhost:3000")
  .option("--live <url>", "live target base URL")
  .option("--repo <url>", "target repository URL")
  .option("--commit <sha>", "pinned commit")
  .option("--workspace <path>", "path to cloned target source")
  .description("Initialize a NEXUS assessment run")
  .action(async (runDir: string, opts) => {
    const abs = path.resolve(runDir);
    await fs.mkdir(abs, { recursive: true });
    const config: NexusConfig = {
      target: {
        name: "World Monitor",
        repoUrl: opts.repo ?? "https://github.com/koala73/worldmonitor",
        pinnedCommit: opts.commit,
        localBaseUrl: opts.local,
        liveBaseUrl: opts.live,
      },
      policy: {
        allowLiveWrites: false,
        maxLiveRequestsPerMinute: 20,
        requireLocalForExploits: true,
      },
    };
    await fs.writeFile(path.join(abs, "nexus.config.json"), JSON.stringify(config, null, 2));
    console.log(`initialized ${abs}`);
    console.log(`  local (exploit OK): ${config.target.localBaseUrl}`);
    console.log(`  live (read-only):   ${config.target.liveBaseUrl ?? "(not set)"}`);
  });

program
  .command("discover")
  .argument("<runDir>")
  .description("Stage 1: static endpoint inventory from target source")
  .action(async (runDir: string) => {
    const abs = path.resolve(runDir);
    const config = await loadConfig(abs);
    const workspace = path.resolve(process.env.NEXUS_WORKSPACE ?? "./target");
    const endpoints = await discover({ config, runDir: abs, workspace });
    console.log(`discovered ${endpoints.length} endpoints → ${path.join(abs, "endpoints.json")}`);
    for (const e of endpoints.slice(0, 30)) {
      console.log(`  ${e.method.padEnd(6)} ${e.path}${e.forceKey ? " [forceKey]" : ""}${e.premiumGated ? " [premiumGated]" : ""}`);
    }
  });

program
  .command("assess")
  .argument("<runDir>")
  .option("--steps <n>", "max agent steps", "30")
  .description("Stages 2–6: AI agent analyzes source, validates, proves, remediates, re-tests")
  .action(async (runDir: string, opts) => {
    const abs = path.resolve(runDir);
    const config = await loadConfig(abs);
    const workspace = path.resolve(process.env.NEXUS_WORKSPACE ?? "./target");

    await fs.mkdir(abs, { recursive: true });
    console.log(`NEXUS assess — target=${config.target.name} workspace=${workspace}`);
    console.log(`policy: exploits → ${config.target.localBaseUrl} only, live read-only ${config.policy.maxLiveRequestsPerMinute}/min\n`);

    const result = await runPipeline({
      config,
      runDir: abs,
      workspace,
      llm: new LlmClient(),
      maxStepsPerStage: Number(opts.steps),
      onEvent: logEvent,
    });

    console.log(`\n=== ${result.findings.length} finding(s) ===`);
    for (const f of result.findings) {
      console.log(`  ${f.id} [${f.severity.level} ${f.severity.score}] ${f.title}`);
      console.log(`        component: ${f.affectedComponent} | status: ${f.status}${f.retest ? ` | retest ${f.retest.before}→${f.retest.after}` : ""}`);
    }
  });

program
  .command("report")
  .argument("<runDir>")
  .description("Generate SIH26163-format markdown report (8 fields per finding + coverage matrix)")
  .action(async (runDir: string) => {
    const abs = path.resolve(runDir);
    const config = await loadConfig(abs);
    const findings = await listFindings(abs);
    const out = await generateReport(abs, config, findings);
    console.log(out);
  });

program
  .command("serve")
  .argument("<runDir>")
  .option("-p, --port <port>", "port", "8787")
  .description("Serve the web dashboard (findings, evidence, coverage)")
  .action(async (runDir: string, opts) => {
    const abs = path.resolve(runDir);
    await serveDashboard(abs, Number(opts.port));
  });

program.parseAsync().catch((e) => {
  console.error(e);
  process.exit(1);
});
