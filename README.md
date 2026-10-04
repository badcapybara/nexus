# NEXUS

**Source-guided autonomous security assessment agent** — SIH 26163 · Team FROST

NEXUS reads an application's *own source code* to form falsifiable security hypotheses, validates each with exactly one targeted probe, proves every finding with a re-runnable exploit, and re-tests its own fixes. It ships as a CLI, a set of MCP-style tools, and a presentation web report.

**Live report:** https://badcapybara.github.io/nexus/

---

## How it works

```
Discover → Analyze → Validate → Prove → Remediate → Re-test
   │           │          │         │         │          │
 OpenAPI +   agent      exactly   repro.sh  minimal   patch applied,
 source scan reads     one probe  + SHA-256  unified   exploit must
 → 335 epts  auth code  = evidence transcript  diff     now FAIL
```

1. **Discover** — OpenAPI + source scan yields an endpoint catalogue (335 endpoints for the World Monitor target) annotated with `forceKey` / premium-gate flags.
2. **Analyze** — the agent reads the auth/gateway code first and states a hypothesis tied to a specific file and line. No blind fuzzing.
3. **Validate** — exactly one targeted probe; status codes, headers, and payloads become on-disk evidence.
4. **Prove** — a finding is only confirmed with `repro.sh` + a hashed transcript any evaluator can re-run in one command.
5. **Remediate** — a minimal unified-diff patch is proposed at the root cause.
6. **Re-test** — the patch is applied and the PoC is re-run. NEXUS claims a fix only after the exploit fails.

Every LLM turn, tool call, and validation is journaled to `journal.jsonl` for forensics.

## Safety policy

| Rule | Enforcement |
|---|---|
| Exploits run **only** against a local instance (`localhost`) | Policy Engine rejects otherwise — verified with tests |
| Live target is **read-only** (`GET`/`HEAD`/`OPTIONS`) | Same layer |
| ≤ 20 requests/min against the live target | Same layer |
| Model output can never bypass policy | Policy layer sits below the agent, not in the prompt |

## Repository layout

```
packages/
  core/     policy engine, evidence store, LLM harness (ReAct loop,
            compaction, journal), 6 MCP-style tools, assessment pipeline
  cli/      nexus init | discover | assess | report | serve
  web/      presentation report (static, deployed to GitHub Pages)
nexus-run/  example run: config, 335-endpoint catalogue, audit journal
```

## Quickstart

```bash
npm install
npm run build

# 1. scaffold a run directory
node packages/cli/dist/index.js init nexus-run

# 2. discover endpoints from the target repo (OpenAPI + source scan)
node packages/cli/dist/index.js discover nexus-run --workspace ./target

# 3. run the agent (requires an OpenAI-compatible endpoint, e.g. local Ollama)
export NEXUS_LLM_BASE_URL=http://localhost:11434/v1
export NEXUS_LLM_API_KEY=ollama
export NEXUS_LLM_MODEL=qwen3.5:9b
node packages/cli/dist/index.js assess nexus-run --steps 24

# 4. produce the PS-format report (REPORT.md + coverage matrix)
node packages/cli/dist/index.js report nexus-run

# 5. optional: local dashboard
node packages/cli/dist/index.js serve nexus-run
```

## MCP-style tools

`read_file` · `search_code` · `list_endpoints` · `probe` · `run_repro` · `save_finding`

Argument schemas are validated before execution; oversized output is truncated head+tail with a continuation hint; identical consecutive calls trip a circuit breaker.

## Validation benchmark (seeded mutants)

| Metric | Result |
|---|---|
| Recall on seeded mutants | 5 / 6 |
| Precision | 67 % |
| Time to first finding | 4 m 12 s |
| Repro pass rate | 100 % |
| Held-out real issue #5061 | found |

## Target

- **Repository:** `github.com/koala73/worldmonitor` (AGPL-3.0), pinned at `0d5c618e`
- **Assessment:** 8 problem scopes from the evaluation problem statement (PS)
- **Demo report:** presentation frontend with mock findings, served from GitHub Pages

## Frontend

```bash
npm run build -w @nexus/web   # or: npx vite packages/web
```

Static report — executive summary, expandable findings with evidence transcripts, coverage matrix, pipeline stages. Deployed automatically by GitHub Actions on every push to `main`.
