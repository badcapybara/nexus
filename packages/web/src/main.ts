import "./style.css";
import { RUN, STATS, BENCHMARK, FINDINGS, COVERAGE, PIPELINE, type MockFinding } from "./data";

const esc = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

function findingCard(f: MockFinding): string {
  const sevClass = f.severity.level.toLowerCase();
  const retest = f.retest
    ? `<div class="retest">
         <span class="tag">Retest</span>
         <span class="before">before · ${esc(f.retest.before)}</span>
         <span class="arrow">→</span>
         <span class="after">after · ${esc(f.retest.after)}</span>
       </div>`
    : "";
  return `
  <article class="finding" data-id="${f.id}">
    <div class="finding-head">
      <span class="fid">${f.id}</span>
      <div>
        <div class="ftitle">${esc(f.title)}</div>
        <div class="fmeta"><code>${esc(f.component)}</code> · ${esc(f.scope)}</div>
      </div>
      <div class="fright">
        <span class="sev ${sevClass}">${f.severity.level}</span>
        <span class="score">${f.severity.score.toFixed(1)}</span>
        <span class="status ${f.status}">${f.status}</span>
        <span class="chev">▸</span>
      </div>
    </div>
    <div class="finding-body">
      <p style="color:var(--ink-2);font-size:14px">${esc(f.summary)}</p>

      <div class="block hypo">
        <div class="label" style="margin-bottom:2px">Hypothesis</div>
        <code>${esc(f.hypothesis.file)}</code>
        <p>${esc(f.hypothesis.reasoning)}</p>
      </div>

      <div class="grid2">
        <div class="block">
          <div class="label">Reproduction steps</div>
          <ol class="steps">${f.steps.map((s) => `<li>${esc(s)}</li>`).join("")}</ol>
        </div>
        <div class="block">
          <div class="label">Evidence</div>
          <div class="evidence">
            <div class="evidence-head">
              <span class="cmd">${esc(f.evidence.repro)}</span>
              <span>${esc(f.severity.vector.split("/")[0])}</span>
            </div>
            <pre>${esc(f.evidence.transcript)}</pre>
          </div>
        </div>
      </div>

      <div class="grid2">
        <div class="block">
          <div class="label">Business impact</div>
          <p>${esc(f.impact)}</p>
        </div>
        <div class="block">
          <div class="label">Remediation</div>
          <p>${esc(f.remediation)}</p>
        </div>
      </div>
      ${retest}
    </div>
  </article>`;
}

function render(): string {
  const stats = STATS.map(
    (s) => `<div class="stat"><div class="v num">${s.value}</div><div class="l">${s.label}</div></div>`
  ).join("");

  const benchRows = BENCHMARK.map(
    (b) => `<tr><td>${esc(b.metric)}</td><td class="num" style="text-align:right;font-weight:600">${esc(b.value)}</td></tr>`
  ).join("");

  const covRows = COVERAGE.map((c) => {
    const chips = c.findings.length
      ? c.findings.map((f) => `<span class="chip">${f}</span>`).join("")
      : `<span class="chip empty">—</span>`;
    const label = c.findings.length ? "finding raised" : "tested · clean";
    const dot = c.findings.length ? "find-dot" : "ok-dot";
    return `<tr>
      <td>${esc(c.area)}</td>
      <td><span class="cov-status"><span class="${dot}"></span>${label}</span></td>
      <td><div class="chips">${chips}</div></td>
    </tr>`;
  }).join("");

  const stages = PIPELINE.map(
    (p) => `<div class="stage"><div class="n">${p.n}</div><div class="s">${esc(p.name)}</div><div class="d">${esc(p.desc)}</div></div>`
  ).join("");

  const findings = FINDINGS.map(findingCard).join("");

  return `
  <header class="masthead">
    <div class="masthead-inner">
      <div class="brandrow">
        <div>
          <div class="wordmark">NEX<span>US</span></div>
          <div class="brand-sub">Autonomous security assessment · ${esc(RUN.target)} · ${esc(RUN.ps)}</div>
        </div>
        <div class="run-meta">
          <span>repo <b>${esc(RUN.repo)}</b></span>
          <span>commit <b>${RUN.commit}</b></span>
          <span>run <b>${RUN.date}</b></span>
          <span>model <b>${esc(RUN.model)}</b></span>
        </div>
      </div>
      <div class="policy-chip">${esc(RUN.policy)}</div>
      <nav class="tabs">
        <button class="tab active" data-tab="overview">Overview</button>
        <button class="tab" data-tab="findings">Findings</button>
        <button class="tab" data-tab="coverage">Coverage</button>
        <button class="tab" data-tab="pipeline">Pipeline</button>
      </nav>
    </div>
  </header>

  <main>
    <section id="overview">
      <div class="eyebrow">Executive summary</div>
      <h2>Source-guided assessment, proven with re-tests</h2>
      <p class="lede">
        NEXUS reads the target's own source to form hypotheses, validates each with a single
        targeted probe, and proves remediations by re-running the exploit against the patch.
        Four findings were confirmed from 335 discovered endpoints; one has a verified fix.
      </p>
      <div class="stats">${stats}</div>
      <div class="cols">
        <div class="panel">
          <h3>Validation benchmark</h3>
          <table class="data">
            <thead><tr><th>Metric</th><th style="text-align:right">Result</th></tr></thead>
            <tbody>${benchRows}</tbody>
          </table>
        </div>
        <div class="panel">
          <h3>Run parameters</h3>
          <table class="data">
            <tbody>
              <tr><td style="color:var(--muted)">Target commit</td><td style="text-align:right;font-family:var(--mono)">${RUN.commit}</td></tr>
              <tr><td style="color:var(--muted)">Endpoints discovered</td><td class="num" style="text-align:right;font-weight:600">335</td></tr>
              <tr><td style="color:var(--muted)">Assessment classes</td><td class="num" style="text-align:right;font-weight:600">8</td></tr>
              <tr><td style="color:var(--muted)">Exploit policy</td><td style="text-align:right">localhost PoC only</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <section id="findings" hidden>
      <div class="eyebrow">Confirmed findings</div>
      <h2>Four issues, each with a reproducible proof</h2>
      <p class="lede">Select a row to expand the hypothesis, evidence transcript, and re-test result.</p>
      ${findings}
    </section>

    <section id="coverage" hidden>
      <div class="eyebrow">Assessment coverage</div>
      <h2>Eight problem scopes, mapped to evidence</h2>
      <p class="lede">Every scope was exercised; scopes with a raised finding link directly to it.</p>
      <div class="panel">
        <table class="data">
          <thead><tr><th>Scope</th><th>Status</th><th>Findings</th></tr></thead>
          <tbody>${covRows}</tbody>
        </table>
      </div>
    </section>

    <section id="pipeline" hidden>
      <div class="eyebrow">Agent pipeline</div>
      <h2>Six stages, one verified loop</h2>
      <p class="lede">The agent does not claim a fix until the re-test stage shows the exploit failing.</p>
      <div class="pipeline">${stages}</div>
      <div class="panel">
        <h3>Why this design holds up</h3>
        <table class="data">
          <tbody>
            <tr><td style="width:200px;color:var(--muted)">Hypothesis before probe</td><td>Every network call is justified by a specific source location — no blind fuzzing.</td></tr>
            <tr><td style="color:var(--muted)">Evidence on disk</td><td>Findings ship as <code>repro.sh</code> + SHA-256 transcript; evaluators re-run in one command.</td></tr>
            <tr><td style="color:var(--muted)">Policy gate</td><td>Exploits are structurally blocked outside localhost; live target stays read-only.</td></tr>
            <tr><td style="color:var(--muted)">Audit journal</td><td>Every LLM turn, tool call, and validation is logged to JSONL for forensics.</td></tr>
          </tbody>
        </table>
      </div>
    </section>
  </main>

  <footer>
    <div class="footer-inner">
      <span>NEXUS · ${esc(RUN.ps)} · demo data for presentation</span>
      <span>${esc(RUN.policy)}</span>
    </div>
  </footer>`;
}

const app = document.getElementById("app");
if (app) app.innerHTML = render();

document.querySelectorAll<HTMLButtonElement>(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    document.querySelectorAll<HTMLElement>("main section").forEach((s) => (s.hidden = true));
    const target = document.getElementById(btn.dataset.tab!);
    if (target) target.hidden = false;
    window.scrollTo({ top: 0, behavior: "smooth" });
  });
});

document.querySelectorAll<HTMLElement>(".finding-head").forEach((head) => {
  head.addEventListener("click", () => head.closest(".finding")?.classList.toggle("open"));
});

// Open the first finding by default when the Findings tab is shown first time.
let openedOnce = false;
document.querySelector('[data-tab="findings"]')?.addEventListener("click", () => {
  if (!openedOnce) {
    document.querySelector(".finding")?.classList.add("open");
    openedOnce = true;
  }
});
