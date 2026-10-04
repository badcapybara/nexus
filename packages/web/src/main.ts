import "./style.css";
import {
  RUN, STATS, BENCHMARK, FINDINGS, COVERAGE, PIPELINE,
  HERO, SEVERITY, PILLARS, ARCHITECTURE, TIMELINE, STACK, PS_ALIGNMENT,
  type MockFinding,
} from "./data";

const esc = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

function severityChart(): string {
  const total = SEVERITY.reduce((a, s) => a + s.count, 0) || 1;
  const rows = SEVERITY.map((s) => {
    const pct = Math.round((s.count / total) * 100);
    return `
      <div class="sev-row">
        <span class="sev-name">${s.level}</span>
        <div class="sev-track"><div class="sev-fill" style="width:${s.count ? Math.max(pct, 8) : 0}%;background:${s.color}"></div></div>
        <span class="sev-count num">${s.count}</span>
      </div>`;
  }).join("");
  const angles = (() => {
    let acc = 0;
    return SEVERITY.filter((s) => s.count > 0)
      .map((s) => {
        const from = acc;
        acc += (s.count / total) * 360;
        return `${s.color} ${from}deg ${acc}deg`;
      })
      .join(", ");
  })();
  return `
    <div class="sev-chart">
      <div class="donut" style="background:conic-gradient(${angles})">
        <div class="donut-hole"><span class="donut-n num">${total}</span><span class="donut-l">findings</span></div>
      </div>
      <div class="sev-rows">${rows}</div>
    </div>`;
}

function benchBars(): string {
  const bars: Record<string, number> = {
    "Recall (seeded mutants)": (5 / 6) * 100,
    Precision: 67,
    "Time to first finding": 85,
    "Held-out test · issue #5061": 100,
  };
  const rows = BENCHMARK.map(
    (b) => `
    <div class="bench-row">
      <div class="bench-label">${esc(b.metric)}</div>
      <div class="bench-track"><div class="bench-fill" style="width:${bars[b.metric] ?? 70}%"></div></div>
      <div class="bench-value num">${esc(b.value)}</div>
    </div>`
  ).join("");
  return `<div class="bench">${rows}</div>`;
}

function coverageDonut(): string {
  const withFindings = COVERAGE.filter((c) => c.findings.length).length;
  const total = COVERAGE.length;
  const deg = (withFindings / total) * 360;
  return `
    <div class="cov-donut-wrap">
      <div class="donut" style="background:conic-gradient(var(--navy) 0deg ${deg}deg, #e8e5dd ${deg}deg 360deg)">
        <div class="donut-hole">
          <span class="donut-n num">${withFindings}/${total}</span>
          <span class="donut-l">scopes raised findings</span>
        </div>
      </div>
    </div>`;
}

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

  const pillars = PILLARS.map(
    (p) => `<div class="pillar"><div class="pillar-n">${p.n}</div><div class="pillar-t">${esc(p.t)}</div><div class="pillar-d">${esc(p.d)}</div></div>`
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

  const psRows = PS_ALIGNMENT.map(
    (p) => `<tr><td style="color:var(--muted);width:38%">${esc(p.ps)}</td><td><b>${esc(p.nx)}</b></td></tr>`
  ).join("");

  const stages = PIPELINE.map(
    (p) => `<div class="stage"><div class="n">${p.n}</div><div class="s">${esc(p.name)}</div><div class="d">${esc(p.desc)}</div></div>`
  ).join("");

  const arch = ARCHITECTURE.map(
    (a, i) => `
      <div class="arch-node ${a.k}">
        ${i > 0 ? '<span class="arch-arrow">→</span>' : ""}
        <div class="arch-t">${esc(a.t)}</div>
        <div class="arch-s">${esc(a.s)}</div>
      </div>`
  ).join("");

  const timeline = TIMELINE.map(
    (t) => `
      <div class="tl-row">
        <span class="tl-t num">${t.t}</span>
        <span class="tl-dot ${t.k}"></span>
        <span class="tl-e">${esc(t.e)}</span>
      </div>`
  ).join("");

  const stack = STACK.map((s) => `<span class="stack-chip">${esc(s)}</span>`).join("");
  const findings = FINDINGS.map(findingCard).join("");
  const critHigh = FINDINGS.filter((f) => f.severity.score >= 7).length;

  return `
  <header class="masthead">
    <div class="masthead-inner">
      <div class="brandrow">
        <div>
          <div class="wordmark">NEX<span>US</span></div>
          <div class="brand-sub">Autonomous security assessment · ${esc(RUN.target)}</div>
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
      <div class="hero">
        <div class="eyebrow">${esc(HERO.kicker)}</div>
        <h1 class="hero-title">${esc(HERO.title)}<br><em>${esc(HERO.titleEm)}</em></h1>
        <p class="hero-body">${esc(HERO.body)}</p>
      </div>

      <div class="stats stats6">${stats}</div>

      <div class="cols">
        <div class="panel">
          <h3>Findings by severity</h3>
          ${severityChart()}
        </div>
        <div class="panel">
          <h3>Validation benchmark</h3>
          ${benchBars()}
          <p class="fine">Seeded-mutant recall, precision on confirmed findings, held-out real issue #5061.</p>
        </div>
      </div>

      <div class="pillars">${pillars}</div>

      <div class="stack-strip">${stack}</div>
    </section>

    <section id="findings" hidden>
      <div class="eyebrow">Confirmed findings</div>
      <h2>Four issues, each with a reproducible proof</h2>
      <p class="lede">Select a row to expand the hypothesis, evidence transcript, and re-test result.
        <b>${critHigh} of ${FINDINGS.length}</b> rate high or above.</p>
      ${findings}
    </section>

    <section id="coverage" hidden>
      <div class="eyebrow">Assessment coverage</div>
      <h2>Eight problem scopes, mapped to evidence</h2>
      <p class="lede">Every scope from the evaluation problem statement was exercised; scopes with a raised finding link directly to it.</p>
      <div class="cols">
        <div class="panel">
          <table class="data">
            <thead><tr><th>Scope</th><th>Status</th><th>Findings</th></tr></thead>
            <tbody>${covRows}</tbody>
          </table>
        </div>
        <div class="panel">
          <h3>Scope coverage</h3>
          ${coverageDonut()}
          <h3 style="margin-top:22px">Problem-statement alignment</h3>
          <table class="data">
            <tbody>${psRows}</tbody>
          </table>
        </div>
      </div>
    </section>

    <section id="pipeline" hidden>
      <div class="eyebrow">Agent pipeline</div>
      <h2>Six stages, one verified loop</h2>
      <p class="lede">The agent does not claim a fix until the re-test stage shows the exploit failing.</p>
      <div class="pipeline">${stages}</div>

      <div class="cols">
        <div class="panel">
          <h3>Run timeline <span class="fine-inline">extract from audit journal</span></h3>
          <div class="timeline">${timeline}</div>
        </div>
        <div class="panel">
          <h3>Architecture</h3>
          <div class="arch">${arch}</div>
        </div>
      </div>

      <div class="panel" style="margin-top:26px">
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
      <span>NEXUS · Team FROST · ${esc(RUN.ps)} · demo data for presentation</span>
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
    if (target) {
      target.hidden = false;
      target.classList.add("enter");
      setTimeout(() => target.classList.remove("enter"), 400);
    }
    window.scrollTo({ top: 0, behavior: "smooth" });
  });
});

document.querySelectorAll<HTMLElement>(".finding-head").forEach((head) => {
  head.addEventListener("click", () => head.closest(".finding")?.classList.toggle("open"));
});

let openedOnce = false;
document.querySelector('[data-tab="findings"]')?.addEventListener("click", () => {
  if (!openedOnce) {
    document.querySelector(".finding")?.classList.add("open");
    openedOnce = true;
  }
});
