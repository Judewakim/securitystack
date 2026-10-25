// SecurityStack free scan: front end.
// All data from the API is written with textContent (never innerHTML), and every
// link we receive is checked against the AWS console origin before it is used.

const API = "/api/scans";
const POLL_MS = 3000;
const POLL_LIMIT_MS = 12 * 60 * 1000;
const ARN_RE = /^arn:aws:iam::\d{12}:role\/SecurityStackScanRole-[a-z0-9]{8}$/;
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SEV_LABEL = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low" };
const GRADE_HEADLINE = {
  A: "Well protected. A few things to tidy up.",
  B: "Mostly solid, with some gaps worth closing.",
  C: "Real gaps that an attacker or auditor would find.",
  D: "Exposed in several ways that matter.",
  F: "Seriously exposed. Start with the critical items today.",
};

const $ = (id) => document.getElementById(id);
const state = { scanId: null, result: null, demo: false };

// ---------------------------------------------------------------- utilities

function store(key, value) {
  try {
    if (value === null) sessionStorage.removeItem(key);
    else sessionStorage.setItem(key, value);
  } catch { /* storage can be unavailable (private mode); the flow still works */ }
}
function recall(key) {
  try { return sessionStorage.getItem(key); } catch { return null; }
}

function safeConsoleUrl(url) {
  try {
    const u = new URL(url);
    return u.protocol === "https:" && /(^|\.)console\.aws\.amazon\.com$/.test(u.hostname) ? u.href : null;
  } catch { return null; }
}

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) if (c) node.append(c);
  return node;
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
  });
  let body = {};
  try { body = await res.json(); } catch { /* non-JSON error page */ }
  if (!res.ok) throw new Error(body.error || `The service returned ${res.status}. Try again in a minute.`);
  return body;
}

function show(view) {
  for (const v of ["landing", "wizard", "results"]) $(`view-${v}`).hidden = v !== view;
  window.scrollTo({ top: 0 });
  const heading = $(`view-${view}`).querySelector("h1");
  if (heading) { heading.setAttribute("tabindex", "-1"); heading.focus({ preventScroll: true }); }
}

function setStep(id, { enabled, done }) {
  const step = $(id);
  if (enabled !== undefined) step.setAttribute("aria-disabled", String(!enabled));
  if (done !== undefined) step.classList.toggle("done", done);
}

// ------------------------------------------------------------------- wizard

function resetWizard() {
  state.scanId = null;
  store("scanId", null);
  $("role-hint").hidden = true;
  $("role-arn").value = "";
  $("role-arn").disabled = true;
  $("scan-btn").disabled = true;
  $("session-btn").disabled = false;
  $("arn-error").hidden = true;
  $("run-status").textContent = "Waiting for the role.";
  $("progress").hidden = true;
  setStep("step-role", { enabled: true, done: false });
  setStep("step-arn", { enabled: false, done: false });
  setStep("step-run", { enabled: false, done: false });
}

async function createSession() {
  const btn = $("session-btn");
  btn.disabled = true;
  btn.textContent = "Preparing…";
  // Open the tab synchronously (inside the click) so pop-up blockers allow it.
  const tab = window.open("about:blank", "_blank");
  try {
    const s = await api(API, { method: "POST", body: JSON.stringify({ homeRegion: $("region").value }) });
    const url = safeConsoleUrl(s.roleLaunchUrl);
    if (!url) throw new Error("Received an unexpected link. Please try again.");
    state.scanId = s.scanId;
    store("scanId", s.scanId);
    if (tab) { tab.opener = null; tab.location.href = url; }
    $("role-link").href = url;
    $("role-hint").hidden = false;
    setStep("step-role", { done: true });
    setStep("step-arn", { enabled: true });
    $("role-arn").disabled = false;
    $("scan-btn").disabled = false;
    $("role-arn").focus();
    btn.textContent = "Open AWS again";
  } catch (err) {
    if (tab) tab.close();
    btn.textContent = "Open AWS to create the role";
    showArnError(err.message, "step-role");
  } finally {
    btn.disabled = false;
  }
}

function showArnError(message) {
  const e = $("arn-error");
  e.textContent = message;
  e.hidden = false;
}

async function startScan(event) {
  event.preventDefault();
  $("arn-error").hidden = true;
  const roleArn = $("role-arn").value.trim();
  if (!ARN_RE.test(roleArn)) {
    showArnError("That isn't the RoleArn output. It should look like arn:aws:iam::123456789012:role/SecurityStackScanRole-1a2b3c4d.");
    return;
  }
  $("scan-btn").disabled = true;
  try {
    await api(`${API}/${encodeURIComponent(state.scanId)}/start`, { method: "POST", body: JSON.stringify({ roleArn }) });
    setStep("step-arn", { done: true });
    setStep("step-run", { enabled: true });
    $("progress").hidden = false;
    poll(Date.now());
  } catch (err) {
    showArnError(err.message);
    $("scan-btn").disabled = false;
  }
}

const STATUS_TEXT = {
  QUEUED: "Starting the scan…",
  RUNNING: "Checking every region you use. This usually takes one to three minutes.",
};

async function poll(startedAt) {
  if (Date.now() - startedAt > POLL_LIMIT_MS) {
    $("run-status").textContent = "This is taking longer than expected. Refresh the page in a few minutes to check again.";
    $("progress").hidden = true;
    return;
  }
  try {
    const s = await api(`${API}/${encodeURIComponent(state.scanId)}`);
    if (s.status === "DONE") {
      setStep("step-run", { done: true });
      renderResults(s.result, false);
      return;
    }
    if (s.status === "FAILED") {
      $("progress").hidden = true;
      $("run-status").textContent = "The scan didn't run.";
      showArnError(s.error || "The scan failed. Check the RoleArn and try again.");
      $("scan-btn").disabled = false;
      return;
    }
    $("run-status").textContent = STATUS_TEXT[s.status] || "Working…";
  } catch (err) {
    $("run-status").textContent = err.message;
  }
  setTimeout(() => poll(startedAt), POLL_MS);
}

// ------------------------------------------------------------------ results

function renderCheck(c) {
  // "Security Hub is off" + 3 findings means "off in 3 regions", not "3 found".
  const perRegion = c.findings?.length && c.findings.every((f) => f.region !== "global" && f.resource.endsWith(`(${f.region})`));
  const count = !c.findingCount ? "" : perRegion
    ? `${c.findingCount} ${c.findingCount === 1 ? "region" : "regions"}`
    : `${c.findingCount} found`;
  const summary = el("summary", {},
    el("span", { class: `sev ${c.severity}`, text: SEV_LABEL[c.severity] }),
    el("span", { class: "title", text: c.title }),
    el("span", { class: "n", text: c.status === "UNKNOWN" ? "Not checked" : count }),
  );
  const body = el("div", { class: "body" },
    el("h3", { text: "Why it matters" }), el("p", { text: c.why }),
    el("h3", { text: "How to fix it" }), el("p", { text: c.fix }),
  );
  if (c.fixedBySecurityStack) body.append(el("span", { class: "tag", text: "SecurityStack fixes this" }));
  if (c.status === "UNKNOWN" && c.note) {
    body.append(el("h3", { text: "Why it wasn't checked" }), el("p", { text: c.note }));
  }
  if (c.findings && c.findings.length) {
    body.append(el("h3", { text: "Where" }));
    const list = el("ul", { class: "resources" });
    for (const f of c.findings) {
      const li = el("li", {}, el("code", { text: f.resource }));
      const extra = [f.region !== "global" ? f.region : "", f.detail].filter(Boolean).join(". ");
      if (extra) li.append(document.createTextNode(` ${extra}`));
      list.append(li);
    }
    if (c.findingCount > c.findings.length) list.append(el("li", { text: `…and ${c.findingCount - c.findings.length} more` }));
    body.append(list);
  }
  return el("details", { class: "check" }, summary, body);
}

function renderResults(r, demo) {
  state.result = r;
  state.demo = demo;
  $("demo-banner").hidden = !demo;
  $("r-cleanup").hidden = demo;

  const stamp = $("r-stamp");
  stamp.className = `stamp grade-${r.grade}`;
  $("r-grade").textContent = r.grade;
  $("r-headline").textContent = GRADE_HEADLINE[r.grade] || "Here's what we found.";
  const when = new Date(r.finishedAt).toLocaleString();
  $("r-meta").textContent = `Score ${r.score} out of 100 for account ${r.accountId}, ${r.regionsScanned.length} regions, checked ${when}.`;

  const counts = $("r-counts");
  counts.replaceChildren();
  for (const sev of SEVERITIES) {
    counts.append(el("div", { class: sev.toLowerCase() }, el("dt", { text: SEV_LABEL[sev].toLowerCase() }), el("dd", { text: String(r.counts[sev] || 0) })));
  }

  const fixable = r.fixableBySecurityStack || 0;
  const launch = safeConsoleUrl(r.baselineLaunchUrl);
  $("r-fixkit").hidden = fixable === 0 || !launch;
  $("r-fix-title").textContent = `SecurityStack fixes ${fixable} of these in one deployment`;
  if (demo) {
    $("r-fixkit").hidden = false;
    $("r-launch").href = "https://github.com/Judewakim/securitystack#deploy";
    $("r-launch").textContent = "How to deploy SecurityStack";
  } else if (launch) {
    $("r-launch").href = launch;
    $("r-launch").textContent = "Deploy SecurityStack in AWS";
  }

  const failed = r.checks.filter((c) => c.status === "FAIL");
  const unknown = r.checks.filter((c) => c.status === "UNKNOWN");
  const passed = r.checks.filter((c) => c.status === "PASS");
  $("r-failed").replaceChildren(...(failed.length ? failed.map(renderCheck) : [el("p", { text: "Nothing failed. Keep it that way with continuous monitoring." })]));
  $("r-unknown-wrap").hidden = unknown.length === 0;
  $("r-unknown").replaceChildren(...unknown.map(renderCheck));
  $("r-passed-summary").textContent = `${passed.length} checks passed`;
  $("r-passed").replaceChildren(...passed.map((c) => el("li", { text: c.ok || c.title })));

  show("results");
  stamp.classList.remove("landed");
  void stamp.offsetWidth; // restart the one deliberate animation
  stamp.classList.add("landed");
}

async function showDemo() {
  try {
    const r = await (await fetch("demo.json", { credentials: "same-origin" })).json();
    renderResults(r, true);
  } catch {
    alert("The sample report couldn't load. Refresh and try again.");
  }
}

function downloadJson() {
  const blob = new Blob([JSON.stringify(state.result, null, 2)], { type: "application/json" });
  const a = el("a", { href: URL.createObjectURL(blob), download: `securitystack-scan-${state.result.accountId}.json` });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

// ------------------------------------------------------------------ landing

const DEPLOY_DOCS = "https://github.com/Judewakim/securitystack/blob/main/docs/deploying.md";
const site = { config: null };

function launchUrl(templateUrl, region, stackName) {
  const params = new URLSearchParams({ stackName, templateURL: templateUrl });
  return `https://${region}.console.aws.amazon.com/cloudformation/home?region=${region}#/stacks/quickcreate?${params}`;
}

function isTemplateUrl(u) {
  try {
    const url = new URL(u);
    return url.protocol === "https:" && /\.s3[.-]([a-z0-9-]+\.)?amazonaws\.com$/.test(url.hostname);
  } catch { return false; }
}

function updateDeployLink() {
  const btn = $("deploy-btn");
  const region = $("deploy-region").value;
  const cfg = site.config;
  if (cfg && isTemplateUrl(cfg.homeTemplateUrl)) {
    btn.href = launchUrl(cfg.homeTemplateUrl, region, "SecurityStack");
  } else {
    btn.href = DEPLOY_DOCS; // local preview, or config missing: send people to the guide
  }
}

async function initLanding() {
  // Reuse the wizard's region list so there's one source of truth.
  $("deploy-region").replaceChildren(...[...$("region").options].map((o) => new Option(o.textContent, o.value)));
  $("deploy-region").addEventListener("change", updateDeployLink);
  try {
    const res = await fetch("config.json", { credentials: "same-origin", cache: "no-store" });
    if (res.ok) site.config = await res.json();
  } catch { /* fine: falls back to the guide */ }
  if (site.config && isTemplateUrl(site.config.regionTemplateUrl)) {
    $("region-template-link").href = site.config.regionTemplateUrl;
  }
  updateDeployLink();

  // The page's one orchestrated moment: services switch on, one after another.
  const items = [...document.querySelectorAll("#switches li")];
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduce) return;
  items.forEach((li) => { li.classList.add("off"); li.querySelector(".state").textContent = "Off"; });
  items.forEach((li, i) => setTimeout(() => {
    li.classList.remove("off");
    li.querySelector(".state").textContent = "On";
  }, 500 + i * 140));
}

// -------------------------------------------------------------------- wiring

function startWizard() {
  resetWizard();
  show("wizard");
}

window.addEventListener("beforeprint", () => document.querySelectorAll("#view-results details").forEach((d) => { d.dataset.wasOpen = d.open; d.open = true; }));
window.addEventListener("afterprint", () => document.querySelectorAll("#view-results details").forEach((d) => { d.open = d.dataset.wasOpen === "true"; }));

document.addEventListener("DOMContentLoaded", async () => {
  initLanding();
  $("start-btn").addEventListener("click", startWizard);
  $("scan-first-btn").addEventListener("click", startWizard);
  $("demo-btn").addEventListener("click", showDemo);
  $("demo-to-scan").addEventListener("click", startWizard);
  $("back-btn").addEventListener("click", () => show("landing"));
  $("session-btn").addEventListener("click", createSession);
  $("arn-form").addEventListener("submit", startScan);
  $("print-btn").addEventListener("click", () => window.print());
  $("json-btn").addEventListener("click", downloadJson);
  $("again-btn").addEventListener("click", startWizard);

  // Resume a scan after a refresh.
  const saved = recall("scanId");
  if (saved && /^[A-Za-z0-9_-]{32}$/.test(saved)) {
    try {
      const s = await api(`${API}/${encodeURIComponent(saved)}`);
      state.scanId = saved;
      if (s.status === "DONE") return renderResults(s.result, false);
      if (s.status === "QUEUED" || s.status === "RUNNING") {
        show("wizard");
        setStep("step-role", { enabled: true, done: true });
        setStep("step-arn", { enabled: true, done: true });
        setStep("step-run", { enabled: true });
        $("progress").hidden = false;
        return poll(Date.now());
      }
    } catch { store("scanId", null); }
  }
});
