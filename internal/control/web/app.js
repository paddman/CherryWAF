"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const appRoot = $("#app");
const modalRoot = $("#modal-root");
const toastRoot = $("#toast-root");

const state = {
  user: null,
  csrf: "",
  route: "dashboard",
  config: null,
  rules: null,
  certificates: [],
  runtimeOnline: null,
  restartRequired: false,
};

const routes = [
  { id: "dashboard", label: "Overview", icon: "OV", group: "Monitor", min: "viewer" },
  { id: "applications", label: "Applications", icon: "AP", group: "Protect", min: "viewer" },
  { id: "policy", label: "WAF Policy", icon: "WF", group: "Protect", min: "viewer" },
  { id: "rules", label: "Rule Studio", icon: "RL", group: "Protect", min: "viewer" },
  { id: "certificates", label: "Certificates", icon: "TL", group: "Protect", min: "viewer" },
  { id: "network", label: "Network", icon: "NW", group: "Appliance", min: "viewer" },
  { id: "recovery", label: "Backup & Rollback", icon: "BK", group: "Appliance", min: "admin" },
  { id: "users", label: "Users & Roles", icon: "ID", group: "Administration", min: "admin" },
  { id: "audit", label: "Audit Log", icon: "AU", group: "Administration", min: "admin" },
  { id: "config", label: "Raw Configuration", icon: "{}", group: "Administration", min: "admin" },
];

const roleLevel = { viewer: 1, operator: 2, admin: 3 };
const can = (role) => (roleLevel[state.user?.role] || 0) >= (roleLevel[role] || 99);

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[ch]));
}
function escapeAttr(value) { return escapeHTML(value).replace(/`/g, "&#96;"); }
function fmtNumber(value) { return Number(value || 0).toLocaleString(); }
function fmtDate(value) {
  if (!value) return "Never";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}
function initials(name) {
  return String(name || "CW").split(/\s+/).filter(Boolean).slice(0, 2).map((part) => part[0]).join("").toUpperCase();
}
function bytes(value) {
  const n = Number(value || 0);
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1024 ** 2).toFixed(1)} MiB`;
}
function statusBadge(label, kind = "blue") { return `<span class="badge ${kind}">${escapeHTML(label)}</span>`; }

async function api(path, options = {}) {
  const opts = { credentials: "same-origin", ...options, headers: { ...(options.headers || {}) } };
  const method = String(opts.method || "GET").toUpperCase();
  if (!["GET", "HEAD", "OPTIONS"].includes(method) && state.csrf) opts.headers["X-CSRF-Token"] = state.csrf;
  if (opts.body && !(opts.body instanceof FormData) && typeof opts.body !== "string") {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.body);
  }
  const response = await fetch(path, opts);
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json") ? await response.json().catch(() => ({})) : await response.text();
  if (!response.ok) {
    const error = new Error(payload?.error || payload || `HTTP ${response.status}`);
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

function toast(message, type = "success") {
  const item = document.createElement("div");
  item.className = `toast ${type}`;
  item.textContent = message;
  toastRoot.appendChild(item);
  setTimeout(() => item.remove(), 4600);
}

function openModal(title, body, options = {}) {
  modalRoot.innerHTML = `<div class="modal-backdrop" data-close-modal="true">
    <section class="modal ${options.wide ? "wide" : ""}" role="dialog" aria-modal="true" aria-label="${escapeAttr(title)}">
      <header class="modal-head"><h2>${escapeHTML(title)}</h2><button class="btn btn-ghost icon-btn" data-close-modal="true" aria-label="Close">×</button></header>
      <div class="modal-body">${body}</div>
    </section>
  </div>`;
  const backdrop = $(".modal-backdrop", modalRoot);
  backdrop.addEventListener("click", (event) => {
    if (event.target.dataset.closeModal === "true") closeModal();
  });
}
function closeModal() { modalRoot.innerHTML = ""; }

function loading() { return `<div class="loading"><div><div class="spinner"></div><p>Loading control plane data…</p></div></div>`; }
function page(title, description, actions = "") {
  return `<div class="page-head"><div><h1>${escapeHTML(title)}</h1><p>${escapeHTML(description)}</p></div><div class="page-actions">${actions}</div></div><div id="page-body">${loading()}</div>`;
}

async function boot() {
  try {
    const setup = await api("/api/v1/setup/status");
    if (setup.setup_required) return renderSetup();
    try {
      const me = await api("/api/v1/auth/me");
      state.user = me.user;
      state.csrf = me.csrf_token || "";
      renderShell();
    } catch (error) {
      renderLogin(error.status === 401 ? "" : error.message);
    }
  } catch (error) {
    renderFatal(error.message);
  }
}

function authBrand() {
  return `<section class="auth-brand">
    <div class="brand-lockup"><div class="brand-mark">CW</div><h1>Cherry<span>WAF</span></h1><p>Application security, TLS termination, policy control, and appliance operations from one hardened control center.</p></div>
    <div class="auth-features">
      <div class="auth-feature"><strong>Transactional policy</strong><span>Validate, snapshot, apply, and roll back.</span></div>
      <div class="auth-feature"><strong>Safe network changes</strong><span>Automatic rollback if connectivity is lost.</span></div>
      <div class="auth-feature"><strong>Role-based access</strong><span>Admin, operator, and read-only viewer roles.</span></div>
      <div class="auth-feature"><strong>Private-key aware</strong><span>Keys remain local and are never returned by the API.</span></div>
    </div>
  </section>`;
}

function renderSetup() {
  appRoot.innerHTML = `<main class="auth-page">${authBrand()}<section class="auth-panel"><form id="setup-form" class="auth-card">
    <div class="setup-steps"><span class="setup-step active"></span><span class="setup-step"></span><span class="setup-step"></span></div>
    <h2>First-boot setup</h2><p>Create the first local administrator. The appliance stores only a salted password hash.</p>
    <div class="field"><label for="setup-token">First-boot setup code</label><input id="setup-token" class="input mono" name="setup_token" autocomplete="one-time-code" required><small>Read the code from the appliance console. It prevents another host on the management network from claiming the first administrator.</small></div>
    <div class="field"><label for="setup-username">Administrator username</label><input id="setup-username" class="input" name="username" value="admin" autocomplete="username" required minlength="3"></div>
    <div class="field"><label for="setup-name">Display name</label><input id="setup-name" class="input" name="display_name" value="CherryWAF Administrator" required></div>
    <div class="field"><label for="setup-password">Password</label><input id="setup-password" class="input" name="password" type="password" autocomplete="new-password" required minlength="12"><small>At least 12 characters with uppercase, lowercase, number, and symbol.</small></div>
    <div class="field"><label for="setup-confirm">Confirm password</label><input id="setup-confirm" class="input" name="confirm" type="password" autocomplete="new-password" required></div>
    <button class="btn btn-primary" type="submit">Create administrator</button>
  </form></section></main>`;
  $("#setup-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    if (form.get("password") !== form.get("confirm")) return toast("Passwords do not match.", "error");
    const button = $("button[type=submit]", event.currentTarget); button.disabled = true;
    try {
      const result = await api("/api/v1/setup/complete", { method: "POST", body: { setup_token: form.get("setup_token"), username: form.get("username"), display_name: form.get("display_name"), password: form.get("password") } });
      state.user = result.user; state.csrf = result.csrf_token; toast("Administrator created."); renderShell(); setTimeout(openFirstBootGuide, 0);
    } catch (error) { toast(error.message, "error"); button.disabled = false; }
  });
}

function openFirstBootGuide() {
  openModal("CherryWAF first-boot guide", `<div class="stack">
    <div class="notice"><strong>Administrator ready.</strong>&nbsp;Complete the two operational steps below before placing the appliance in front of production traffic.</div>
    <div class="grid two"><section class="card card-pad"><h3 class="section-title">1. Network</h3><p class="muted small">Keep DHCP or configure a static management address with automatic rollback protection.</p><button class="btn mt-12" data-first-route="network">Configure network</button></section>
    <section class="card card-pad"><h3 class="section-title">2. Protect an application</h3><p class="muted small">Install a TLS certificate, define the origin, then begin in detect mode while tuning false positives.</p><div class="inline mt-12"><button class="btn" data-first-route="certificates">Install certificate</button><button class="btn btn-primary" data-first-route="applications">Add application</button></div></section></div>
    <div class="form-actions"><button class="btn" data-close-modal="true">Continue to dashboard</button></div>
  </div>`, { wide: true });
  $$('[data-close-modal]', modalRoot).forEach((button) => button.onclick = closeModal);
  $$('[data-first-route]', modalRoot).forEach((button) => button.onclick = () => { const route = button.dataset.firstRoute; closeModal(); location.hash = route; });
}

function renderLogin(message = "") {
  state.user = null; state.csrf = "";
  appRoot.innerHTML = `<main class="auth-page">${authBrand()}<section class="auth-panel"><form id="login-form" class="auth-card">
    <h2>Sign in</h2><p>Use a local CherryWAF Control Center account.</p>
    ${message ? `<div class="notice danger">${escapeHTML(message)}</div>` : ""}
    <div class="field"><label for="login-username">Username</label><input id="login-username" class="input" name="username" autocomplete="username" required autofocus></div>
    <div class="field"><label for="login-password">Password</label><input id="login-password" class="input" name="password" type="password" autocomplete="current-password" required></div>
    <button class="btn btn-primary" type="submit">Sign in</button>
  </form></section></main>`;
  $("#login-form").addEventListener("submit", async (event) => {
    event.preventDefault(); const form = new FormData(event.currentTarget); const button = $("button", event.currentTarget); button.disabled = true;
    try {
      const result = await api("/api/v1/auth/login", { method: "POST", body: { username: form.get("username"), password: form.get("password") } });
      state.user = result.user; state.csrf = result.csrf_token; renderShell();
    } catch (error) { toast(error.message, "error"); button.disabled = false; }
  });
}

function renderFatal(message) {
  appRoot.innerHTML = `<main class="auth-page">${authBrand()}<section class="auth-panel"><div class="auth-card"><h2>Control Center unavailable</h2><div class="notice danger">${escapeHTML(message)}</div><button class="btn" id="retry">Retry</button></div></section></main>`;
  $("#retry").onclick = boot;
}

function renderShell() {
  const groups = [...new Set(routes.map((route) => route.group))];
  const navigation = groups.map((group) => {
    const items = routes.filter((route) => route.group === group && can(route.min)).map((route) => `<button class="nav-item" data-route="${route.id}"><span class="nav-icon">${escapeHTML(route.icon)}</span><span>${escapeHTML(route.label)}</span></button>`).join("");
    return items ? `<div class="nav-group"><div class="nav-label">${escapeHTML(group)}</div>${items}</div>` : "";
  }).join("");
  appRoot.innerHTML = `<div class="shell">
    <aside class="sidebar" id="sidebar">
      <div class="sidebar-brand"><div class="brand-mark">CW</div><div><strong>CherryWAF</strong><span>Control Center</span></div></div>
      <nav>${navigation}</nav>
      <div class="sidebar-footer"><div class="user-chip"><div class="avatar">${escapeHTML(initials(state.user.display_name))}</div><div><strong>${escapeHTML(state.user.display_name)}</strong><span>${escapeHTML(state.user.role)}</span></div></div><div class="sidebar-actions"><button class="btn btn-sm" id="refresh-page">Refresh</button><button class="btn btn-sm btn-ghost" id="logout">Sign out</button></div></div>
    </aside>
    <main class="main"><header class="topbar"><div class="topbar-title"><button class="btn icon-btn mobile-menu" id="menu-toggle">☰</button><strong id="top-title">Overview</strong><span>Secure appliance management</span></div><div class="status-pill"><span class="status-dot" id="runtime-dot"></span><span id="runtime-label">Checking WAF core</span></div></header><section class="content" id="content"></section></main>
  </div>`;
  $$("[data-route]").forEach((button) => button.addEventListener("click", () => { location.hash = button.dataset.route; $("#sidebar").classList.remove("open"); }));
  $("#menu-toggle").onclick = () => $("#sidebar").classList.toggle("open");
  $("#refresh-page").onclick = () => navigate(state.route, true);
  $("#logout").onclick = async () => { try { await api("/api/v1/auth/logout", { method: "POST" }); } catch (_) {} renderLogin(); };
  window.onhashchange = () => navigate(location.hash.slice(1) || "dashboard");
  navigate(location.hash.slice(1) || "dashboard");
}

async function navigate(route, force = false) {
  const descriptor = routes.find((item) => item.id === route && can(item.min)) || routes.find((item) => item.id === "dashboard");
  state.route = descriptor.id;
  if (location.hash.slice(1) !== descriptor.id) history.replaceState(null, "", `#${descriptor.id}`);
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.route === descriptor.id));
  $("#top-title").textContent = descriptor.label;
  const content = $("#content"); content.innerHTML = loading();
  const handlers = { dashboard: renderDashboard, applications: renderApplications, policy: renderPolicy, rules: renderRules, certificates: renderCertificates, network: renderNetwork, recovery: renderRecovery, users: renderUsers, audit: renderAudit, config: renderRawConfig };
  try { await handlers[descriptor.id](content, force); }
  catch (error) {
    if (error.status === 401) return renderLogin("Your session expired.");
    content.innerHTML = `<div class="notice danger">${escapeHTML(error.message)}</div>`;
    toast(error.message, "error");
  }
}

function updateRuntimeStatus(online) {
  state.runtimeOnline = online;
  const dot = $("#runtime-dot"); const label = $("#runtime-label"); if (!dot || !label) return;
  dot.classList.toggle("bad", !online); label.textContent = online ? "WAF core online" : "WAF core unavailable";
}

async function loadConfig(force = false) {
  if (!state.config || force) { const result = await api("/api/v1/config"); state.config = result.config; }
  return state.config;
}
async function saveConfig(config, message = "Configuration applied") {
  const result = await api("/api/v1/config", { method: "PUT", body: config });
  state.config = config;
  toast(result.restart_required ? `${message}. Service restart required for listener changes.` : message, result.restart_required ? "error" : "success");
  if (result.restart_required) {
    state.restartRequired = true;
    setTimeout(openRestartPrompt, 0);
  }
  return result;
}

async function renderDashboard(content) {
  content.innerHTML = page("Security overview", "Live status from the WAF data plane and the local appliance control plane.");
  const result = await api("/api/v1/dashboard");
  updateRuntimeStatus(Boolean(result.runtime_available));
  const runtime = result.runtime || {};
  const metrics = runtime.metrics || {};
  const domains = runtime.domains || [];
  const certs = runtime.certificates || [];
  const blockedRate = metrics.requests ? ((metrics.blocked || 0) / metrics.requests * 100).toFixed(2) : "0.00";
  $("#page-body").innerHTML = `
    ${!result.runtime_available ? `<div class="notice danger"><strong>WAF core is not responding.</strong>&nbsp;${escapeHTML(result.runtime_error || "Check cherrywaf.service and the loopback admin token.")}</div>` : ""}
    <div class="grid cards-4">
      <div class="card metric"><div class="metric-label">Requests</div><div class="metric-value">${fmtNumber(metrics.requests)}</div><div class="metric-note">${fmtNumber(metrics.in_flight)} currently in flight</div></div>
      <div class="card metric"><div class="metric-label">Blocked</div><div class="metric-value">${fmtNumber(metrics.blocked)}</div><div class="metric-note">${blockedRate}% of processed traffic</div></div>
      <div class="card metric"><div class="metric-label">Protected domains</div><div class="metric-value">${fmtNumber(domains.length)}</div><div class="metric-note">${fmtNumber(runtime.rule_count)} active rules</div></div>
      <div class="card metric"><div class="metric-label">Origin errors</div><div class="metric-value">${fmtNumber(metrics.upstream_errors)}</div><div class="metric-note">${fmtNumber(metrics.reload_failures)} reload failures</div></div>
    </div>
    <div class="grid two mt-16">
      <section class="card"><header class="card-head"><div><h3>Protected applications</h3><p>Host routing currently loaded by the WAF.</p></div><button class="btn btn-sm" data-jump="applications">Manage</button></header><div class="card-body">${domains.length ? domains.map((domain) => `<div class="meta-row"><span>Domain</span><span class="mono">${escapeHTML(domain)}</span></div>`).join("") : `<div class="empty"><strong>No protected applications</strong>Add a virtual host to start routing traffic.</div>`}</div></section>
      <section class="card"><header class="card-head"><div><h3>TLS certificate health</h3><p>Certificates loaded in the current runtime.</p></div><button class="btn btn-sm" data-jump="certificates">Manage</button></header><div class="card-body">${certs.length ? certs.map((cert) => `<div class="meta-row"><span>${escapeHTML(cert.virtual_host || "Certificate")}</span><span>${cert.days_left < 30 ? statusBadge(`${cert.days_left} days`, "amber") : statusBadge(`${cert.days_left} days`, "green")}</span></div>`).join("") : `<div class="empty"><strong>No runtime certificates</strong>HTTPS may be disabled or no virtual hosts are active.</div>`}</div></section>
    </div>`;
  $$('[data-jump]').forEach((button) => button.onclick = () => { location.hash = button.dataset.jump; });
}

function deepClone(value) {
  if (typeof structuredClone === "function") return structuredClone(value);
  return JSON.parse(JSON.stringify(value));
}
function listValue(value) {
  return String(value || "").split(/[\n,]+/).map((item) => item.trim()).filter(Boolean);
}
function headersFromText(value) {
  const result = {};
  for (const line of String(value || "").split(/\n+/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const position = trimmed.indexOf(":");
    if (position < 1) throw new Error(`Invalid response header: ${trimmed}`);
    result[trimmed.slice(0, position).trim()] = trimmed.slice(position + 1).trim();
  }
  return result;
}
function headersToText(value) {
  return Object.entries(value || {}).map(([key, item]) => `${key}: ${item}`).join("\n");
}
function appDefaults() {
  return {
    name: "", enabled: true, domains: [], upstream: "http://127.0.0.1:8080", preserve_host: true,
    frontend_tls: { certificate_file: "", private_key_file: "" },
    origin_tls: { server_name: "", ca_file: "", insecure_skip_verify: false },
    response_headers: { "X-Content-Type-Options": "nosniff" },
  };
}

function openRestartPrompt() {
  if (!state.restartRequired || !can("admin")) return;
  openModal("Restart WAF data plane", `<div class="stack"><div class="notice warning"><strong>A validated listener change is waiting.</strong>&nbsp;The current process is still serving the previous listener set until cherrywaf.service restarts.</div><p class="muted small">Restarting the WAF briefly interrupts new connections. The Control Center remains available on port 9443.</p><div class="form-actions"><button class="btn" data-close-modal="true">Restart later</button><button class="btn btn-danger" id="restart-waf-now">Restart WAF now</button></div></div>`);
  $$('[data-close-modal]', modalRoot).forEach((button) => button.onclick = closeModal);
  $("#restart-waf-now").onclick = restartWAF;
}

async function restartWAF() {
  const button = $("#restart-waf-now"); if (button) button.disabled = true;
  try {
    await api("/api/v1/system/restart-waf", { method: "POST", body: {} });
    state.restartRequired = false; closeModal(); toast("WAF service restarted.");
    setTimeout(async () => { try { const result = await api("/api/v1/dashboard"); updateRuntimeStatus(Boolean(result.runtime_available)); } catch (_) {} }, 1600);
  } catch (error) { toast(error.message, "error"); if (button) button.disabled = false; }
}

async function renderApplications(content, force = false) {
  const actions = can("admin") ? `<button class="btn" id="edit-listeners">Frontend listeners</button><button class="btn btn-primary" id="add-application">Add application</button>` : "";
  content.innerHTML = page("Protected applications", "Configure domains, origin servers, frontend TLS, and origin certificate verification.", actions);
  const config = await loadConfig(force);
  const hosts = config.virtual_hosts || [];
  const listenerSummary = `<section class="card card-pad mb-16"><div class="split"><div><h3 class="section-title">Frontend listeners</h3><div class="inline">${config.http?.enabled ? statusBadge(`HTTP ${config.http.listen}`, "blue") : statusBadge("HTTP off", "amber")}${config.https?.enabled ? statusBadge(`HTTPS ${config.https.listen}`, "green") : statusBadge("HTTPS off", "amber")}${config.http?.redirect_to_https ? statusBadge("Redirect to HTTPS", "blue") : ""}</div></div><div class="small muted">TLS minimum ${escapeHTML(config.https?.min_tls_version || "1.2")}</div></div></section>`;
  $("#page-body").innerHTML = listenerSummary + (hosts.length ? `<div class="app-list">${hosts.map((host, index) => {
    const domains = host.domains || [];
    const tls = Boolean(host.frontend_tls?.certificate_file);
    return `<article class="app-card">
      <div class="app-card-top"><div><h3>${escapeHTML(host.name)}</h3><div class="domain">${escapeHTML(domains.join(", ") || "No domain")}</div></div>${host.enabled ? statusBadge("Enabled", "green") : statusBadge("Disabled", "amber")}</div>
      <div class="app-meta">
        <div class="meta-row"><span>Origin</span><span class="mono">${escapeHTML(host.upstream)}</span></div>
        <div class="meta-row"><span>Frontend TLS</span><span>${tls ? "Certificate assigned" : "Not assigned"}</span></div>
        <div class="meta-row"><span>Origin verification</span><span>${host.origin_tls?.insecure_skip_verify ? statusBadge("Disabled", "red") : statusBadge("Enabled", "green")}</span></div>
        <div class="meta-row"><span>Preserve Host</span><span>${host.preserve_host ? "Yes" : "No"}</span></div>
      </div>
      <div class="app-card-actions"><button class="btn btn-sm" data-edit-app="${index}">${can("admin") ? "Edit" : "View"}</button>${can("admin") ? `<button class="btn btn-sm btn-danger" data-delete-app="${index}">Delete</button>` : ""}</div>
    </article>`;
  }).join("")}</div>` : `<div class="card"><div class="empty"><strong>No applications configured</strong>Add the first domain and origin server. A WAF without a protected application is essentially a very stern JSON file.</div></div>`);
  if (can("admin")) {
    $("#add-application").onclick = () => openApplicationEditor(null);
    $("#edit-listeners").onclick = openListenerEditor;
  }
  $$('[data-edit-app]').forEach((button) => button.onclick = () => openApplicationEditor(Number(button.dataset.editApp)));
  $$('[data-delete-app]').forEach((button) => button.onclick = async () => {
    const index = Number(button.dataset.deleteApp); const host = state.config.virtual_hosts[index];
    if (!confirm(`Delete application ${host.name}?`)) return;
    const next = deepClone(state.config); next.virtual_hosts.splice(index, 1);
    if (!next.virtual_hosts.length) {
      next.http = next.http || {};
      next.https = next.https || {};
      next.http.enabled = true;
      next.http.redirect_to_https = false;
      next.https.enabled = false;
    }
    await saveConfig(next, "Application removed"); await renderApplications(content, true);
  });
}

function openListenerEditor() {
  const config = state.config;
  openModal("Frontend listeners", `<form id="listener-form">
    <div class="grid two"><section class="card card-pad"><h3 class="section-title">HTTP</h3><label class="check"><input type="checkbox" name="http_enabled" ${config.http?.enabled ? "checked" : ""}>Enable HTTP listener</label><div class="field mt-16"><label>Listen address</label><input class="input mono" name="http_listen" value="${escapeAttr(config.http?.listen || ":80")}" required></div><label class="check"><input type="checkbox" name="redirect" ${config.http?.redirect_to_https ? "checked" : ""}>Redirect HTTP requests to HTTPS</label></section>
    <section class="card card-pad"><h3 class="section-title">HTTPS</h3><label class="check"><input type="checkbox" name="https_enabled" ${config.https?.enabled ? "checked" : ""}>Enable HTTPS listener</label><div class="field mt-16"><label>Listen address</label><input class="input mono" name="https_listen" value="${escapeAttr(config.https?.listen || ":443")}" required></div><div class="field"><label>Minimum TLS version</label><select class="select" name="min_tls"><option value="1.2" ${config.https?.min_tls_version !== "1.3" ? "selected" : ""}>TLS 1.2</option><option value="1.3" ${config.https?.min_tls_version === "1.3" ? "selected" : ""}>TLS 1.3</option></select></div></section></div>
    <div class="notice warning mt-16">Changing listener addresses or enabling HTTPS for the first time requires a service restart after the candidate configuration is validated.</div>
    <div class="form-actions"><button type="button" class="btn" data-close-modal="true">Cancel</button><button class="btn btn-primary" type="submit">Validate and apply</button></div>
  </form>`, { wide: true });
  $$('[data-close-modal]', modalRoot).forEach((button) => button.onclick = closeModal);
  $("#listener-form").onsubmit = async (event) => {
    event.preventDefault(); const values = new FormData(event.currentTarget); const next = deepClone(config);
    next.http = { ...(next.http || {}), enabled: values.has("http_enabled"), listen: String(values.get("http_listen") || "").trim(), redirect_to_https: values.has("redirect") };
    next.https = { ...(next.https || {}), enabled: values.has("https_enabled"), listen: String(values.get("https_listen") || "").trim(), min_tls_version: String(values.get("min_tls")) };
    try { await saveConfig(next, "Frontend listeners updated"); closeModal(); await navigate("applications", true); } catch (error) { toast(error.message, "error"); }
  };
}

async function openApplicationEditor(index) {
  const readOnly = !can("admin");
  const config = await loadConfig();
  let certs = [];
  try { certs = (await api("/api/v1/certificates")).certificates || []; } catch (_) {}
  const original = index === null ? appDefaults() : deepClone(config.virtual_hosts[index]);
  const selectedCert = certs.find((item) => item.certificate_file === original.frontend_tls?.certificate_file)?.domain || "";
  const certOptions = `<option value="">Manual paths / no managed certificate</option>${certs.map((item) => `<option value="${escapeAttr(item.domain)}" ${item.domain === selectedCert ? "selected" : ""}>${escapeHTML(item.domain)} (${item.days_left} days)</option>`).join("")}`;
  openModal(index === null ? "Add protected application" : `${readOnly ? "View" : "Edit"} application`, `<form id="application-form">
    <div class="field-row"><div class="field"><label>Name</label><input class="input" name="name" value="${escapeAttr(original.name)}" required ${readOnly ? "disabled" : ""}></div><div class="field"><label>Origin URL</label><input class="input mono" name="upstream" value="${escapeAttr(original.upstream)}" placeholder="https://10.10.10.20:443" required ${readOnly ? "disabled" : ""}></div></div>
    <div class="field"><label>Domains</label><textarea class="textarea mono" name="domains" placeholder="app.example.com\nwww.example.com" required ${readOnly ? "disabled" : ""}>${escapeHTML((original.domains || []).join("\n"))}</textarea><small>One domain per line. One-label wildcards such as *.example.com are supported.</small></div>
    <div class="field-row"><label class="check"><input type="checkbox" name="enabled" ${original.enabled ? "checked" : ""} ${readOnly ? "disabled" : ""}>Enable this virtual host</label><label class="check"><input type="checkbox" name="preserve_host" ${original.preserve_host ? "checked" : ""} ${readOnly ? "disabled" : ""}>Preserve incoming Host header</label></div>
    <h3 class="section-title mt-16">Frontend TLS</h3>
    <div class="field"><label>Managed certificate</label><select class="select" name="managed_certificate" ${readOnly ? "disabled" : ""}>${certOptions}</select></div>
    <div class="field-row"><div class="field"><label>Certificate file</label><input class="input mono" name="certificate_file" value="${escapeAttr(original.frontend_tls?.certificate_file || "")}" ${readOnly ? "disabled" : ""}></div><div class="field"><label>Private key file</label><input class="input mono" name="private_key_file" value="${escapeAttr(original.frontend_tls?.private_key_file || "")}" ${readOnly ? "disabled" : ""}></div></div>
    <h3 class="section-title mt-16">Origin TLS</h3>
    <div class="field-row"><div class="field"><label>Origin SNI / server name</label><input class="input" name="origin_server_name" value="${escapeAttr(original.origin_tls?.server_name || "")}" ${readOnly ? "disabled" : ""}></div><div class="field"><label>Private CA bundle</label><input class="input mono" name="origin_ca_file" value="${escapeAttr(original.origin_tls?.ca_file || "")}" ${readOnly ? "disabled" : ""}></div></div>
    <label class="check"><input type="checkbox" name="insecure_skip_verify" ${original.origin_tls?.insecure_skip_verify ? "checked" : ""} ${readOnly ? "disabled" : ""}>Disable origin certificate verification (unsafe; use only for controlled diagnostics)</label>
    <div class="field mt-16"><label>Response headers</label><textarea class="textarea mono" name="response_headers" placeholder="X-Content-Type-Options: nosniff" ${readOnly ? "disabled" : ""}>${escapeHTML(headersToText(original.response_headers))}</textarea></div>
    <div class="form-actions"><button type="button" class="btn" data-close-modal="true">Close</button>${readOnly ? "" : `<button class="btn btn-primary" type="submit">Validate and apply</button>`}</div>
  </form>`, { wide: true });
  $$('[data-close-modal]', modalRoot).forEach((button) => button.onclick = closeModal);
  const form = $("#application-form");
  const managed = $("[name=managed_certificate]", form);
  if (managed && !readOnly) managed.onchange = () => {
    const certificate = certs.find((item) => item.domain === managed.value);
    if (!certificate) return;
    $("[name=certificate_file]", form).value = certificate.certificate_file;
    $("[name=private_key_file]", form).value = certificate.private_key_file;
  };
  if (!readOnly) form.onsubmit = async (event) => {
    event.preventDefault(); const values = new FormData(form);
    try {
      const item = {
        name: String(values.get("name") || "").trim(), enabled: values.has("enabled"), domains: listValue(values.get("domains")),
        upstream: String(values.get("upstream") || "").trim(), preserve_host: values.has("preserve_host"),
        frontend_tls: { certificate_file: String(values.get("certificate_file") || "").trim(), private_key_file: String(values.get("private_key_file") || "").trim() },
        origin_tls: { server_name: String(values.get("origin_server_name") || "").trim(), ca_file: String(values.get("origin_ca_file") || "").trim(), insecure_skip_verify: values.has("insecure_skip_verify") },
        response_headers: headersFromText(values.get("response_headers")),
      };
      const next = deepClone(config); next.virtual_hosts = next.virtual_hosts || [];
      if (index === null) {
        next.virtual_hosts.push(item);
        if (next.virtual_hosts.length === 1) {
          next.http = next.http || {};
          next.http.enabled = true;
          if (!next.http.listen || next.http.listen === "127.0.0.1:8080") next.http.listen = ":80";
          if (item.frontend_tls.certificate_file && item.frontend_tls.private_key_file) {
            next.https = next.https || {};
            next.https.enabled = true;
            if (!next.https.listen || next.https.listen === "127.0.0.1:8443") next.https.listen = ":443";
            next.https.min_tls_version = next.https.min_tls_version || "1.2";
            next.http.redirect_to_https = true;
          }
        }
      } else next.virtual_hosts[index] = item;
      await saveConfig(next, index === null ? "Application added" : "Application updated"); closeModal(); location.hash = "applications"; await navigate("applications", true);
    } catch (error) { toast(error.message, "error"); }
  };
}

async function renderPolicy(content, force = false) {
  content.innerHTML = page("WAF policy", "Tune anomaly scoring, inspection limits, request handling, and per-client rate limiting.");
  const config = await loadConfig(force); const security = config.security || {}; const rate = security.rate_limit || {}; const disabled = can("admin") ? "" : "disabled";
  $("#page-body").innerHTML = `<form id="policy-form" class="grid two">
    <section class="card"><header class="card-head"><div><h3>Inspection and enforcement</h3><p>Global behavior for the active data plane.</p></div></header><div class="card-body">
      <div class="field"><label>Enforcement mode</label><select class="select" name="mode" ${disabled}><option value="detect" ${security.mode === "detect" ? "selected" : ""}>Detect only</option><option value="blocking" ${security.mode === "blocking" ? "selected" : ""}>Blocking</option></select></div>
      <div class="field"><label>Block threshold</label><input class="input" type="number" min="1" max="1000" name="block_threshold" value="${escapeAttr(security.block_threshold || 10)}" ${disabled}><small>Requests reaching this anomaly score are blocked in blocking mode.</small></div>
      <div class="field-row"><div class="field"><label>Maximum inspected body</label><input class="input" type="number" min="1024" max="134217728" name="max_body_bytes" value="${escapeAttr(security.max_body_bytes || 1048576)}" ${disabled}><small>${bytes(security.max_body_bytes)}</small></div><div class="field"><label>Maximum headers</label><input class="input" type="number" min="8192" max="16777216" name="max_header_bytes" value="${escapeAttr(security.max_header_bytes || 1048576)}" ${disabled}><small>${bytes(security.max_header_bytes)}</small></div></div>
      <div class="field"><label>Forwarded client IP header</label><input class="input" name="forwarded_for_header" value="${escapeAttr(security.forwarded_for_header || "X-Forwarded-For")}" ${disabled}></div>
      <div class="field"><label>Trusted proxy CIDRs</label><textarea class="textarea mono" name="trusted_proxies" ${disabled}>${escapeHTML((security.trusted_proxies || []).join("\n"))}</textarea></div>
    </div></section>
    <section class="card"><header class="card-head"><div><h3>Rate limiting</h3><p>Local token-bucket protection per application and client.</p></div></header><div class="card-body">
      <label class="check"><input type="checkbox" name="rate_enabled" ${rate.enabled ? "checked" : ""} ${disabled}>Enable rate limiting</label>
      <div class="field-row mt-16"><div class="field"><label>Requests per second</label><input class="input" type="number" step="0.1" min="0.1" name="requests_per_second" value="${escapeAttr(rate.requests_per_second || 50)}" ${disabled}></div><div class="field"><label>Burst capacity</label><input class="input" type="number" min="1" name="burst" value="${escapeAttr(rate.burst || 100)}" ${disabled}></div></div>
      <div class="field"><label>Client entry TTL (seconds)</label><input class="input" type="number" min="30" name="entry_ttl_seconds" value="${escapeAttr(rate.entry_ttl_seconds || 600)}" ${disabled}></div>
      <div class="notice warning"><strong>Deployment note:</strong>&nbsp;This limiter is local to one CherryWAF node. A clustered deployment should use shared state before marketing departments discover the phrase “globally distributed.”</div>
      ${can("admin") ? `<div class="form-actions"><button class="btn btn-primary" type="submit">Apply policy</button></div>` : `<div class="notice">Viewer access is read-only.</div>`}
    </div></section>
  </form>`;
  if (can("admin")) $("#policy-form").onsubmit = async (event) => {
    event.preventDefault(); const values = new FormData(event.currentTarget); const next = deepClone(config);
    next.security = next.security || {};
    Object.assign(next.security, { mode: values.get("mode"), block_threshold: Number(values.get("block_threshold")), max_body_bytes: Number(values.get("max_body_bytes")), max_header_bytes: Number(values.get("max_header_bytes")), forwarded_for_header: String(values.get("forwarded_for_header") || "").trim(), trusted_proxies: listValue(values.get("trusted_proxies")), rate_limit: { enabled: values.has("rate_enabled"), requests_per_second: Number(values.get("requests_per_second")), burst: Number(values.get("burst")), entry_ttl_seconds: Number(values.get("entry_ttl_seconds")) } });
    await saveConfig(next, "WAF policy applied"); await renderPolicy(content, true);
  };
}

async function renderCertificates(content) {
  const actions = can("admin") ? `<button class="btn btn-primary" id="upload-certificate">Install certificate</button>` : "";
  content.innerHTML = page("TLS certificates", "Validate and manage frontend certificate/key pairs. Private keys never leave the appliance API.", actions);
  const result = await api("/api/v1/certificates"); state.certificates = result.certificates || [];
  $("#page-body").innerHTML = `<div class="card"><div class="table-wrap"><table><thead><tr><th>Domain</th><th>Issuer</th><th>Expires</th><th>Status</th><th>Usage</th><th></th></tr></thead><tbody>${state.certificates.length ? state.certificates.map((item) => `<tr><td><strong>${escapeHTML(item.domain)}</strong><div class="small muted mono break">${escapeHTML(item.certificate_file)}</div></td><td>${escapeHTML(item.issuer)}</td><td>${fmtDate(item.not_after)}</td><td>${item.days_left < 0 ? statusBadge("Expired", "red") : item.days_left < 30 ? statusBadge(`${item.days_left} days`, "amber") : statusBadge(`${item.days_left} days`, "green")}</td><td>${item.in_use ? statusBadge("In use", "blue") : statusBadge("Available", "green")}</td><td><div class="actions">${can("admin") && !item.in_use ? `<button class="btn btn-sm btn-danger" data-delete-cert="${escapeAttr(item.domain)}">Delete</button>` : ""}</div></td></tr>`).join("") : `<tr><td colspan="6"><div class="empty"><strong>No managed certificates</strong>Upload a PEM full chain and matching private key.</div></td></tr>`}</tbody></table></div></div>
  <div class="notice mt-16">Certificate files are stored locally with restricted permissions. The API returns paths and metadata, never private-key material.</div>`;
  if (can("admin")) {
    $("#upload-certificate").onclick = openCertificateUpload;
    $$('[data-delete-cert]').forEach((button) => button.onclick = async () => {
      const domain = button.dataset.deleteCert; if (!confirm(`Delete certificate for ${domain}?`)) return;
      await api(`/api/v1/certificates/${encodeURIComponent(domain)}`, { method: "DELETE" }); toast("Certificate deleted."); await renderCertificates(content);
    });
  }
}

function openCertificateUpload() {
  openModal("Install TLS certificate", `<form id="certificate-form">
    <div class="field"><label>Domain</label><input class="input" name="domain" placeholder="app.example.com or *.example.com" required></div>
    <div class="field"><label>Certificate / full chain (PEM)</label><input class="input" name="certificate" type="file" accept=".pem,.crt,.cer" required></div>
    <div class="field"><label>Private key (PEM)</label><input class="input" name="private_key" type="file" accept=".pem,.key" required></div>
    <div class="notice warning">The key is validated locally for pair matching and restrictive filesystem permissions. It is never downloadable through Control Center.</div>
    <div class="form-actions"><button type="button" class="btn" data-close-modal="true">Cancel</button><button class="btn btn-primary" type="submit">Validate and install</button></div>
  </form>`);
  $$('[data-close-modal]', modalRoot).forEach((button) => button.onclick = closeModal);
  $("#certificate-form").onsubmit = async (event) => {
    event.preventDefault(); const data = new FormData(event.currentTarget);
    try { await api("/api/v1/certificates", { method: "POST", body: data }); toast("Certificate installed."); closeModal(); await navigate("certificates", true); }
    catch (error) { toast(error.message, "error"); }
  };
}

async function renderRules(content) {
  const actions = can("operator") ? `<button class="btn" id="test-rule">Test rule</button><button class="btn btn-primary" id="add-rule">Add rule</button>` : "";
  content.innerHTML = page("Visual Rule Studio", "Build, test, and publish native RE2-compatible request inspection rules.", actions);
  const result = await api("/api/v1/rules"); state.rules = result.rule_file || { version: 1, rules: [] }; const rules = state.rules.rules || [];
  $("#page-body").innerHTML = `${!result.active && rules.length ? `<div class="notice warning">The GUI rule file exists but is not referenced by the active WAF configuration. Saving it again will attach it transactionally.</div>` : ""}
  <div class="card"><div class="table-wrap"><table><thead><tr><th>Rule</th><th>Targets</th><th>Pattern</th><th>Score</th><th>Action</th><th>Status</th><th></th></tr></thead><tbody>${rules.length ? rules.map((rule, index) => `<tr><td><strong>${escapeHTML(rule.id)}</strong><div class="small muted">${escapeHTML(rule.name)}</div></td><td>${escapeHTML((rule.targets || []).join(", "))}</td><td><div class="rule-pattern mono" title="${escapeAttr(rule.pattern)}">${escapeHTML(rule.pattern)}</div></td><td>${fmtNumber(rule.score)}</td><td>${statusBadge(rule.action, rule.action === "block" ? "red" : rule.action === "log" ? "blue" : "amber")}</td><td>${rule.enabled ? statusBadge(rule.severity, "green") : statusBadge("Disabled", "amber")}</td><td><div class="actions"><button class="btn btn-sm" data-edit-rule="${index}">${can("operator") ? "Edit" : "View"}</button>${can("operator") ? `<button class="btn btn-sm btn-danger" data-delete-rule="${index}">Delete</button>` : ""}</div></td></tr>`).join("") : `<tr><td colspan="7"><div class="empty"><strong>No custom rules</strong>Built-in rules remain active according to the WAF configuration.</div></td></tr>`}</tbody></table></div></div>`;
  if (can("operator")) { $("#add-rule").onclick = () => openRuleEditor(null); $("#test-rule").onclick = () => openRuleTest(null); }
  $$('[data-edit-rule]').forEach((button) => button.onclick = () => openRuleEditor(Number(button.dataset.editRule)));
  $$('[data-delete-rule]').forEach((button) => button.onclick = async () => {
    const index = Number(button.dataset.deleteRule); if (!confirm(`Delete rule ${rules[index].id}?`)) return;
    const next = deepClone(state.rules); next.rules.splice(index, 1); await saveRules(next); await navigate("rules", true);
  });
}

async function saveRules(ruleFile) {
  const result = await api("/api/v1/rules", { method: "PUT", body: ruleFile }); state.rules = ruleFile;
  toast(result.restart_required ? "Rules saved; service restart required." : "Rules applied.", result.restart_required ? "error" : "success");
  if (result.restart_required) { state.restartRequired = true; setTimeout(openRestartPrompt, 0); }
  return result;
}

function ruleDefaults() { return { id: `LOCAL-${Date.now().toString().slice(-6)}`, name: "", description: "", enabled: true, targets: ["path", "query"], pattern: "", score: 10, action: "score", severity: "high" }; }
function openRuleEditor(index) {
  const readOnly = !can("operator"); const rule = index === null ? ruleDefaults() : deepClone(state.rules.rules[index]); const allTargets = ["method", "path", "query", "headers", "cookies", "body"];
  openModal(index === null ? "Add custom rule" : `${readOnly ? "View" : "Edit"} rule`, `<form id="rule-form">
    <div class="field-row"><div class="field"><label>Rule ID</label><input class="input mono" name="id" value="${escapeAttr(rule.id)}" required ${readOnly ? "disabled" : ""}></div><div class="field"><label>Name</label><input class="input" name="name" value="${escapeAttr(rule.name)}" required ${readOnly ? "disabled" : ""}></div></div>
    <div class="field"><label>Description</label><input class="input" name="description" value="${escapeAttr(rule.description || "")}" ${readOnly ? "disabled" : ""}></div>
    <div class="field"><label>Inspection targets</label><div class="inline">${allTargets.map((target) => `<label class="check"><input type="checkbox" name="target" value="${target}" ${(rule.targets || []).includes(target) ? "checked" : ""} ${readOnly ? "disabled" : ""}>${target}</label>`).join("")}</div></div>
    <div class="field"><label>RE2 pattern</label><textarea class="textarea code-editor" name="pattern" required ${readOnly ? "disabled" : ""}>${escapeHTML(rule.pattern)}</textarea><small>Go's RE2 engine avoids catastrophic backtracking but does not support look-around or backreferences.</small></div>
    <div class="field-row"><div class="field"><label>Score</label><input class="input" type="number" min="0" max="1000" name="score" value="${escapeAttr(rule.score)}" ${readOnly ? "disabled" : ""}></div><div class="field"><label>Action</label><select class="select" name="action" ${readOnly ? "disabled" : ""}>${["score", "block", "log"].map((item) => `<option ${rule.action === item ? "selected" : ""}>${item}</option>`).join("")}</select></div></div>
    <div class="field-row"><div class="field"><label>Severity</label><select class="select" name="severity" ${readOnly ? "disabled" : ""}>${["low", "medium", "high", "critical"].map((item) => `<option ${rule.severity === item ? "selected" : ""}>${item}</option>`).join("")}</select></div><label class="check"><input type="checkbox" name="enabled" ${rule.enabled ? "checked" : ""} ${readOnly ? "disabled" : ""}>Rule enabled</label></div>
    <div class="form-actions"><button type="button" class="btn" data-close-modal="true">Close</button>${readOnly ? "" : `<button type="button" class="btn" id="preview-rule">Test</button><button class="btn btn-primary" type="submit">Save and apply</button>`}</div>
  </form>`, { wide: true });
  $$('[data-close-modal]', modalRoot).forEach((button) => button.onclick = closeModal);
  const form = $("#rule-form"); const collect = () => { const values = new FormData(form); return { id: String(values.get("id") || "").trim(), name: String(values.get("name") || "").trim(), description: String(values.get("description") || "").trim(), enabled: values.has("enabled"), targets: values.getAll("target"), pattern: String(values.get("pattern") || ""), score: Number(values.get("score")), action: String(values.get("action")), severity: String(values.get("severity")) }; };
  if (!readOnly) {
    $("#preview-rule").onclick = () => openRuleTest(collect());
    form.onsubmit = async (event) => { event.preventDefault(); try { const next = deepClone(state.rules); if (index === null) next.rules.push(collect()); else next.rules[index] = collect(); await saveRules(next); closeModal(); await navigate("rules", true); } catch (error) { toast(error.message, "error"); } };
  }
}

function openRuleTest(rule) {
  const selected = rule || state.rules?.rules?.[0] || ruleDefaults();
  openModal("Test rule against a synthetic request", `<form id="rule-test-form">
    <div class="notice">Testing runs only against the supplied synthetic request. It does not send traffic to an origin.</div>
    <div class="field"><label>Rule JSON</label><textarea class="textarea code-editor" name="rule">${escapeHTML(JSON.stringify(selected, null, 2))}</textarea></div>
    <div class="field-row"><div class="field"><label>Method</label><input class="input" name="method" value="GET"></div><div class="field"><label>Path</label><input class="input mono" name="path" value="/"></div></div>
    <div class="field"><label>Query string</label><input class="input mono" name="query" placeholder="q=%3Cscript%3Ealert(1)%3C/script%3E"></div>
    <div class="field"><label>Headers (Header: value)</label><textarea class="textarea mono" name="headers">User-Agent: CherryWAF-Rule-Test</textarea></div>
    <div class="field"><label>Body</label><textarea class="textarea mono" name="body"></textarea></div>
    <div id="rule-test-result"></div><div class="form-actions"><button type="button" class="btn" data-close-modal="true">Close</button><button class="btn btn-primary" type="submit">Run test</button></div>
  </form>`, { wide: true });
  $$('[data-close-modal]', modalRoot).forEach((button) => button.onclick = closeModal);
  $("#rule-test-form").onsubmit = async (event) => {
    event.preventDefault(); const values = new FormData(event.currentTarget);
    try {
      const ruleValue = JSON.parse(String(values.get("rule"))); const headerMap = headersFromText(values.get("headers"));
      const decision = await api("/api/v1/rules/test", { method: "POST", body: { rule: ruleValue, test: { method: values.get("method"), path: values.get("path"), query: values.get("query"), headers: headerMap, body: values.get("body") } } });
      $("#rule-test-result").innerHTML = `<div class="notice ${decision.matches?.length ? "warning" : ""}"><strong>${decision.matches?.length ? `${decision.matches.length} match(es)` : "No match"}</strong>&nbsp;Score ${fmtNumber(decision.score)} · ${decision.blocked ? "Would block" : "Would not block"}</div><pre class="code-preview">${escapeHTML(JSON.stringify(decision, null, 2))}</pre>`;
    } catch (error) { toast(error.message, "error"); }
  };
}

async function renderNetwork(content) {
  content.innerHTML = page("Network setup", "Configure Netplan through a root helper with a mandatory automatic rollback window.");
  const result = await api("/api/v1/network"); const interfaces = (result.interfaces || []).filter((item) => item.name !== "lo"); const helper = result.helper || {}; const pending = helper.pending || [];
  $("#page-body").innerHTML = `${!result.helper_available ? `<div class="notice danger"><strong>Network helper unavailable.</strong>&nbsp;${escapeHTML(result.helper_error || "Check cherrywaf-netd.socket.")}</div>` : ""}
    ${pending.length ? pending.map((item) => `<section class="card card-pad pending-banner"><div class="split"><div><h3 class="section-title">Unconfirmed network change</h3><div class="small muted">Interface ${escapeHTML(item.plan?.interface)} · rollback deadline ${fmtDate(item.confirm_by)}</div></div><div class="inline"><span class="countdown" data-deadline="${escapeAttr(item.confirm_by)}">Calculating…</span>${can("admin") ? `<button class="btn btn-success" data-confirm-network="${escapeAttr(item.token)}">Confirm</button><button class="btn btn-danger" data-rollback-network="${escapeAttr(item.token)}">Roll back now</button>` : ""}</div></div></section>`).join("") : ""}
    <div class="grid two mt-16"><section class="card"><header class="card-head"><div><h3>Detected interfaces</h3><p>Current addresses as reported by the appliance.</p></div></header><div class="card-body">${interfaces.length ? interfaces.map((item) => `<div class="kv"><span>${escapeHTML(item.name)}</span><span><strong>${escapeHTML((item.addresses || []).join(", ") || "No address")}</strong><div class="small muted">${escapeHTML(item.hardware_address || "No MAC")} · MTU ${fmtNumber(item.mtu)}</div></span></div>`).join("") : `<div class="empty">No configurable interface detected.</div>`}</div></section>
    <section class="card"><header class="card-head"><div><h3>Network plan</h3><p>Changes roll back automatically unless confirmed.</p></div></header><div class="card-body"><form id="network-form">
      <div class="field"><label>Interface</label><select class="select" name="interface" ${!can("admin") ? "disabled" : ""}>${interfaces.map((item) => `<option value="${escapeAttr(item.name)}">${escapeHTML(item.name)} · ${escapeHTML((item.addresses || []).join(", ") || "unconfigured")}</option>`).join("")}</select></div>
      <label class="check"><input type="checkbox" name="dhcp4" checked ${!can("admin") ? "disabled" : ""}>Use IPv4 DHCP</label>
      <div class="field mt-16"><label>Static addresses (CIDR)</label><textarea class="textarea mono" name="addresses" placeholder="192.168.1.50/24" ${!can("admin") ? "disabled" : ""}></textarea></div>
      <div class="field-row"><div class="field"><label>Default gateway</label><input class="input mono" name="gateway4" placeholder="192.168.1.1" ${!can("admin") ? "disabled" : ""}></div><div class="field"><label>MTU</label><input class="input" type="number" min="576" max="9216" name="mtu" value="1500" ${!can("admin") ? "disabled" : ""}></div></div>
      <div class="field"><label>DNS servers</label><textarea class="textarea mono" name="nameservers" ${!can("admin") ? "disabled" : ""}>1.1.1.1\n8.8.8.8</textarea></div>
      ${can("admin") ? `<div class="form-actions"><button class="btn" type="button" id="validate-network">Preview Netplan</button><button class="btn btn-primary" type="submit" ${!result.helper_available || !interfaces.length ? "disabled" : ""}>Apply with rollback</button></div>` : ""}
    </form></div></section></div>`;
  const countdown = () => $$('[data-deadline]').forEach((item) => { const seconds = Math.max(0, Math.ceil((new Date(item.dataset.deadline).getTime() - Date.now()) / 1000)); item.textContent = seconds ? `${seconds}s to confirm` : "Rollback due"; }); countdown(); const timer = setInterval(countdown, 1000); setTimeout(() => clearInterval(timer), 65000);
  $$('[data-confirm-network]').forEach((button) => button.onclick = async () => { await api("/api/v1/network/confirm", { method: "POST", body: { token: button.dataset.confirmNetwork } }); toast("Network change confirmed."); await renderNetwork(content); });
  $$('[data-rollback-network]').forEach((button) => button.onclick = async () => { await api("/api/v1/network/rollback", { method: "POST", body: { token: button.dataset.rollbackNetwork } }); toast("Network configuration rolled back."); await renderNetwork(content); });
  if (can("admin")) {
    const form = $("#network-form"); const plan = () => { const values = new FormData(form); return { version: 1, interface: values.get("interface"), dhcp4: values.has("dhcp4"), addresses: listValue(values.get("addresses")), gateway4: String(values.get("gateway4") || "").trim(), nameservers: listValue(values.get("nameservers")), mtu: Number(values.get("mtu")) || 0 }; };
    $("#validate-network").onclick = async () => { try { const preview = await api("/api/v1/network/validate", { method: "POST", body: plan() }); openModal("Netplan preview", `<pre class="code-preview">${escapeHTML(preview.netplan)}</pre><div class="form-actions"><button class="btn" data-close-modal="true">Close</button></div>`); $$('[data-close-modal]', modalRoot).forEach((button) => button.onclick = closeModal); } catch (error) { toast(error.message, "error"); } };
    form.onsubmit = async (event) => { event.preventDefault(); if (!confirm("Apply this network plan? You must reconnect and confirm within 60 seconds or it will roll back automatically.")) return; try { const applied = await api("/api/v1/network/apply", { method: "POST", body: plan() }); toast(applied.message); await renderNetwork(content); } catch (error) { toast(error.message, "error"); } };
  }
}

async function renderRecovery(content) {
  content.innerHTML = page("Backup and rollback", "Create portable configuration backups or restore an automatically captured safety revision.", `<button class="btn btn-primary" id="create-backup">Create backup</button>`);
  const [backupResult, revisionResult] = await Promise.all([api("/api/v1/backups"), api("/api/v1/revisions")]); const backups = backupResult.backups || []; const revisions = revisionResult.revisions || [];
  $("#page-body").innerHTML = `<div class="notice">Backups include the WAF configuration and GUI rule file. Private keys, users, password hashes, audit events, and sessions are intentionally excluded.</div>
  <div class="grid two"><section class="card"><header class="card-head"><div><h3>Portable backups</h3><p>Manual ZIP snapshots stored on the appliance.</p></div></header><div class="table-wrap"><table><thead><tr><th>Created</th><th>Actor</th><th>Size</th><th></th></tr></thead><tbody>${backups.length ? backups.map((item) => `<tr><td><strong>${fmtDate(item.created_at)}</strong><div class="small muted mono">${escapeHTML(item.id)}</div></td><td>${escapeHTML(item.actor)}</td><td>${bytes(item.size)}</td><td><div class="actions"><a class="btn btn-sm" href="/api/v1/backups/${encodeURIComponent(item.id)}/download">Download</a><button class="btn btn-sm btn-success" data-restore-backup="${escapeAttr(item.id)}">Restore</button><button class="btn btn-sm btn-danger" data-delete-backup="${escapeAttr(item.id)}">Delete</button></div></td></tr>`).join("") : `<tr><td colspan="4"><div class="empty"><strong>No backups</strong>Create one before the next ambitious configuration experiment.</div></td></tr>`}</tbody></table></div></section>
  <section class="card"><header class="card-head"><div><h3>Safety revisions</h3><p>Captured automatically before every apply operation.</p></div></header><div class="table-wrap"><table><thead><tr><th>Created</th><th>Reason</th><th>Actor</th><th></th></tr></thead><tbody>${revisions.length ? revisions.map((item) => `<tr><td><strong>${fmtDate(item.created_at)}</strong><div class="small muted mono">${escapeHTML(item.id)}</div></td><td>${escapeHTML(item.reason)} ${item.restart_required ? statusBadge("Restart", "amber") : ""}</td><td>${escapeHTML(item.actor)}</td><td><button class="btn btn-sm btn-success" data-restore-revision="${escapeAttr(item.id)}">Restore</button></td></tr>`).join("") : `<tr><td colspan="4"><div class="empty">No safety revisions yet.</div></td></tr>`}</tbody></table></div></section></div>`;
  $("#create-backup").onclick = async () => { await api("/api/v1/backups", { method: "POST" }); toast("Backup created."); await renderRecovery(content); };
  $$('[data-restore-backup]').forEach((button) => button.onclick = async () => { if (!confirm("Restore this backup and reload the WAF?")) return; const result = await api(`/api/v1/backups/${encodeURIComponent(button.dataset.restoreBackup)}/restore`, { method: "POST" }); toast(result.result?.restart_required ? "Backup restored; restart required." : "Backup restored."); state.config = null; await renderRecovery(content); });
  $$('[data-delete-backup]').forEach((button) => button.onclick = async () => { if (!confirm("Delete this backup?")) return; await api(`/api/v1/backups/${encodeURIComponent(button.dataset.deleteBackup)}`, { method: "DELETE" }); toast("Backup deleted."); await renderRecovery(content); });
  $$('[data-restore-revision]').forEach((button) => button.onclick = async () => { if (!confirm("Restore this safety revision?")) return; const result = await api(`/api/v1/revisions/${encodeURIComponent(button.dataset.restoreRevision)}/restore`, { method: "POST" }); toast(result.restart_required ? "Revision restored; restart required." : "Revision restored."); state.config = null; await renderRecovery(content); });
}

async function renderUsers(content) {
  content.innerHTML = page("Users and roles", "Manage local Control Center identities and least-privilege access.", `<button class="btn btn-primary" id="add-user">Add user</button>`);
  const result = await api("/api/v1/users"); const users = result.users || [];
  $("#page-body").innerHTML = `<div class="card"><div class="table-wrap"><table><thead><tr><th>User</th><th>Role</th><th>Status</th><th>Last login</th><th>Updated</th><th></th></tr></thead><tbody>${users.map((user) => `<tr><td><strong>${escapeHTML(user.display_name)}</strong><div class="small muted mono">${escapeHTML(user.username)}</div></td><td>${statusBadge(user.role, user.role === "admin" ? "red" : user.role === "operator" ? "amber" : "blue")}</td><td>${user.disabled ? statusBadge("Disabled", "red") : statusBadge("Active", "green")}</td><td>${fmtDate(user.last_login_at)}</td><td>${fmtDate(user.updated_at)}</td><td><div class="actions"><button class="btn btn-sm" data-edit-user="${escapeAttr(user.id)}">Edit</button>${user.id !== state.user.id ? `<button class="btn btn-sm btn-danger" data-delete-user="${escapeAttr(user.id)}">Delete</button>` : ""}</div></td></tr>`).join("")}</tbody></table></div></div>`;
  $("#add-user").onclick = () => openUserEditor(null, users);
  $$('[data-edit-user]').forEach((button) => button.onclick = () => openUserEditor(users.find((item) => item.id === button.dataset.editUser), users));
  $$('[data-delete-user]').forEach((button) => button.onclick = async () => { const user = users.find((item) => item.id === button.dataset.deleteUser); if (!confirm(`Delete user ${user.username}?`)) return; await api(`/api/v1/users/${encodeURIComponent(user.id)}`, { method: "DELETE" }); toast("User deleted."); await renderUsers(content); });
}

function openUserEditor(user) {
  const creating = !user; const current = user || { username: "", display_name: "", role: "viewer", disabled: false };
  openModal(creating ? "Add user" : `Edit ${current.username}`, `<form id="user-form">
    <div class="field-row"><div class="field"><label>Username</label><input class="input" name="username" value="${escapeAttr(current.username)}" required ${creating ? "" : "disabled"}></div><div class="field"><label>Display name</label><input class="input" name="display_name" value="${escapeAttr(current.display_name)}" required></div></div>
    <div class="field"><label>Role</label><select class="select" name="role">${["viewer", "operator", "admin"].map((role) => `<option value="${role}" ${current.role === role ? "selected" : ""}>${role}</option>`).join("")}</select></div>
    <div class="field"><label>${creating ? "Password" : "New password (leave blank to retain)"}</label><input class="input" type="password" name="password" ${creating ? "required" : ""} minlength="12" autocomplete="new-password"><small>At least 12 characters with upper/lowercase, number, and symbol.</small></div>
    ${creating ? "" : `<label class="check"><input type="checkbox" name="disabled" ${current.disabled ? "checked" : ""}>Disable account</label>`}
    <div class="form-actions"><button type="button" class="btn" data-close-modal="true">Cancel</button><button class="btn btn-primary" type="submit">Save user</button></div>
  </form>`);
  $$('[data-close-modal]', modalRoot).forEach((button) => button.onclick = closeModal);
  $("#user-form").onsubmit = async (event) => { event.preventDefault(); const values = new FormData(event.currentTarget); try {
    const body = { username: values.get("username") || current.username, display_name: values.get("display_name"), password: values.get("password"), role: values.get("role"), disabled: values.has("disabled") };
    if (creating) { delete body.disabled; await api("/api/v1/users", { method: "POST", body }); } else { delete body.username; await api(`/api/v1/users/${encodeURIComponent(current.id)}`, { method: "PUT", body }); }
    toast(creating ? "User created." : "User updated."); closeModal(); await navigate("users", true);
  } catch (error) { toast(error.message, "error"); } };
}

async function renderAudit(content) {
  content.innerHTML = page("Audit log", "Review authentication, policy, certificate, network, user, backup, and rollback activity.");
  const result = await api("/api/v1/audit?limit=500"); const events = result.events || [];
  $("#page-body").innerHTML = `<div class="card"><div class="table-wrap"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Resource</th><th>Outcome</th><th>Remote IP</th></tr></thead><tbody>${events.length ? events.map((item) => `<tr><td>${fmtDate(item.timestamp)}</td><td><strong>${escapeHTML(item.actor)}</strong><div class="small muted">${escapeHTML(item.role || "")}</div></td><td class="mono">${escapeHTML(item.action)}</td><td>${escapeHTML(item.resource)}</td><td>${statusBadge(item.outcome, item.outcome === "success" ? "green" : "red")}</td><td class="mono">${escapeHTML(item.remote_ip || "local")}</td></tr>`).join("") : `<tr><td colspan="6"><div class="empty">No audit events.</div></td></tr>`}</tbody></table></div></div>`;
}

async function renderRawConfig(content, force = false) {
  content.innerHTML = page("Raw configuration", "Advanced JSON editor with strict schema validation, safety snapshots, atomic writes, and automatic rollback.");
  const config = await loadConfig(force);
  $("#page-body").innerHTML = `<section class="card"><header class="card-head"><div><h3>cherrywaf.json</h3><p>Unknown fields are rejected instead of being silently ignored.</p></div></header><div class="card-body"><textarea id="raw-config" class="textarea code-editor">${escapeHTML(JSON.stringify(config, null, 2))}</textarea><div id="config-validation"></div><div class="form-actions"><button class="btn" id="validate-config">Validate</button><button class="btn btn-primary" id="apply-config">Validate and apply</button></div></div></section>`;
  const parseEditor = () => JSON.parse($("#raw-config").value);
  $("#validate-config").onclick = async () => { try { const result = await api("/api/v1/config/validate", { method: "POST", body: parseEditor() }); $("#config-validation").innerHTML = `<div class="notice mt-16"><strong>Valid configuration.</strong>&nbsp;${fmtNumber(result.result?.rule_count)} rules · ${fmtNumber(result.result?.domains?.length)} domains</div>`; } catch (error) { $("#config-validation").innerHTML = `<div class="notice danger mt-16">${escapeHTML(error.message)}</div>`; } };
  $("#apply-config").onclick = async () => { try { const parsed = parseEditor(); await saveConfig(parsed, "Raw configuration applied"); await renderRawConfig(content, true); } catch (error) { toast(error.message, "error"); } };
}

boot();
