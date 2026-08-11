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
  $$('[data-route]').forEach((button) => button.addEventListener("click", () => { location.hash = button.dataset.route; $("#sidebar").classList.remove("open"); }));
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
