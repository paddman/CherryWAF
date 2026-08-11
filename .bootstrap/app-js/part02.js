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
