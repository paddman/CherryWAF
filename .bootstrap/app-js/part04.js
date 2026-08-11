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
