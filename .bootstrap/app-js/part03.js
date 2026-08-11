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
