(() => {
  const deliveryIndex = Math.max(1, routes.findIndex((item) => item.id === "policy"));
  routes.splice(deliveryIndex, 0,
    { id: "server-pools", label: "Server Pools", icon: "SP", group: "Delivery", min: "viewer" },
    { id: "virtual-services", label: "Virtual Services", icon: "VS", group: "Delivery", min: "viewer" },
  );
  const protectionIndex = routes.findIndex((item) => item.id === "certificates");
  routes.splice(protectionIndex < 0 ? routes.length : protectionIndex, 0,
    { id: "threat-intel", label: "Threat Intelligence", icon: "TI", group: "Protect", min: "viewer" },
  );

  const advancedHandlers = {
    "server-pools": renderServerPools,
    "virtual-services": renderVirtualServices,
    "threat-intel": renderThreatIntelligence,
  };
  const standardNavigate = navigate;
  navigate = async function adcNavigate(route, force = false) {
    if (!advancedHandlers[route]) return standardNavigate(route, force);
    const descriptor = routes.find((item) => item.id === route && can(item.min)) || routes.find((item) => item.id === "dashboard");
    if (!advancedHandlers[descriptor.id]) return standardNavigate(descriptor.id, force);
    state.route = descriptor.id;
    if (location.hash.slice(1) !== descriptor.id) history.replaceState(null, "", `#${descriptor.id}`);
    $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.route === descriptor.id));
    $("#top-title").textContent = descriptor.label;
    const content = $("#content");
    content.innerHTML = loading();
    try { await advancedHandlers[descriptor.id](content, force); }
    catch (error) {
      if (error.status === 401) return renderLogin("Your session expired.");
      content.innerHTML = `<div class="notice danger">${escapeHTML(error.message)}</div>`;
      toast(error.message, "error");
    }
  };

  function ensureADCDefaults(config) {
    config.server_pools = Array.isArray(config.server_pools) ? config.server_pools : [];
    config.security = config.security || {};
    config.security.reputation = config.security.reputation || { enabled: false, mode: "monitor", entries: [], files: [] };
    for (const host of config.virtual_hosts || []) normalizeVirtualService(host);
    return config;
  }

  function normalizeVirtualService(host) {
    host.action = host.action || "group";
    host.redirect = host.redirect || { url: "", status: 302 };
    host.discard_status = host.discard_status || 403;
    host.persistence = host.persistence || { mode: "none", cookie_name: "CWAF_ROUTE", ttl_seconds: 3600 };
    host.waf_policy = host.waf_policy || { mode: "inherit", block_threshold: 0, max_body_bytes: 0, fail_mode: "closed", allow_cidrs: [], deny_cidrs: [], rule_files: [] };
    host.waf_policy.fail_mode = host.waf_policy.fail_mode || "closed";
    host.bot_policy = host.bot_policy || { enabled: false, mode: "monitor", requests_per_minute: 300, burst: 60, bad_user_agents: [], allow_user_agents: [] };
    host.content_routes = Array.isArray(host.content_routes) ? host.content_routes : [];
    host.request_headers = host.request_headers || {};
    host.response_headers = host.response_headers || {};
    host.frontend_tls = host.frontend_tls || { certificate_file: "", private_key_file: "" };
    host.origin_tls = host.origin_tls || { server_name: "", ca_file: "", insecure_skip_verify: false };
    return host;
  }

  function poolDefaults() {
    return {
      name: `pool-${Date.now().toString().slice(-6)}`,
      enabled: true,
      algorithm: "round_robin",
      failure_mode: "reject",
      members: [{ id: "origin-1", url: "http://127.0.0.1:8080", enabled: true, weight: 1, priority: 100, backup: false, origin_tls: { server_name: "", ca_file: "", insecure_skip_verify: false } }],
      health_check: { enabled: true, type: "http", interval_seconds: 10, timeout_seconds: 3, healthy_threshold: 2, unhealthy_threshold: 3, method: "GET", path: "/healthz", host: "", expected_status_min: 200, expected_status_max: 399 },
    };
  }

  function runtimePoolMap(runtime) {
    const result = new Map();
    for (const route of runtime?.routes || []) {
      for (const pool of route.pools || []) {
        if (!result.has(pool.name)) result.set(pool.name, pool);
      }
    }
    return result;
  }

  async function renderServerPools(content, force = false) {
    content.innerHTML = page("Server pools", "Build multi-origin groups with load balancing, active health checks, backup members, persistence, and passive failover.", can("admin") ? `<button class="btn btn-primary" id="add-pool">Add server pool</button>` : "");
    const config = ensureADCDefaults(await loadConfig(force));
    let runtime = {};
    try { runtime = (await api("/api/v1/dashboard")).runtime || {}; } catch (_) {}
    const health = runtimePoolMap(runtime);
    const pools = config.server_pools || [];
    $("#page-body").innerHTML = pools.length ? `<div class="adc-pool-grid">${pools.map((pool, index) => {
      const status = health.get(pool.name);
      const healthy = status?.healthy_members ?? "–";
      const total = status?.total_members ?? pool.members?.filter((member) => member.enabled).length ?? 0;
      const stateBadge = !pool.enabled ? statusBadge("Disabled", "amber") : status && status.healthy_members === 0 ? statusBadge("No healthy origin", "red") : statusBadge("Enabled", "green");
      return `<article class="card adc-pool-card">
        <header class="card-head"><div><h3>${escapeHTML(pool.name)}</h3><p>${escapeHTML(pool.algorithm || "round_robin")} · ${escapeHTML(pool.failure_mode || "reject")}</p></div>${stateBadge}</header>
        <div class="card-body">
          <div class="adc-health-number"><strong>${escapeHTML(String(healthy))}</strong><span>/ ${escapeHTML(String(total))} healthy</span></div>
          <div class="adc-member-list">${(status?.members || pool.members || []).map((member) => `<div class="adc-member"><span class="health-dot ${member.healthy === false ? "bad" : member.healthy === true ? "" : "unknown"}"></span><div><strong>${escapeHTML(member.id)}</strong><span class="mono">${escapeHTML(member.url)}</span></div><small>${member.backup ? "backup" : "primary"} · w${fmtNumber(member.weight || 1)}${member.active_connections !== undefined ? ` · ${fmtNumber(member.active_connections)} active` : ""}</small></div>`).join("")}</div>
        </div>
        <footer class="app-card-actions"><button class="btn btn-sm" data-edit-pool="${index}">${can("admin") ? "Edit" : "View"}</button>${can("admin") ? `<button class="btn btn-sm btn-danger" data-delete-pool="${index}">Delete</button>` : ""}</footer>
      </article>`;
    }).join("")}</div>` : `<div class="card"><div class="empty"><strong>No server pools</strong>Create a pool before assigning multiple origins. One lonely upstream is not load balancing, however optimistic its marketing department may be.</div></div>`;
    if (can("admin")) $("#add-pool").onclick = () => openPoolEditor(null);
    $$('[data-edit-pool]').forEach((button) => button.onclick = () => openPoolEditor(Number(button.dataset.editPool)));
    $$('[data-delete-pool]').forEach((button) => button.onclick = async () => {
      const index = Number(button.dataset.deletePool);
      const pool = state.config.server_pools[index];
      const users = (state.config.virtual_hosts || []).filter((host) => host.server_pool === pool.name || (host.content_routes || []).some((route) => route.pool === pool.name));
      if (users.length) return toast(`Pool is still used by: ${users.map((item) => item.name).join(", ")}`, "error");
      if (!confirm(`Delete server pool ${pool.name}?`)) return;
      const next = deepClone(state.config); next.server_pools.splice(index, 1);
      await saveConfig(next, "Server pool removed");
      await renderServerPools(content, true);
    });
  }

  function memberEditorRow(member = {}, index = 0) {
    return `<div class="adc-member-row" data-member-row>
      <input class="input" data-field="id" value="${escapeAttr(member.id || `origin-${index + 1}`)}" placeholder="Member ID" required>
      <input class="input mono adc-url" data-field="url" value="${escapeAttr(member.url || "http://127.0.0.1:8080")}" placeholder="http://10.0.0.10:8080" required>
      <input class="input" type="number" min="1" max="1000" data-field="weight" value="${escapeAttr(member.weight || 1)}" title="Weight">
      <input class="input" type="number" min="1" max="1000" data-field="priority" value="${escapeAttr(member.priority || 100)}" title="Priority">
      <label class="check compact"><input type="checkbox" data-field="backup" ${member.backup ? "checked" : ""}>Backup</label>
      <label class="check compact"><input type="checkbox" data-field="enabled" ${member.enabled !== false ? "checked" : ""}>Enabled</label>
      <button class="btn btn-sm btn-danger" type="button" data-remove-member>×</button>
      <div class="adc-member-tls">
        <input class="input" data-field="server_name" value="${escapeAttr(member.origin_tls?.server_name || "")}" placeholder="Origin TLS server name">
        <input class="input mono" data-field="ca_file" value="${escapeAttr(member.origin_tls?.ca_file || "")}" placeholder="Custom CA file (optional)">
        <label class="check compact"><input type="checkbox" data-field="insecure" ${member.origin_tls?.insecure_skip_verify ? "checked" : ""}>Skip verify</label>
      </div>
    </div>`;
  }

  async function openPoolEditor(index) {
    const readOnly = !can("admin");
    const config = ensureADCDefaults(await loadConfig());
    const original = index === null ? poolDefaults() : deepClone(config.server_pools[index]);
    original.health_check = { ...poolDefaults().health_check, ...(original.health_check || {}) };
    openModal(index === null ? "Add server pool" : `${readOnly ? "View" : "Edit"} server pool`, `<form id="pool-form">
      <div class="field-row"><div class="field"><label>Pool name</label><input class="input" name="name" value="${escapeAttr(original.name)}" required ${readOnly ? "disabled" : ""}></div><div class="field"><label>Algorithm</label><select class="select" name="algorithm" ${readOnly ? "disabled" : ""}>${["round_robin", "weighted_round_robin", "least_connections", "source_ip_hash", "primary_backup", "random"].map((item) => `<option value="${item}" ${original.algorithm === item ? "selected" : ""}>${item.replaceAll("_", " ")}</option>`).join("")}</select></div></div>
      <div class="field-row"><label class="check"><input type="checkbox" name="enabled" ${original.enabled ? "checked" : ""} ${readOnly ? "disabled" : ""}>Enable pool</label><div class="field"><label>When every member is unhealthy</label><select class="select" name="failure_mode" ${readOnly ? "disabled" : ""}><option value="reject" ${original.failure_mode !== "last_resort" ? "selected" : ""}>Reject with 503</option><option value="last_resort" ${original.failure_mode === "last_resort" ? "selected" : ""}>Try unhealthy members as last resort</option></select></div></div>
      <div class="split mt-16"><h3 class="section-title">Pool members</h3>${readOnly ? "" : `<button type="button" class="btn btn-sm" id="add-pool-member">Add member</button>`}</div>
      <div class="adc-member-editor-head"><span>ID</span><span>URL</span><span>Weight</span><span>Priority</span><span>Role</span><span>State</span><span></span></div>
      <div id="pool-members">${(original.members || []).map(memberEditorRow).join("")}</div>
      <h3 class="section-title mt-16">Active health check</h3>
      <div class="field-row"><label class="check"><input type="checkbox" name="health_enabled" ${original.health_check.enabled ? "checked" : ""} ${readOnly ? "disabled" : ""}>Enable health monitor</label><div class="field"><label>Type</label><select class="select" name="health_type" ${readOnly ? "disabled" : ""}><option value="http" ${original.health_check.type !== "tcp" ? "selected" : ""}>HTTP</option><option value="tcp" ${original.health_check.type === "tcp" ? "selected" : ""}>TCP connect</option></select></div></div>
      <div class="grid four"><div class="field"><label>Interval (s)</label><input class="input" type="number" min="2" max="3600" name="interval" value="${escapeAttr(original.health_check.interval_seconds)}" ${readOnly ? "disabled" : ""}></div><div class="field"><label>Timeout (s)</label><input class="input" type="number" min="1" max="60" name="timeout" value="${escapeAttr(original.health_check.timeout_seconds)}" ${readOnly ? "disabled" : ""}></div><div class="field"><label>Healthy threshold</label><input class="input" type="number" min="1" max="20" name="healthy" value="${escapeAttr(original.health_check.healthy_threshold)}" ${readOnly ? "disabled" : ""}></div><div class="field"><label>Unhealthy threshold</label><input class="input" type="number" min="1" max="20" name="unhealthy" value="${escapeAttr(original.health_check.unhealthy_threshold)}" ${readOnly ? "disabled" : ""}></div></div>
      <div class="field-row"><div class="field"><label>HTTP method</label><select class="select" name="method" ${readOnly ? "disabled" : ""}><option ${original.health_check.method === "GET" ? "selected" : ""}>GET</option><option ${original.health_check.method === "HEAD" ? "selected" : ""}>HEAD</option></select></div><div class="field"><label>Path</label><input class="input mono" name="path" value="${escapeAttr(original.health_check.path)}" ${readOnly ? "disabled" : ""}></div><div class="field"><label>Host override</label><input class="input" name="host" value="${escapeAttr(original.health_check.host || "")}" ${readOnly ? "disabled" : ""}></div></div>
      <div class="field-row"><div class="field"><label>Expected status from</label><input class="input" type="number" min="100" max="599" name="status_min" value="${escapeAttr(original.health_check.expected_status_min)}" ${readOnly ? "disabled" : ""}></div><div class="field"><label>Expected status through</label><input class="input" type="number" min="100" max="599" name="status_max" value="${escapeAttr(original.health_check.expected_status_max)}" ${readOnly ? "disabled" : ""}></div></div>
      <div class="notice mt-16">TLS verification is enabled by default. “Skip verify” exists for controlled migrations, not as a ceremonial checkbox to make red warnings disappear.</div>
      <div class="form-actions"><button type="button" class="btn" data-close-modal="true">Close</button>${readOnly ? "" : `<button class="btn btn-primary" type="submit">Validate and apply</button>`}</div>
    </form>`, { wide: true });
    $$('[data-close-modal]', modalRoot).forEach((button) => button.onclick = closeModal);
    const membersRoot = $("#pool-members");
    const bindRemove = () => $$('[data-remove-member]', membersRoot).forEach((button) => button.onclick = () => button.closest("[data-member-row]").remove());
    bindRemove();
    if (!readOnly) {
      $("#add-pool-member").onclick = () => { membersRoot.insertAdjacentHTML("beforeend", memberEditorRow({}, $$('[data-member-row]', membersRoot).length)); bindRemove(); };
      $("#pool-form").onsubmit = async (event) => {
        event.preventDefault();
        const values = new FormData(event.currentTarget);
        const members = $$('[data-member-row]', membersRoot).map((row) => ({
          id: row.querySelector('[data-field="id"]').value.trim(),
          url: row.querySelector('[data-field="url"]').value.trim(),
          enabled: row.querySelector('[data-field="enabled"]').checked,
          weight: Number(row.querySelector('[data-field="weight"]').value),
          priority: Number(row.querySelector('[data-field="priority"]').value),
          backup: row.querySelector('[data-field="backup"]').checked,
          origin_tls: {
            server_name: row.querySelector('[data-field="server_name"]').value.trim(),
            ca_file: row.querySelector('[data-field="ca_file"]').value.trim(),
            insecure_skip_verify: row.querySelector('[data-field="insecure"]').checked,
          },
        }));
        const pool = {
          name: String(values.get("name") || "").trim(), enabled: values.has("enabled"), algorithm: String(values.get("algorithm")), failure_mode: String(values.get("failure_mode")), members,
          health_check: { enabled: values.has("health_enabled"), type: String(values.get("health_type")), interval_seconds: Number(values.get("interval")), timeout_seconds: Number(values.get("timeout")), healthy_threshold: Number(values.get("healthy")), unhealthy_threshold: Number(values.get("unhealthy")), method: String(values.get("method")), path: String(values.get("path") || "").trim(), host: String(values.get("host") || "").trim(), expected_status_min: Number(values.get("status_min")), expected_status_max: Number(values.get("status_max")) },
        };
        try {
          const next = deepClone(config);
          if (index === null) next.server_pools.push(pool);
          else {
            const previousName = next.server_pools[index].name;
            next.server_pools[index] = pool;
            if (previousName !== pool.name) {
              for (const host of next.virtual_hosts || []) {
                if (host.server_pool === previousName) host.server_pool = pool.name;
                for (const route of host.content_routes || []) if (route.pool === previousName) route.pool = pool.name;
              }
            }
          }
          await saveConfig(next, "Server pool updated"); closeModal(); await navigate("server-pools", true);
        } catch (error) { toast(error.message, "error"); }
      };
    }
  }

  function serviceDefaults() {
    return normalizeVirtualService({
      name: "", enabled: true, domains: [], action: "group", upstream: "http://127.0.0.1:8080", server_pool: "", redirect: { url: "https://{host}{request_uri}", status: 302 }, discard_status: 403,
      preserve_host: true, frontend_tls: { certificate_file: "", private_key_file: "" }, origin_tls: { server_name: "", ca_file: "", insecure_skip_verify: false },
      persistence: { mode: "none", cookie_name: "CWAF_ROUTE", ttl_seconds: 3600 }, waf_policy: { mode: "inherit", block_threshold: 0, max_body_bytes: 0, fail_mode: "closed", allow_cidrs: [], deny_cidrs: [], rule_files: [] },
      bot_policy: { enabled: false, mode: "monitor", requests_per_minute: 300, burst: 60, bad_user_agents: ["(?i)\\b(?:curl|wget|python-requests|scrapy|headlesschrome)\\b"], allow_user_agents: [] }, content_routes: [], request_headers: {}, response_headers: { "X-Content-Type-Options": "nosniff" },
    });
  }

  async function renderVirtualServices(content, force = false) {
    content.innerHTML = page("Virtual services", "Bind domains to a server pool, redirect, or discard action and attach application-specific WAF, bot, persistence, access, and content-routing policies.", can("admin") ? `<button class="btn btn-primary" id="add-virtual-service">Add virtual service</button>` : "");
    const config = ensureADCDefaults(await loadConfig(force));
    const pools = new Map((config.server_pools || []).map((pool) => [pool.name, pool]));
    const hosts = config.virtual_hosts || [];
    $("#page-body").innerHTML = `<div class="card"><div class="table-wrap"><table><thead><tr><th>State</th><th>Virtual service</th><th>Domains</th><th>Action / target</th><th>WAF</th><th>Bot</th><th>Persistence</th><th></th></tr></thead><tbody>${hosts.length ? hosts.map((host, index) => {
      normalizeVirtualService(host);
      const target = host.action === "group" ? (host.server_pool ? `Pool: ${host.server_pool}` : host.upstream) : host.action === "redirect" ? `${host.redirect?.status || 302} → ${host.redirect?.url || ""}` : `HTTP ${host.discard_status || 403}`;
      const pool = host.server_pool ? pools.get(host.server_pool) : null;
      return `<tr><td>${host.enabled ? statusBadge("Enabled", "green") : statusBadge("Disabled", "amber")}</td><td><strong>${escapeHTML(host.name)}</strong><div class="small muted">${escapeHTML(host.action)}</div></td><td class="mono">${escapeHTML((host.domains || []).join(", "))}</td><td><strong>${escapeHTML(target)}</strong>${pool ? `<div class="small muted">${escapeHTML(pool.algorithm)} · ${fmtNumber(pool.members?.length || 0)} members</div>` : ""}</td><td>${statusBadge(host.waf_policy?.mode || "inherit", host.waf_policy?.mode === "blocking" ? "red" : "blue")}</td><td>${host.bot_policy?.enabled ? statusBadge(host.bot_policy.mode || "monitor", host.bot_policy.mode === "block" ? "red" : "amber") : statusBadge("Off", "blue")}</td><td>${escapeHTML(host.persistence?.mode || "none")}</td><td><div class="actions"><button class="btn btn-sm" data-edit-service="${index}">${can("admin") ? "Edit" : "View"}</button>${can("admin") ? `<button class="btn btn-sm btn-danger" data-delete-service="${index}">Delete</button>` : ""}</div></td></tr>`;
    }).join("") : `<tr><td colspan="8"><div class="empty"><strong>No virtual services</strong>Add a protected domain, route action, and policy binding.</div></td></tr>`}</tbody></table></div></div>`;
    if (can("admin")) $("#add-virtual-service").onclick = () => openVirtualServiceEditor(null);
    $$('[data-edit-service]').forEach((button) => button.onclick = () => openVirtualServiceEditor(Number(button.dataset.editService)));
    $$('[data-delete-service]').forEach((button) => button.onclick = async () => { const index = Number(button.dataset.deleteService); const host = state.config.virtual_hosts[index]; if (!confirm(`Delete virtual service ${host.name}?`)) return; const next = deepClone(state.config); next.virtual_hosts.splice(index, 1); if (!next.virtual_hosts.length && next.https?.enabled) { next.https.enabled = false; next.http.enabled = true; next.http.redirect_to_https = false; } await saveConfig(next, "Virtual service removed"); await renderVirtualServices(content, true); });
  }

  async function openVirtualServiceEditor(index) {
    const readOnly = !can("admin");
    const config = ensureADCDefaults(await loadConfig());
    const original = index === null ? serviceDefaults() : normalizeVirtualService(deepClone(config.virtual_hosts[index]));
    let certs = [];
    try { certs = (await api("/api/v1/certificates")).certificates || []; } catch (_) {}
    const selectedCert = certs.find((item) => item.certificate_file === original.frontend_tls?.certificate_file)?.domain || "";
    const poolOptions = `<option value="">Direct upstream (legacy single origin)</option>${(config.server_pools || []).map((pool) => `<option value="${escapeAttr(pool.name)}" ${original.server_pool === pool.name ? "selected" : ""}>${escapeHTML(pool.name)} · ${escapeHTML(pool.algorithm)}</option>`).join("")}`;
    const certOptions = `<option value="">Manual paths / no managed certificate</option>${certs.map((item) => `<option value="${escapeAttr(item.domain)}" ${selectedCert === item.domain ? "selected" : ""}>${escapeHTML(item.domain)} (${item.days_left} days)</option>`).join("")}`;
    openModal(index === null ? "Add virtual service" : `${readOnly ? "View" : "Edit"} virtual service`, `<form id="virtual-service-form">
      <div class="field-row"><div class="field"><label>Virtual service ID</label><input class="input" name="name" value="${escapeAttr(original.name)}" required ${readOnly ? "disabled" : ""}></div><div class="field"><label>Action</label><select class="select" name="action" ${readOnly ? "disabled" : ""}>${["group", "redirect", "discard"].map((item) => `<option value="${item}" ${original.action === item ? "selected" : ""}>${item}</option>`).join("")}</select></div></div>
      <div class="field"><label>Domains</label><textarea class="textarea mono" name="domains" required ${readOnly ? "disabled" : ""}>${escapeHTML((original.domains || []).join("\n"))}</textarea></div>
      <div class="field-row"><label class="check"><input type="checkbox" name="enabled" ${original.enabled ? "checked" : ""} ${readOnly ? "disabled" : ""}>Enable virtual service</label><label class="check"><input type="checkbox" name="preserve_host" ${original.preserve_host ? "checked" : ""} ${readOnly ? "disabled" : ""}>Preserve incoming Host</label></div>
      <section class="adc-action-panel" data-action-panel="group"><h3 class="section-title">Group action</h3><div class="field-row"><div class="field"><label>Default server pool</label><select class="select" name="server_pool" ${readOnly ? "disabled" : ""}>${poolOptions}</select></div><div class="field"><label>Direct upstream URL</label><input class="input mono" name="upstream" value="${escapeAttr(original.upstream || "")}" ${readOnly ? "disabled" : ""}></div></div>
        <div class="field-row"><div class="field"><label>Persistence</label><select class="select" name="persistence_mode" ${readOnly ? "disabled" : ""}>${["none", "source_ip", "cookie"].map((item) => `<option value="${item}" ${original.persistence.mode === item ? "selected" : ""}>${item}</option>`).join("")}</select></div><div class="field"><label>Cookie name</label><input class="input" name="cookie_name" value="${escapeAttr(original.persistence.cookie_name)}" ${readOnly ? "disabled" : ""}></div><div class="field"><label>TTL (seconds)</label><input class="input" type="number" min="60" max="2592000" name="persistence_ttl" value="${escapeAttr(original.persistence.ttl_seconds)}" ${readOnly ? "disabled" : ""}></div></div>
        <div class="field"><label>Content routing rules (JSON array)</label><textarea class="textarea code-editor" name="content_routes" ${readOnly ? "disabled" : ""}>${escapeHTML(JSON.stringify(original.content_routes || [], null, 2))}</textarea><small>Rules are evaluated in order and can match methods, path prefix/RE2, a header, or a query parameter before selecting another pool.</small></div>
      </section>
      <section class="adc-action-panel" data-action-panel="redirect"><h3 class="section-title">Redirect action</h3><div class="field-row"><div class="field"><label>Target URL</label><input class="input mono" name="redirect_url" value="${escapeAttr(original.redirect?.url || "")}" ${readOnly ? "disabled" : ""}><small>Supports {host}, {request_uri}, {path}, and {query}.</small></div><div class="field"><label>Status</label><select class="select" name="redirect_status" ${readOnly ? "disabled" : ""}>${[301,302,303,307,308].map((item) => `<option value="${item}" ${Number(original.redirect?.status) === item ? "selected" : ""}>${item}</option>`).join("")}</select></div></div></section>
      <section class="adc-action-panel" data-action-panel="discard"><h3 class="section-title">Discard action</h3><div class="field"><label>HTTP rejection status</label><input class="input" type="number" min="400" max="599" name="discard_status" value="${escapeAttr(original.discard_status)}" ${readOnly ? "disabled" : ""}></div></section>
      <h3 class="section-title mt-16">Frontend and direct-origin TLS</h3><div class="field"><label>Managed frontend certificate</label><select class="select" name="managed_certificate" ${readOnly ? "disabled" : ""}>${certOptions}</select></div>
      <div class="field-row"><div class="field"><label>Certificate file</label><input class="input mono" name="certificate_file" value="${escapeAttr(original.frontend_tls.certificate_file || "")}" ${readOnly ? "disabled" : ""}></div><div class="field"><label>Private key file</label><input class="input mono" name="private_key_file" value="${escapeAttr(original.frontend_tls.private_key_file || "")}" ${readOnly ? "disabled" : ""}></div></div>
      <div class="field-row"><div class="field"><label>Direct-origin SNI</label><input class="input" name="origin_server_name" value="${escapeAttr(original.origin_tls.server_name || "")}" ${readOnly ? "disabled" : ""}></div><div class="field"><label>Direct-origin CA file</label><input class="input mono" name="origin_ca_file" value="${escapeAttr(original.origin_tls.ca_file || "")}" ${readOnly ? "disabled" : ""}></div><label class="check"><input type="checkbox" name="origin_insecure" ${original.origin_tls.insecure_skip_verify ? "checked" : ""} ${readOnly ? "disabled" : ""}>Skip origin verification</label></div>
      <h3 class="section-title mt-16">Per-application WAF policy</h3>
      <div class="grid four"><div class="field"><label>Mode</label><select class="select" name="waf_mode" ${readOnly ? "disabled" : ""}>${["inherit", "detect", "blocking", "disabled"].map((item) => `<option value="${item}" ${original.waf_policy.mode === item ? "selected" : ""}>${item}</option>`).join("")}</select></div><div class="field"><label>Block threshold (0 = inherit)</label><input class="input" type="number" min="0" max="1000" name="block_threshold" value="${escapeAttr(original.waf_policy.block_threshold || 0)}" ${readOnly ? "disabled" : ""}></div><div class="field"><label>Max body bytes (0 = inherit)</label><input class="input" type="number" min="0" max="134217728" name="max_body" value="${escapeAttr(original.waf_policy.max_body_bytes || 0)}" ${readOnly ? "disabled" : ""}></div><div class="field"><label>Engine failure</label><select class="select" name="fail_mode" ${readOnly ? "disabled" : ""}><option value="closed" ${original.waf_policy.fail_mode !== "open" ? "selected" : ""}>Fail closed</option><option value="open" ${original.waf_policy.fail_mode === "open" ? "selected" : ""}>Fail open</option></select></div></div>
      <div class="field-row"><div class="field"><label>Built-in rules</label><select class="select" name="builtins" ${readOnly ? "disabled" : ""}><option value="inherit" ${original.waf_policy.builtins === undefined || original.waf_policy.builtins === null ? "selected" : ""}>Inherit</option><option value="true" ${original.waf_policy.builtins === true ? "selected" : ""}>Enabled</option><option value="false" ${original.waf_policy.builtins === false ? "selected" : ""}>Disabled</option></select></div><div class="field"><label>Additional rule files</label><textarea class="textarea mono" name="rule_files" ${readOnly ? "disabled" : ""}>${escapeHTML((original.waf_policy.rule_files || []).join("\n"))}</textarea></div></div>
      <div class="field-row"><div class="field"><label>Allow IP/CIDRs</label><textarea class="textarea mono" name="allow_cidrs" ${readOnly ? "disabled" : ""}>${escapeHTML((original.waf_policy.allow_cidrs || []).join("\n"))}</textarea></div><div class="field"><label>Deny IP/CIDRs</label><textarea class="textarea mono" name="deny_cidrs" ${readOnly ? "disabled" : ""}>${escapeHTML((original.waf_policy.deny_cidrs || []).join("\n"))}</textarea></div></div>
      <h3 class="section-title mt-16">Per-application rate and bot policy</h3>
      <div class="field-row"><label class="check"><input type="checkbox" name="app_rate_enabled" ${original.waf_policy.rate_limit?.enabled ? "checked" : ""} ${readOnly ? "disabled" : ""}>Override global rate limit</label><div class="field"><label>Requests / second</label><input class="input" type="number" min="0.01" step="0.01" name="app_rps" value="${escapeAttr(original.waf_policy.rate_limit?.requests_per_second || 50)}" ${readOnly ? "disabled" : ""}></div><div class="field"><label>Burst</label><input class="input" type="number" min="1" name="app_burst" value="${escapeAttr(original.waf_policy.rate_limit?.burst || 100)}" ${readOnly ? "disabled" : ""}></div></div>
      <div class="field-row"><label class="check"><input type="checkbox" name="bot_enabled" ${original.bot_policy.enabled ? "checked" : ""} ${readOnly ? "disabled" : ""}>Enable bot policy</label><div class="field"><label>Mode</label><select class="select" name="bot_mode" ${readOnly ? "disabled" : ""}><option value="monitor" ${original.bot_policy.mode !== "block" ? "selected" : ""}>Monitor</option><option value="block" ${original.bot_policy.mode === "block" ? "selected" : ""}>Block</option></select></div><div class="field"><label>Requests / minute</label><input class="input" type="number" min="1" name="bot_rpm" value="${escapeAttr(original.bot_policy.requests_per_minute || 300)}" ${readOnly ? "disabled" : ""}></div><div class="field"><label>Burst</label><input class="input" type="number" min="1" name="bot_burst" value="${escapeAttr(original.bot_policy.burst || 60)}" ${readOnly ? "disabled" : ""}></div></div>
      <div class="field-row"><div class="field"><label>Blocked User-Agent RE2 patterns</label><textarea class="textarea mono" name="bad_agents" ${readOnly ? "disabled" : ""}>${escapeHTML((original.bot_policy.bad_user_agents || []).join("\n"))}</textarea></div><div class="field"><label>Allowed User-Agent RE2 patterns</label><textarea class="textarea mono" name="allowed_agents" ${readOnly ? "disabled" : ""}>${escapeHTML((original.bot_policy.allow_user_agents || []).join("\n"))}</textarea></div></div>
      <h3 class="section-title mt-16">Header modification</h3><div class="field-row"><div class="field"><label>Request headers</label><textarea class="textarea mono" name="request_headers" ${readOnly ? "disabled" : ""}>${escapeHTML(headersToText(original.request_headers))}</textarea></div><div class="field"><label>Response headers</label><textarea class="textarea mono" name="response_headers" ${readOnly ? "disabled" : ""}>${escapeHTML(headersToText(original.response_headers))}</textarea></div></div>
      <div class="form-actions"><button type="button" class="btn" data-close-modal="true">Close</button>${readOnly ? "" : `<button class="btn btn-primary" type="submit">Validate and apply</button>`}</div>
    </form>`, { wide: true });
    $$('[data-close-modal]', modalRoot).forEach((button) => button.onclick = closeModal);
    const form = $("#virtual-service-form");
    const updatePanels = () => $$('[data-action-panel]', form).forEach((panel) => panel.classList.toggle("hidden", panel.dataset.actionPanel !== form.elements.action.value));
    form.elements.action.onchange = updatePanels; updatePanels();
    form.elements.managed_certificate.onchange = () => { const cert = certs.find((item) => item.domain === form.elements.managed_certificate.value); if (cert) { form.elements.certificate_file.value = cert.certificate_file; form.elements.private_key_file.value = cert.private_key_file; } };
    if (!readOnly) form.onsubmit = async (event) => {
      event.preventDefault(); const values = new FormData(event.currentTarget);
      try {
        const builtinsValue = String(values.get("builtins"));
        const rateEnabled = values.has("app_rate_enabled");
        const host = normalizeVirtualService({
          name: String(values.get("name") || "").trim(), enabled: values.has("enabled"), domains: listValue(values.get("domains")), action: String(values.get("action")), server_pool: String(values.get("server_pool") || "").trim(), upstream: String(values.get("upstream") || "").trim(), redirect: { url: String(values.get("redirect_url") || "").trim(), status: Number(values.get("redirect_status")) }, discard_status: Number(values.get("discard_status")), preserve_host: values.has("preserve_host"),
          frontend_tls: { certificate_file: String(values.get("certificate_file") || "").trim(), private_key_file: String(values.get("private_key_file") || "").trim() }, origin_tls: { server_name: String(values.get("origin_server_name") || "").trim(), ca_file: String(values.get("origin_ca_file") || "").trim(), insecure_skip_verify: values.has("origin_insecure") },
          persistence: { mode: String(values.get("persistence_mode")), cookie_name: String(values.get("cookie_name") || "").trim(), ttl_seconds: Number(values.get("persistence_ttl")) },
          waf_policy: { mode: String(values.get("waf_mode")), block_threshold: Number(values.get("block_threshold")), max_body_bytes: Number(values.get("max_body")), ...(builtinsValue === "inherit" ? {} : { builtins: builtinsValue === "true" }), rule_files: listValue(values.get("rule_files")), rate_limit: rateEnabled ? { enabled: true, requests_per_second: Number(values.get("app_rps")), burst: Number(values.get("app_burst")), entry_ttl_seconds: 600 } : undefined, fail_mode: String(values.get("fail_mode")), allow_cidrs: listValue(values.get("allow_cidrs")), deny_cidrs: listValue(values.get("deny_cidrs")) },
          bot_policy: { enabled: values.has("bot_enabled"), mode: String(values.get("bot_mode")), requests_per_minute: Number(values.get("bot_rpm")), burst: Number(values.get("bot_burst")), bad_user_agents: listValue(values.get("bad_agents")), allow_user_agents: listValue(values.get("allowed_agents")) },
          content_routes: JSON.parse(String(values.get("content_routes") || "[]")), request_headers: headersFromText(values.get("request_headers")), response_headers: headersFromText(values.get("response_headers")),
        });
        if (host.action === "group") {
          if (host.server_pool) host.upstream = "";
          if (!host.server_pool && !host.upstream) throw new Error("Group action requires a server pool or direct upstream URL.");
        }
        const next = deepClone(config); if (index === null) next.virtual_hosts.push(host); else next.virtual_hosts[index] = host;
        await saveConfig(next, "Virtual service updated"); closeModal(); await navigate("virtual-services", true);
      } catch (error) { toast(error.message, "error"); }
    };
  }

  async function renderThreatIntelligence(content, force = false) {
    content.innerHTML = page("Threat intelligence", "Maintain a local active-attacker and IP/CIDR reputation policy. Feed files can be managed by automation without placing a remote dependency in every request.");
    const config = ensureADCDefaults(await loadConfig(force));
    const reputation = config.security.reputation;
    let runtime = {};
    try { runtime = (await api("/api/v1/dashboard")).runtime || {}; } catch (_) {}
    $("#page-body").innerHTML = `<div class="grid two"><section class="card"><header class="card-head"><div><h3>Policy status</h3><p>Longest-prefix match is used for IPv4 and IPv6 entries.</p></div>${reputation.enabled ? statusBadge(reputation.mode, reputation.mode === "block" ? "red" : "amber") : statusBadge("Disabled", "blue")}</header><div class="card-body"><div class="metric-value">${fmtNumber(runtime.reputation_entries || 0)}</div><div class="metric-note">loaded reputation entries</div><div class="notice mt-16">Monitor mode records security events without blocking. Block mode rejects matching clients before WAF body inspection.</div></div></section>
      <section class="card"><header class="card-head"><div><h3>Reputation policy</h3><p>Inline entries and local feed files are compiled during validated reload.</p></div></header><div class="card-body"><form id="reputation-form">
        <label class="check"><input type="checkbox" name="enabled" ${reputation.enabled ? "checked" : ""} ${!can("admin") ? "disabled" : ""}>Enable IP reputation</label>
        <div class="field mt-16"><label>Operation mode</label><select class="select" name="mode" ${!can("admin") ? "disabled" : ""}><option value="monitor" ${reputation.mode !== "block" ? "selected" : ""}>Monitor only</option><option value="block" ${reputation.mode === "block" ? "selected" : ""}>Block matches</option></select></div>
        <div class="field"><label>Inline IP/CIDR entries</label><textarea class="textarea mono adc-feed" name="entries" placeholder="203.0.113.0/24 scanner network\n2001:db8:bad::/48 threat feed" ${!can("admin") ? "disabled" : ""}>${escapeHTML((reputation.entries || []).join("\n"))}</textarea><small>Optional text after the address becomes the event reason.</small></div>
        <div class="field"><label>Local feed files</label><textarea class="textarea mono" name="files" placeholder="/var/lib/cherrywaf/control/reputation/active-attackers.txt" ${!can("admin") ? "disabled" : ""}>${escapeHTML((reputation.files || []).join("\n"))}</textarea></div>
        ${can("admin") ? `<div class="form-actions"><button class="btn btn-primary" type="submit">Validate and apply</button></div>` : ""}
      </form></div></section></div>`;
    if (can("admin")) $("#reputation-form").onsubmit = async (event) => { event.preventDefault(); const values = new FormData(event.currentTarget); const next = deepClone(config); next.security.reputation = { enabled: values.has("enabled"), mode: String(values.get("mode")), entries: String(values.get("entries") || "").split(/\n+/).map((item) => item.trim()).filter(Boolean), files: listValue(values.get("files")) }; try { await saveConfig(next, "Threat intelligence policy updated"); await renderThreatIntelligence(content, true); } catch (error) { toast(error.message, "error"); } };
  }
})();
