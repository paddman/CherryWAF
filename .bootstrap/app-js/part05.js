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
