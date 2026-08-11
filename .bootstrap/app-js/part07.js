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
