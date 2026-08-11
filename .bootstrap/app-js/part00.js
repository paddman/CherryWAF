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
