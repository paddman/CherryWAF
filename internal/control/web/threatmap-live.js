"use strict";

(() => {
  const view = window.CherryThreatMapView;
  const data = window.CherryThreatMapData;
  const state = { busy:false, queued:false, last:0 };
  const onDashboard = () => (location.hash.slice(1) || "dashboard") === "dashboard";

  function ensurePanel() {
    if (!onDashboard()) return null;
    const body = document.querySelector("#page-body");
    if (!body || !document.querySelector(".shell")) return null;
    let panel = document.querySelector("#threat-map-panel");
    if (!panel) {
      body.insertAdjacentHTML("beforeend", view.markup());
      panel = document.querySelector("#threat-map-panel");
      document.querySelector("#threat-refresh")?.addEventListener("click", () => refresh(true));
    }
    return panel;
  }

  async function refresh(force=false) {
    const panel = ensurePanel();
    if (!panel || state.busy) return;
    const now = Date.now();
    if (!force && now - state.last < 900) return;
    state.last = now; state.busy = true; panel.classList.add("is-refreshing");
    try {
      const response = await fetch("/api/v1/dashboard", { credentials:"same-origin", headers:{Accept:"application/json"}, cache:"no-store" });
      if (response.status === 401) return;
      if (!response.ok) throw new Error(`Dashboard API returned HTTP ${response.status}`);
      const payload = await response.json();
      if (!payload.runtime_available) return view.unavailable(payload.runtime_error || "WAF core is not responding.");
      view.render(payload.runtime || {}); panel.dataset.loaded = "true";
    } catch (error) { view.unavailable(error.message); }
    finally { state.busy=false; panel.classList.remove("is-refreshing"); }
  }

  function schedule() {
    if (state.queued) return;
    state.queued = true;
    setTimeout(() => { state.queued=false; const panel=ensurePanel(); if(panel && panel.dataset.loaded!=="true") refresh(); }, 80);
  }

  function start() {
    const app = document.querySelector("#app"); if (!app) return;
    new MutationObserver(schedule).observe(app, {childList:true,subtree:true});
    addEventListener("hashchange", schedule);
    setInterval(() => { if(onDashboard()) refresh(); }, data.refreshMs);
    schedule();
  }

  document.readyState === "loading" ? document.addEventListener("DOMContentLoaded", start, {once:true}) : start();
})();