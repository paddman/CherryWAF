"use strict";

window.CherryThreatMapView = (() => {
  const core = window.CherryThreatMap;
  const target = { x: 1005, y: 250 };
  const $ = (selector) => document.querySelector(selector);

  function markup() {
    return `<section class="threat-map-section" id="threat-map-panel" aria-labelledby="threat-map-title">
      <header class="threat-map-header"><div><div class="threat-map-kicker">GLOBAL THREAT INTELLIGENCE</div>
      <h2 id="threat-map-title">Live attack map</h2><p>Recent WAF security events enriched only by trusted proxy geo headers.</p></div>
      <div class="threat-map-actions"><span class="threat-live-pill"><span class="threat-live-dot"></span><span id="threat-live-label">Live · 5s</span></span>
      <button class="btn btn-sm" id="threat-refresh" type="button">Refresh now</button></div></header>
      <div class="threat-map-metrics" aria-label="Threat summary">
      <div class="threat-mini-metric"><span>Recent events</span><strong id="threat-total">0</strong></div>
      <div class="threat-mini-metric"><span>Blocked</span><strong id="threat-blocked">0</strong></div>
      <div class="threat-mini-metric"><span>Geolocated</span><strong id="threat-geolocated">0</strong></div>
      <div class="threat-mini-metric"><span>Unique sources</span><strong id="threat-sources">0</strong></div></div>
      <div class="threat-map-layout"><section class="card threat-map-card"><div class="threat-map-stage">
      <svg class="threat-map-svg" viewBox="0 0 1080 500" role="img" aria-label="Recent attack sources on a world map">
      <image href="/assets/world-map.svg" x="20" y="0" width="880" height="500" preserveAspectRatio="none"></image>
      <g id="threat-arcs"></g><g id="threat-points"></g><g class="threat-edge-node" transform="translate(1005 250)">
      <circle class="threat-edge-halo" r="44"></circle><circle class="threat-edge-ring" r="27"></circle>
      <circle class="threat-edge-core" r="10"></circle><text x="0" y="64" text-anchor="middle">CherryWAF Edge</text></g></svg>
      <div class="threat-map-legend" aria-hidden="true"><span><i class="blocked"></i>Blocked</span><span><i class="detected"></i>Detected</span><span><i class="logged"></i>Logged</span></div>
      <div class="threat-map-empty hidden" id="threat-map-empty"></div></div></section>
      <aside class="threat-map-side"><section class="card threat-country-card"><header class="card-head"><div><h3>Top source countries</h3><p>Current memory window.</p></div></header><div class="threat-country-list" id="threat-country-list"></div></section>
      <section class="card threat-feed-card"><header class="card-head"><div><h3>Latest security events</h3><p>Newest events first.</p></div></header><div class="threat-event-feed" id="threat-event-feed"></div></section></aside></div>
      <div class="threat-map-footnote">Geo headers are accepted only from peers in <code>security.trusted_proxies</code>. Supports <code>CF-IPCountry</code> and <code>X-Geo-*</code>. No third-party browser lookup is used.</div></section>`;
  }

  function setText(selector, value) { const node = $(selector); if (node) node.textContent = String(value); }

  function map(events) {
    const located = events.map((event,index) => ({ event,index,loc:core.location(event) })).filter((row) => row.loc);
    const visible = located.slice(0, core.data.maxMapEvents);
    const arcs = [], points = [];
    for (const row of visible) {
      const p = core.point(row.event, row.loc, row.index), type = core.kind(row.event.action);
      const cx = Math.min(target.x - 55, p.x + Math.max(95, (target.x - p.x) * .48));
      const cy = p.y + (target.y - p.y) * .32 - 42 - (row.index % 4) * 7;
      const title = core.escapeHTML(core.label(row.event)), delay = `threat-delay-${row.index % 12}`;
      arcs.push(`<path class="threat-arc ${type} ${delay}" d="M ${p.x.toFixed(1)} ${p.y.toFixed(1)} Q ${cx.toFixed(1)} ${cy.toFixed(1)} ${target.x} ${target.y}"><title>${title}</title></path>`);
      points.push(`<g class="threat-point ${type}" transform="translate(${p.x.toFixed(1)} ${p.y.toFixed(1)})"><circle class="threat-point-pulse ${delay}" r="11"></circle><circle class="threat-point-core" r="4.2"></circle><title>${title}</title></g>`);
    }
    if ($("#threat-arcs")) $("#threat-arcs").innerHTML = arcs.join("");
    if ($("#threat-points")) $("#threat-points").innerHTML = points.join("");
    const empty = $("#threat-map-empty");
    if (empty) {
      const message = !events.length ? "No security events yet. The map populates after a rule match, block, or rate-limit event."
        : !located.length ? "Events are arriving without trusted geo data. Configure CF-IPCountry or X-Geo-* on a trusted reverse proxy." : "";
      empty.textContent = message; empty.classList.toggle("hidden", !message);
    }
  }

  function countries(items) {
    const root = $("#threat-country-list"); if (!root) return;
    const rows = items.slice(0,7), max = Math.max(1, ...rows.map((row) => row.count));
    root.innerHTML = rows.length ? rows.map((row,index) => `<div class="threat-country-row"><span class="threat-country-rank">${String(index+1).padStart(2,"0")}</span>
      <div class="threat-country-main"><div><strong>${core.escapeHTML(row.name || row.code || "Unresolved")}</strong><span>${core.escapeHTML(row.code || "--")}</span></div>
      <div class="threat-country-bar"><i class="threat-width-${Math.max(1, Math.min(10, Math.ceil(row.count/max*10)))}"></i></div></div><strong class="threat-country-count">${row.count}</strong></div>`).join("")
      : `<div class="empty threat-compact-empty"><strong>No country data</strong>Trusted geo metadata has not arrived yet.</div>`;
  }

  function feed(events) {
    const root = $("#threat-event-feed"); if (!root) return;
    root.innerHTML = events.slice(0,8).map((event) => {
      const loc = core.location(event), type = core.kind(event.action), stamp = new Date(event.timestamp);
      const time = Number.isNaN(stamp.getTime()) ? "Now" : stamp.toLocaleTimeString([], {hour:"2-digit",minute:"2-digit",second:"2-digit"});
      const place = loc ? [loc.city,loc.country].filter(Boolean).join(", ") : "Geo unresolved";
      const rule = event.reason || event.matches?.[0]?.rule_name || event.matches?.[0]?.rule_id || "Security rule matched";
      return `<article class="threat-event-row"><span class="threat-event-marker ${type}"></span><div class="threat-event-main"><div><strong class="mono">${core.escapeHTML(event.client_ip || "unknown")}</strong><span>${core.escapeHTML(time)}</span></div>
      <p>${core.escapeHTML(rule)}</p><small>${core.escapeHTML(place)} · ${core.escapeHTML(event.host || event.virtual_host || "unknown host")}</small></div><span class="threat-action-badge ${type}">${core.escapeHTML(event.action || "log")}</span></article>`;
    }).join("") || `<div class="empty threat-compact-empty"><strong>No attack activity</strong>Nothing has matched a security rule in this runtime.</div>`;
  }

  function render(runtime) {
    const events = Array.isArray(runtime?.recent_security_events) ? runtime.recent_security_events.slice().reverse() : [];
    const summary = core.summarize(events); map(events); countries(summary.countries); feed(events);
    setText("#threat-total", summary.total.toLocaleString()); setText("#threat-blocked", summary.blocked.toLocaleString());
    setText("#threat-geolocated", summary.geolocated.toLocaleString()); setText("#threat-sources", summary.sources.toLocaleString());
    setText("#threat-live-label", `Live · ${new Date().toLocaleTimeString([], {hour:"2-digit",minute:"2-digit",second:"2-digit"})}`);
  }

  function unavailable(message) { const empty=$("#threat-map-empty"); if(empty){empty.textContent=message||"Threat telemetry unavailable.";empty.classList.remove("hidden");} setText("#threat-live-label","Telemetry unavailable"); }
  return Object.freeze({ markup, render, unavailable });
})();