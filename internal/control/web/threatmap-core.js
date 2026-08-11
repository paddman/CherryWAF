"use strict";

window.CherryThreatMap = (() => {
  const data = window.CherryThreatMapData;
  const names = typeof Intl.DisplayNames === "function"
    ? new Intl.DisplayNames([navigator.language || "en"], { type: "region" })
    : null;

  function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>'"]/g, (char) => ({
      "&":"&amp;", "<":"&lt;", ">":"&gt;", "'":"&#39;", '"':"&quot;"
    }[char]));
  }

  function countryCode(value) {
    const code = String(value || "").trim().toUpperCase();
    return /^[A-Z]{2}$/.test(code) ? code : "";
  }

  function countryName(code, fallback = "") {
    if (!code) return fallback || "Unresolved";
    try { return names?.of(code) || fallback || code; } catch (_) { return fallback || code; }
  }

  function number(value) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  function location(event) {
    const geo = event?.geo || {};
    const code = countryCode(geo.country_code);
    let latitude = number(geo.latitude);
    let longitude = number(geo.longitude);
    if (latitude === null || longitude === null || latitude < -90 || latitude > 90 || longitude < -180 || longitude > 180) {
      const fallback = data.centroids[code];
      if (!fallback) return null;
      [latitude, longitude] = fallback;
    }
    return {
      latitude, longitude, code,
      country: countryName(code, String(geo.country || "").trim()),
      city: String(geo.city || "").trim()
    };
  }

  function hash(value) {
    let result = 2166136261;
    for (const char of String(value || "")) {
      result ^= char.charCodeAt(0);
      result = Math.imul(result, 16777619);
    }
    return result >>> 0;
  }

  function point(event, loc, index) {
    const seed = hash(`${event.client_ip}|${event.request_id}|${index}`);
    const lon = Math.max(-179.8, Math.min(179.8, loc.longitude + (((seed & 255) / 255) - .5) * 2.1));
    const lat = Math.max(-89.8, Math.min(89.8, loc.latitude + ((((seed >>> 8) & 255) / 255) - .5) * 1.5));
    return { x: 20 + ((lon + 180) / 360) * 880, y: 20 + ((90 - lat) / 180) * 440 };
  }

  function kind(action) {
    const value = String(action || "").toLowerCase();
    if (value === "block" || value === "rate_limit") return "blocked";
    if (value === "detect") return "detected";
    return "logged";
  }

  function label(event) {
    const loc = location(event);
    const place = loc ? [loc.city, loc.country].filter(Boolean).join(", ") : "Location unresolved";
    return `${event.client_ip || "unknown"} · ${place} · ${event.reason || "Security event"}`;
  }

  function summarize(events) {
    const countries = new Map();
    let geolocated = 0;
    let blocked = 0;
    const sources = new Set();
    for (const event of events) {
      if (["block", "rate_limit"].includes(String(event.action || "").toLowerCase())) blocked++;
      if (event.client_ip) sources.add(event.client_ip);
      const loc = location(event);
      if (!loc) continue;
      geolocated++;
      const key = loc.code || loc.country;
      const row = countries.get(key) || { code: loc.code, name: loc.country, count: 0 };
      row.count++;
      countries.set(key, row);
    }
    return {
      total: events.length, blocked, geolocated, sources: sources.size,
      countries: [...countries.values()].sort((a,b) => b.count - a.count)
    };
  }

  return Object.freeze({ data, escapeHTML, location, point, kind, label, summarize });
})();