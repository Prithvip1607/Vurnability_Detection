/* EVVP dashboard core: escaping templates, API client, router, widgets, charts. No dependencies. */
(function () {
  "use strict";
  const E = (window.EVVP = { pages: [], actions: {} });

  // ── Safe templating: every interpolated value is HTML-escaped unless wrapped by raw()/html`` ──
  class Raw { constructor(s) { this.s = s; } }
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const val = (v) => (v instanceof Raw ? v.s : Array.isArray(v) ? v.map(val).join("") : v === false || v == null ? "" : esc(v));
  const html = (strs, ...vals) => new Raw(strs.reduce((o, s, i) => o + s + (i < vals.length ? val(vals[i]) : ""), ""));
  const raw = (s) => new Raw(s);
  const safeUrl = (u) => (/^https?:\/\//i.test(u || "") ? u : "#");
  Object.assign(E, { esc, html, raw, safeUrl });

  // ── Formatting ──
  const fmtTs = (s) => { if (!s) return "—"; const d = new Date(s); return isNaN(d) ? String(s) : d.toISOString().slice(0, 16).replace("T", " ") + " UTC"; };
  const ago = (s) => {
    const d = new Date(s); if (!s || isNaN(d)) return "—";
    let sec = Math.round((Date.now() - d) / 1000); if (sec < 0) return "in the future";
    if (sec < 90) return "just now";
    const u = [[86400, "d"], [3600, "h"], [60, "m"]];
    for (const [n, l] of u) if (sec >= n) return `${Math.floor(sec / n)}${l} ago`;
    return `${sec}s ago`;
  };
  const num = (n, d = 1) => (n == null || isNaN(n) ? "Not available" : Number(n).toFixed(d));
  const pct = (n, d = 1) => (n == null || isNaN(n) ? "Not available" : (n * 100).toFixed(d) + "%");
  const label = (s) => String(s || "").replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  Object.assign(E, { fmtTs, ago, num, pct, label });

  // ── Settings (analyst name, token, theme) ──
  const store = {
    get: (k, d = "") => { try { return localStorage.getItem(k) ?? d; } catch (e) { return d; } },
    set: (k, v) => { try { localStorage.setItem(k, v); } catch (e) { /* private mode */ } },
  };
  E.analyst = () => store.get("evvp.analyst", "Security Analyst");
  const token = () => { try { return sessionStorage.getItem("evvp.token") || ""; } catch (e) { return ""; } };
  document.documentElement.dataset.theme = store.get("evvp.theme", "dark");

  // ── API client ──
  class ApiError extends Error { constructor(msg, status, data) { super(msg); this.status = status; this.data = data; } }
  E.api = async function (path, opts = {}) {
    const headers = { Accept: "application/json" };
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
    if (token() && (opts.method || "GET") !== "GET") headers.Authorization = "Bearer " + token();
    let res;
    try {
      res = await fetch("/api" + path, { method: opts.method || "GET", headers, body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined });
    } catch (e) { throw new ApiError("Cannot reach the EVVP API — is the backend running?", 0); }
    let data = null;
    try { data = await res.json(); } catch (e) { /* non-JSON error body */ }
    if (!res.ok && !(opts.okStatuses || []).includes(res.status)) {
      const msg = res.status === 401 ? "Unauthorized — set the API token in ⚙ Settings" : (data && data.error) || `Request failed (HTTP ${res.status})`;
      throw new ApiError(msg, res.status, data);
    }
    return data;
  };
  const qs = (o) => { const p = new URLSearchParams(); Object.entries(o).forEach(([k, v]) => { if (v !== "" && v != null && v !== false) p.set(k, v); }); const s = p.toString(); return s ? "?" + s : ""; };
  E.qs = qs;

  // ── Toasts & modals ──
  E.toast = (msg, kind = "") => {
    const t = document.createElement("div"); t.className = "toast " + kind; t.textContent = msg; t.setAttribute("role", "status");
    document.getElementById("toasts").appendChild(t); setTimeout(() => t.remove(), kind === "bad" ? 7000 : 3500);
  };
  E.modal = (content, onMount) => {
    const bg = document.createElement("div"); bg.className = "modalbg";
    bg.innerHTML = `<div class="modal" role="dialog" aria-modal="true">${val(content)}</div>`;
    const close = () => { bg.remove(); document.removeEventListener("keydown", onKey); };
    const onKey = (e) => { if (e.key === "Escape") close(); };
    bg.addEventListener("mousedown", (e) => { if (e.target === bg) close(); });
    document.addEventListener("keydown", onKey); document.body.appendChild(bg);
    bg.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", close));
    if (onMount) onMount(bg.firstElementChild, close);
    const first = bg.querySelector("input,select,textarea,button"); if (first) first.focus();
    return close;
  };

  // ── Widgets ──
  const riskClass = (r) => (r >= 80 ? "r-c" : r >= 60 ? "r-h" : r >= 40 ? "r-m" : "r-l");
  E.riskBadge = (r) => html`<span class="risk ${riskClass(r)}" title="Risk score ${r}/100">${r}</span>`;
  E.sevBadge = (s) => html`<span class="badge sev-${s}">${s || "—"}</span>`;
  E.statusBadge = (s) => html`<span class="badge ${{ confirmed: "b-ok", false_positive: "b-mute", resolved: "b-mute", under_investigation: "b-warn", potential: "b-poc" }[s] || "b-mute"}">${label(s)}</span>`;
  E.trustBadge = (t) => html`<span class="badge b-mute" title="Source trust level">${label(t || "medium")}</span>`;
  E.chips = (e) => html`<div class="chips">${e.zero_day_candidate ? html`<span class="badge b-zd" title="Unconfirmed indicator, not a certainty">POTENTIAL ZERO-DAY ${e.zero_day_score}</span>` : ""}${e.active_exploitation ? html`<span class="badge b-act">ACTIVE EXPLOITATION</span>` : ""}${e.poc ? html`<span class="badge b-poc">PoC</span>` : ""}${(e.cve_ids || []).slice(0, 3).map((c) => html`<span class="badge b-mute mono">${c}</span>`)}${(e.cve_ids || []).length > 3 ? html`<span class="badge b-mute">+${e.cve_ids.length - 3}</span>` : ""}</div>`;
  E.loading = () => html`<div class="loading"><span class="spin"></span>Loading…</div>`;
  E.empty = (m) => html`<div class="empty">${m}</div>`;
  E.kv = (rows) => html`<dl class="kv">${rows.map(([k, v]) => html`<dt>${k}</dt><dd>${v == null || v === "" ? html`<span class="faint">Not available</span>` : v}</dd>`)}</dl>`;
  E.ext = (url, text) => html`<a href="${safeUrl(url)}" target="_blank" rel="noopener noreferrer">${text || url}</a>`;

  E.pager = (page, pages, total) => html`<div class="pager"><span class="muted small">${total} result${total === 1 ? "" : "s"} · page ${page} of ${pages}</span><span>
    <button data-act="page" data-page="1" ${page <= 1 ? "disabled" : ""}>« First</button>
    <button data-act="page" data-page="${page - 1}" ${page <= 1 ? "disabled" : ""}>‹ Prev</button>
    <button data-act="page" data-page="${page + 1}" ${page >= pages ? "disabled" : ""}>Next ›</button>
    <button data-act="page" data-page="${pages}" ${page >= pages ? "disabled" : ""}>Last »</button></span></div>`;

  // CSS horizontal bars
  E.hbars = (items, { color = "var(--accent)", fmt = (n) => n, max } = {}) => {
    if (!items.length) return E.empty("No data yet");
    const m = max || Math.max(...items.map((i) => i.count), 1);
    return html`${items.map((i) => html`<div class="bar" title="${i.name}: ${fmt(i.count)}"><span class="nm">${i.name}</span><span class="tr"><span class="fl" style="display:block;width:${Math.max(2, (i.count / m) * 100)}%;background:${i.color || color}"></span></span><span class="ct">${fmt(i.count)}</span></div>`)}`;
  };

  // SVG stacked columns. points: [{label, k1:v, k2:v}]
  E.columns = (points, keys, colors, h = 160) => {
    if (!points.length) return E.empty("No data yet");
    const W = 600, pad = { l: 30, r: 6, t: 8, b: 22 }, iw = W - pad.l - pad.r, ih = h - pad.t - pad.b;
    const totals = points.map((p) => keys.reduce((a, k) => a + (p[k] || 0), 0)), max = Math.max(...totals, 1);
    const bw = iw / points.length, step = Math.ceil(points.length / 8);
    let s = `<svg viewBox="0 0 ${W} ${h}" width="100%" role="img" aria-label="chart">`;
    [0, 0.5, 1].forEach((f) => { const y = pad.t + ih - f * ih; s += `<line x1="${pad.l}" x2="${W - pad.r}" y1="${y}" y2="${y}" stroke="var(--line)"/><text x="${pad.l - 4}" y="${y + 3}" text-anchor="end">${Math.round(max * f)}</text>`; });
    points.forEach((p, i) => {
      let y = pad.t + ih; const x = pad.l + i * bw + bw * 0.15, w = bw * 0.7;
      keys.forEach((k, j) => { const v = p[k] || 0; if (!v) return; const bh = (v / max) * ih; y -= bh; s += `<rect class="tip" x="${x}" y="${y}" width="${w}" height="${bh}" fill="${colors[j]}"><title>${esc(p.label)} · ${esc(k)}: ${v}</title></rect>`; });
      if (i % step === 0) s += `<text x="${x + w / 2}" y="${h - 6}" text-anchor="middle">${esc(String(p.label).slice(5))}</text>`;
    });
    s += "</svg>";
    const legend = keys.length > 1 ? `<div class="legend">${keys.map((k, j) => `<span><i style="background:${colors[j]}"></i>${esc(k)}</span>`).join("")}</div>` : "";
    return raw(s + legend);
  };

  // SVG line chart (0..100 y-axis)
  E.line = (points, key, color = "var(--warn)", h = 160) => {
    if (!points.length) return E.empty("No data yet");
    const W = 600, pad = { l: 30, r: 10, t: 8, b: 22 }, iw = W - pad.l - pad.r, ih = h - pad.t - pad.b;
    const X = (i) => pad.l + (points.length === 1 ? iw / 2 : (i / (points.length - 1)) * iw), Y = (v) => pad.t + ih - (v / 100) * ih;
    let s = `<svg viewBox="0 0 ${W} ${h}" width="100%" role="img" aria-label="line chart">`;
    [0, 50, 100].forEach((v) => { s += `<line x1="${pad.l}" x2="${W - pad.r}" y1="${Y(v)}" y2="${Y(v)}" stroke="var(--line)"/><text x="${pad.l - 4}" y="${Y(v) + 3}" text-anchor="end">${v}</text>`; });
    if (points.length > 1) s += `<polyline fill="none" stroke="${color}" stroke-width="2" points="${points.map((p, i) => `${X(i)},${Y(p[key])}`).join(" ")}"/>`;
    const step = Math.ceil(points.length / 8);
    points.forEach((p, i) => { s += `<circle class="tip" cx="${X(i)}" cy="${Y(p[key])}" r="3.5" fill="${color}"><title>${esc(p.label)}: ${p[key]}</title></circle>`; if (i % step === 0) s += `<text x="${X(i)}" y="${h - 6}" text-anchor="middle">${esc(String(p.label).slice(5))}</text>`; });
    return raw(s + "</svg>");
  };

  // ── Router ──
  E.parse = () => { const [path, q] = location.hash.replace(/^#\/?/, "").split("?"); return { path: path || "", params: Object.fromEntries(new URLSearchParams(q || "")) }; };
  E.nav = (path, params = {}) => { location.hash = "#/" + path + qs(params); };
  let token_ = 0;
  async function route() {
    const { path, params } = E.parse(), app = document.getElementById("app"), my = ++token_;
    const top = path.split("/")[0], section = { finding: "findings", cve: "cves" }[top] || top;
    document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("on", a.dataset.r === section));
    const page = E.pages.find((p) => p.re.test(path));
    if (!page) { app.innerHTML = '<div class="empty">Page not found. <a href="#/">Back to overview</a></div>'; return; }
    app.innerHTML = E.loading().s;
    try {
      const out = await page.fn({ params, args: path.match(page.re).slice(1).map(decodeURIComponent) });
      if (my !== token_) return;                          // a newer navigation superseded this one
      app.innerHTML = out.html.s; document.title = (out.title ? out.title + " · " : "") + "EVVP";
      if (out.after) out.after(app);
      window.scrollTo(0, 0);
    } catch (e) {
      if (my !== token_) return;
      app.innerHTML = `<div class="card err"><p><b>Could not load this page.</b></p><p>${esc(e.message)}</p><button data-act="reload">Retry</button></div>`;
    }
  }
  E.reload = route;
  E.route = (re, fn) => E.pages.push({ re, fn });

  // Delegated actions
  document.addEventListener("click", (ev) => {
    const el = ev.target.closest("[data-act]"); if (!el) return;
    const a = el.dataset.act;
    if (a === "page") { const { path, params } = E.parse(); E.nav(path, { ...params, page: el.dataset.page }); }
    else if (a === "reload") route();
    else if (E.actions[a]) E.actions[a](el, ev);
  });
  // Filter bars: Apply button / Enter / change on selects
  function applyFilters(bar) {
    const { path } = E.parse(), p = {};
    bar.querySelectorAll("[name]").forEach((f) => { p[f.name] = f.type === "checkbox" ? (f.checked ? f.value || "true" : "") : f.value.trim(); });
    E.nav(path, p);
  }
  document.addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target.closest(".filters") && e.target.tagName !== "BUTTON") applyFilters(e.target.closest(".filters")); });
  document.addEventListener("change", (e) => { const bar = e.target.closest(".filters"); if (bar && e.target.tagName !== "INPUT") applyFilters(bar); else if (bar && e.target.type === "checkbox") applyFilters(bar); });
  E.actions.apply = (el) => applyFilters(el.closest(".filters"));
  E.actions.clear = () => E.nav(E.parse().path);

  E.start = function () {
    window.addEventListener("hashchange", route);
    document.getElementById("quick").addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target.value.trim().length >= 2) { E.nav("findings", { q: e.target.value.trim() }); e.target.value = ""; } });
    document.getElementById("settings").addEventListener("click", () => E.modal(html`
      <h2>Settings</h2>
      <div class="row"><label class="l" for="s-an">Analyst name (recorded on every decision and audit entry)</label><input id="s-an" value="${E.analyst()}" maxlength="80"></div>
      <div class="row"><label class="l" for="s-tk">API token (only needed if the backend sets EVVP_API_TOKEN; kept for this browser session)</label><input id="s-tk" type="password" value="${token()}" autocomplete="off"></div>
      <div class="row"><label class="l" for="s-th">Theme</label><select id="s-th"><option value="dark">Dark</option><option value="light">Light</option></select></div>
      <div class="acts"><button data-close>Cancel</button><button class="primary" id="s-save">Save</button></div>`, (m, close) => {
      m.querySelector("#s-th").value = document.documentElement.dataset.theme;
      m.querySelector("#s-save").onclick = () => {
        const n = m.querySelector("#s-an").value.trim(); if (!n) return E.toast("Analyst name cannot be empty", "bad");
        store.set("evvp.analyst", n); store.set("evvp.theme", m.querySelector("#s-th").value);
        document.documentElement.dataset.theme = m.querySelector("#s-th").value;
        try { sessionStorage.setItem("evvp.token", m.querySelector("#s-tk").value.trim()); } catch (e) { /* ignore */ }
        close(); E.toast("Settings saved", "ok");
      };
    }));
    const refreshHealth = async () => {
      const el = document.getElementById("health");
      try { const h = await E.api("/health"); el.innerHTML = `<span class="dot ok"></span><span>API ok · ${esc(h.storage)}</span>`; el.title = `${h.findings} findings from ${h.items} evidence items; ${h.sources.enabled}/${h.sources.total} sources enabled, ${h.sources.failing} failing`; }
      catch (e) { el.innerHTML = '<span class="dot bad"></span><span>API unreachable</span>'; }
    };
    refreshHealth(); setInterval(refreshHealth, 30000);
    route();
  };
})();
