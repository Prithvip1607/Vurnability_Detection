/* EVVP dashboard pages. Every number shown comes from the REST API. */
(function () {
  "use strict";
  const E = window.EVVP, { html, raw, esc, api, qs, fmtTs, ago, num, pct, label, riskBadge, sevBadge, chips, kv, ext, empty, hbars, columns, line, pager, statusBadge, trustBadge } = E;
  const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW"], SEV_COLOR = { CRITICAL: "var(--crit)", HIGH: "var(--high)", MEDIUM: "var(--med)", LOW: "var(--low)" };
  const PLAT_COLOR = { blog: "#4da3ff", github: "#9aa7c7", nvd: "#b45cff", reddit: "#ff7a45" };
  const STATUSES = ["potential", "under_investigation", "confirmed", "false_positive", "resolved"];
  const pick = (o, keys) => Object.fromEntries(keys.filter((k) => o[k] !== undefined && o[k] !== "").map((k) => [k, o[k]]));

  // ── filter bar ──
  const field = (f, params) => {
    const v = params[f.name] || "";
    if (f.type === "select") return html`<label>${f.label}<select name="${f.name}">${f.options.map(([val, txt]) => raw(`<option value="${esc(val)}"${String(val) === v ? " selected" : ""}>${esc(txt)}</option>`))}</select></label>`;
    if (f.type === "checkbox") return html`<label style="flex-direction:row;align-items:center;gap:6px;text-transform:none;font-size:13px"><input type="checkbox" name="${f.name}" value="true" ${v ? "checked" : ""}> ${f.label}</label>`;
    return html`<label>${f.label}<input name="${f.name}" value="${v}" placeholder="${f.ph || ""}" style="width:${f.w || 150}px"></label>`;
  };
  const filterBar = (fields, params) => html`<div class="filters" role="search">${fields.map((f) => field(f, params))}<button class="primary" data-act="apply">Apply</button><button data-act="clear">Clear</button></div>`;
  const any = ["", "Any"], yn = [["", "Any"], ["true", "Yes"], ["false", "No"]];

  // ── Overview ──
  E.route(/^$/, async () => {
    const [s, tr, top] = await Promise.all([api("/stats"), api("/trending?top=5"), api("/vulns?sort=risk&per_page=8")]);
    const stale = s.last_collected && Date.now() - new Date(s.last_collected) > 864e5;
    const card = (to, v, l, n, color) => html`<a class="stat" href="#/${to}" style="border-top-color:${color || "var(--accent)"}"><div class="v" style="color:${color || "inherit"}">${v}</div><div class="l">${l}</div><div class="n">${n || ""}</div></a>`;
    const fot = s.findings_over_time.slice(-30).map((d) => ({ label: d.date, Findings: d.findings, risk: d.avg_risk }));
    const sot = s.sources_over_time.slice(-30).map((d) => ({ label: d.date, ...d }));
    const plats = [...new Set(s.sources_over_time.flatMap((d) => Object.keys(d).filter((k) => k !== "date")))];
    return {
      title: "Overview", html: html`
      <h1>Overview</h1><p class="sub">Collect → Normalize → Detect → Enrich → Correlate → Prioritize. All figures are computed live from collected evidence.</p>
      ${s.total === 0 ? html`<div class="note" style="margin-bottom:14px">No findings yet. Start the collectors (<span class="mono">python main.py</span>) or run a single pass with <span class="mono">python main.py --once</span>.</div>` : ""}
      ${stale ? html`<div class="note" style="margin-bottom:14px">Newest collected evidence is <b>${ago(s.last_collected)}</b> (${fmtTs(s.last_collected)}). Collectors may not be running — check <a href="#/sources">Sources</a> and the <a href="#/audit">audit log</a>.</div>` : ""}
      <div class="stats">
        ${card("findings", s.total, "Total findings", `${s.total_evidence_items} evidence items`)}
        ${card("findings?sort=first_seen", s.new_findings, "New (24h)", "first collected")}
        ${card(`findings?min_risk=${s.thresholds.high_risk}`, s.high_risk, "High-risk", `risk ≥ ${s.thresholds.high_risk}`, "var(--high)")}
        ${card("cves?severity=CRITICAL", s.critical_cves, "Critical CVEs", "CVSS ≥ 9.0", "var(--crit)")}
        ${card("zerodays", s.potential_zero_days, "Potential zero-days", "unconfirmed candidates", "#c98bff")}
        ${card("findings?active=true", s.active_exploitation, "Active exploitation", "reported in the wild", "var(--bad)")}
        ${card("sources", `${s.sources.enabled}/${s.sources.total}`, "Sources enabled", `${s.sources.failing} failing`, s.sources.failing ? "var(--warn)" : "var(--ok)")}
        ${card("findings?sort=sources", s.multi_source, "Multi-source", "≥ 2 independent sources", "var(--ok)")}
        ${card("findings?has_cve=true", s.early_detections, "Early detections", "EVVP before CVE", "var(--ok)")}
      </div>
      <div class="grid g2">
        <div class="card"><h2>Findings over time <span class="faint small">(by first seen)</span></h2>${columns(fot, ["Findings"], ["var(--accent)"])}</div>
        <div class="card"><h2>Average risk over time</h2>${line(fot, "risk")}</div>
        <div class="card"><h2>Evidence by source platform over time</h2>${columns(sot, plats, plats.map((p) => PLAT_COLOR[p] || "#888"))}</div>
        <div class="card"><h2>Severity distribution</h2>${hbars(SEV.filter((k) => s.severity[k]).map((k) => ({ name: k, count: s.severity[k], color: SEV_COLOR[k] })))}</div>
        <div class="card"><h2>Vulnerability categories</h2>${hbars(Object.entries(s.by_category).sort((a, b) => b[1] - a[1]).map(([name, count]) => ({ name, count })))}</div>
        <div class="card"><h2>MITRE ATT&amp;CK techniques</h2>${hbars(Object.entries(s.attack_techniques).map(([name, count]) => ({ name, count })), { color: "#b45cff" })}</div>
      </div>
      <div class="grid g2" style="margin-top:14px">
        <div class="card"><h2>Highest-risk findings</h2>${top.items.length ? html`<table><tbody>${top.items.map((e) => html`<tr><td>${riskBadge(e.risk_score)}</td><td><a href="#/finding/${e.id}">${e.title}</a>${chips(e)}</td><td>${sevBadge(e.severity)}</td></tr>`)}</tbody></table>` : empty("No findings")}</div>
        <div class="card"><h2>Trending now</h2>${tr.length ? html`<table><tbody>${tr.map((t) => html`<tr><td><a href="#/finding/${t.entity_id}">${t.cve_id || t.title}</a><div class="small muted">${t.mentions} mentions · ${t.source_count} source${t.source_count === 1 ? "" : "s"}</div></td><td>${sevBadge(t.severity)}</td><td class="mono">${trendArrow(t.trend)}</td></tr>`)}</tbody></table><div class="small" style="margin-top:8px"><a href="#/trending">All trending →</a></div>` : empty("Nothing trending")}</div>
      </div>`,
    };
  });
  const trendArrow = (t) => ({ up: "↑", down: "↓", flat: "→" }[t.direction] || "→") + ` ${t.score}`;

  // ── Findings feed ──
  E.route(/^findings$/, async ({ params }) => {
    const keys = ["q", "severity", "min_risk", "source", "platform", "status", "cve", "zero_day", "poc", "active", "has_cve", "type", "include_roundups", "sort", "order", "per_page", "page"];
    const r = await api("/vulns" + qs(pick(params, keys)));
    const fields = [
      { name: "q", label: "Search", ph: "title, CVE, product…", w: 200 },
      { name: "severity", label: "Severity", type: "select", options: [any, ...SEV.map((s) => [s, label(s)])] },
      { name: "min_risk", label: "Min risk", ph: "0-100", w: 70 },
      { name: "source", label: "Source", ph: "e.g. BleepingComputer", w: 150 },
      { name: "cve", label: "CVE", ph: "CVE-2026-…", w: 130 },
      { name: "platform", label: "Platform", type: "select", options: [any, ["blog", "Blog / RSS"], ["github", "GitHub"], ["nvd", "NVD"], ["cisa", "CISA KEV"], ["reddit", "Reddit"]] },
      { name: "zero_day", label: "Zero-day", type: "select", options: yn },
      { name: "active", label: "Active exploit", type: "select", options: yn },
      { name: "poc", label: "PoC", type: "select", options: yn },
      { name: "has_cve", label: "Has CVE", type: "select", options: yn },
      { name: "status", label: "Analyst status", type: "select", options: [any, ...STATUSES.map((s) => [s, label(s)])] },
      { name: "sort", label: "Sort by", type: "select", options: [["risk", "Risk"], ["first_seen", "First seen"], ["last_updated", "Last updated"], ["mentions", "Mentions"], ["sources", "Sources"], ["cvss", "CVSS"], ["epss", "EPSS"], ["trend", "Trend"], ["zero_day", "Zero-day score"]] },
      { name: "order", label: "Order", type: "select", options: [["desc", "High → low"], ["asc", "Low → high"]] },
      { name: "per_page", label: "Per page", type: "select", options: [["25", "25"], ["50", "50"], ["100", "100"]] },
      { name: "include_roundups", label: "Include roundup articles", type: "checkbox" },
    ];
    return {
      title: "Findings", html: html`<h1>Findings</h1><p class="sub">One finding per vulnerability — evidence from blogs, GitHub and NVD is correlated into a single record.</p>
      ${filterBar(fields, params)}
      ${r.items.length ? html`<div class="card tw"><table><thead><tr><th>Risk</th><th>Finding</th><th>Severity</th><th title="Independent publishers">Sources</th><th>Status</th><th>First seen</th><th>Updated</th></tr></thead><tbody>
        ${r.items.map((e) => html`<tr><td>${riskBadge(e.risk_score)}</td><td><a href="#/finding/${e.id}">${e.title}</a>${chips(e)}</td><td>${sevBadge(e.severity)}</td>
          <td title="${e.sources.join(", ")}" class="mono">${e.cross_source_count}</td><td>${statusBadge(e.analyst.status)}</td><td class="small">${fmtTs(e.first_seen)}</td><td class="small">${ago(e.last_updated)}</td></tr>`)}
      </tbody></table></div>${pager(r.page, r.pages, r.total)}` : html`<div class="card">${empty("No findings match these filters.")}</div>`}`,
    };
  });

  // ── Finding detail ──
  const leadPanel = (e) => {
    const lt = e.lead_time || {}, row = (k, v) => [k, v];
    let headline;
    if (lt.status === "early") headline = html`<div style="font-size:28px;font-weight:700;color:var(--ok)" class="mono">${lt.human}</div><div>ahead of the CVE record</div>`;
    else if (lt.status === "after_cve") headline = html`<div style="font-size:20px;font-weight:700;color:var(--warn)" class="mono">No lead time</div><div>Earliest signal trailed CVE publication by ${lt.human}</div>`;
    else headline = html`<div style="font-size:18px;font-weight:600" class="muted">${{ no_cve: "Awaiting CVE", no_signal: "Not measurable", no_timestamp: "No timestamps" }[lt.status] || "Not available"}</div>`;
    return html`<div class="card"><h2>Early-detection lead time</h2>${headline}<p class="small muted">${lt.note || ""}${lt.basis === "evvp_detection" ? " (measured from when EVVP first collected it)" : lt.basis === "public_signal" ? " (measured from the first public signal's own timestamp)" : ""}</p>
      ${kv([row("First seen", fmtTs(e.first_seen)), row("First public signal", fmtTs(e.first_public_signal)), row("EVVP first collected", fmtTs(e.first_collected)), row("CVE published", fmtTs(e.cve_published))])}</div>`;
  };
  const riskPanel = (e) => html`<div class="card"><h2>Risk score</h2><div style="display:flex;align-items:center;gap:14px;margin-bottom:10px"><div style="font-size:38px;font-weight:800" class="mono">${e.risk_score}<span class="faint" style="font-size:16px">/100</span></div><div style="flex:1"><div class="meter"><i style="width:${e.risk_score}%;background:${e.risk_score >= 80 ? "var(--crit)" : e.risk_score >= 60 ? "var(--high)" : e.risk_score >= 40 ? "var(--med)" : "var(--low)"}"></i></div><div class="small muted" style="margin-top:4px">Sum of the transparent components below, capped at 100</div></div></div>
    ${(e.risk_breakdown || []).length ? html`<table><thead><tr><th>Factor</th><th>Evidence</th><th style="text-align:right">Points</th></tr></thead><tbody>${e.risk_breakdown.map((p) => html`<tr><td>✓ ${p.factor}</td><td class="muted">${p.detail}</td><td class="mono" style="text-align:right">+${p.points}</td></tr>`)}</tbody></table>` : empty("No scoring evidence")}</div>`;
  const zdPanel = (e) => html`<div class="card"><h2>Zero-day assessment</h2>${e.zero_day_candidate
    ? html`<div><span class="badge b-zd" style="font-size:13px">POTENTIAL ZERO-DAY CANDIDATE</span> <b class="mono">Confidence ${e.zero_day_score}/100</b></div><ul class="chk" style="margin-top:10px">${e.zero_day_evidence.map((x) => html`<li>${x}</li>`)}</ul><p class="note">An unverified indicator based on the evidence above — not a confirmed zero-day. Confirm with the vendor or a CVE assignment.</p>`
    : html`<p class="muted">Not flagged as a candidate (score ${e.zero_day_score}/100${e.has_cve ? "; a CVE identifier already exists" : ""}).</p>${e.zero_day_evidence.length ? html`<ul class="chk">${e.zero_day_evidence.map((x) => html`<li>${x}</li>`)}</ul>` : ""}`}</div>`;
  const timelinePanel = (e) => html`<div class="card"><h2>Correlation timeline</h2>${e.timeline.events.length ? html`<div class="tl">${e.timeline.events.map((ev) => html`<div class="ev ${ev.first_observed ? "first" : ""}"><div class="small mono muted">${fmtTs(ev.ts)} ${ev.first_observed ? html`<span class="badge b-ok">FIRST OBSERVED</span>` : ""} <span class="faint">(${ev.basis})</span></div><div><b>${ev.label}</b> · ${ev.source}</div>${ev.title ? html`<div class="small">${ev.url ? ext(ev.url, ev.title) : ev.title}</div>` : ""}</div>`)}</div>` : empty("No dated evidence")}
    ${e.timeline.undated_mentions ? html`<p class="small muted">${e.timeline.undated_mentions} further mention${e.timeline.undated_mentions === 1 ? "" : "s"} had no reliable timestamp and are not placed on the timeline.</p>` : ""}</div>`;

  E.route(/^finding\/([^/]+)$/, async ({ args: [id] }) => {
    const e = await api("/vulns/" + encodeURIComponent(id));
    return {
      title: e.title, html: html`
      <p class="small"><a href="#/findings">← All findings</a></p>
      <h1>${e.title}</h1>
      <div class="chips" style="margin:6px 0 14px">${sevBadge(e.severity)} ${statusBadge(e.analyst.status)} ${e.roundup ? html`<span class="badge b-warn">ROUNDUP ARTICLE</span>` : ""}${e.vendor_confirmed ? html`<span class="badge b-ok">VENDOR ADVISORY</span>` : ""}${e.nvd_confirmed ? html`<span class="badge b-ok">NVD RECORD</span>` : e.has_cve ? html`<span class="badge b-warn" title="${e.nvd_status === "unavailable" ? "NVD enrichment temporarily unavailable" : ""}">${e.nvd_status === "unavailable" ? "NVD ENRICHMENT UNAVAILABLE" : "NO NVD RECORD YET"}</span>` : ""}</div>
      ${chips(e)}
      <div class="card" style="margin:14px 0"><h2>Description</h2><p style="white-space:pre-wrap;margin:0">${e.description || "Not available"}</p></div>
      <div class="grid g2">
        ${riskPanel(e)}${zdPanel(e)}${leadPanel(e)}
        <div class="card"><h2>Vulnerability intelligence</h2>${kv([
          ["CVE", e.cve_ids.length ? html`${e.cve_ids.map((c) => html`<a class="mono" href="#/cve/${c}">${c}</a> `)}` : html`<span class="muted">No CVE identifier found yet</span>`],
          ["CVSS", e.cvss != null ? html`<b class="mono">${num(e.cvss)}</b> <span class="muted small mono">${e.cvss_vector || ""}</span>` : null],
          ["EPSS", e.epss != null ? html`<b class="mono">${pct(e.epss, 2)}</b> <span class="muted small">percentile ${pct(e.epss_percentile, 1)}${e.epss_date ? ` · as of ${e.epss_date}` : ""}</span>` : null],
          ["Active exploitation", e.active_exploitation ? "Reported" : "None detected"], ["PoC / exploit code", e.poc ? "Detected" : "None detected"],
          ["Vulnerability types", (e.vuln_types || []).join(", ")], ["Affected products", (e.affected_products || []).join(", ")],
          ["Independent sources", html`<b>${e.cross_source_count}</b> — ${e.sources.join(", ")}`], ["Mentions", e.mentions], ["Last updated", fmtTs(e.last_updated)]])}</div>
        <div class="card"><h2>MITRE ATT&amp;CK</h2>${e.attack_techniques.length ? html`<table><tbody>${e.attack_techniques.map((t) => html`<tr><td class="mono"><a href="https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/" target="_blank" rel="noopener noreferrer">${t.id}</a></td><td>${t.name}<div class="small muted">matched “${t.matched}”</div></td></tr>`)}</tbody></table>` : html`<p class="muted">No technique mapped — insufficient evidence in the text.</p>`}</div>
        ${timelinePanel(e)}
        <div class="card"><h2>Evidence &amp; sources</h2><div class="tw"><table><thead><tr><th>Source</th><th>Type</th><th>Trust</th><th>Observed</th><th>Link</th></tr></thead><tbody>${e.evidence.map((v) => html`<tr><td>${v.source}<div class="small faint">${v.platform || ""}${v.context ? " · roundup mention" : ""}</div></td><td class="small">${label(v.type)}</td><td>${trustBadge(v.trust)}</td><td class="small">${fmtTs(v.observed_at || v.collected_at)}</td><td class="small">${v.url ? ext(v.url, "open ↗") : ""}</td></tr>`)}</tbody></table></div></div>
        ${e.references.length ? html`<div class="card"><h2>References (NVD)</h2><ul style="padding-left:18px;margin:0">${e.references.map((u) => html`<li class="small">${ext(u)}</li>`)}</ul></div>` : ""}
        <div class="card" style="grid-column:1/-1"><h2>Analyst verification</h2>
          <div class="grid g2"><div>
            <div class="row"><label class="small muted" for="a-name">Analyst</label><input id="a-name" value="${E.analyst()}" maxlength="80" style="width:100%"></div>
            <div class="row" style="margin-top:8px"><label class="small muted" for="a-status">Decision</label><select id="a-status" style="width:100%">${STATUSES.map((s) => raw(`<option value="${s}"${s === e.analyst.status ? " selected" : ""}>${esc(label(s))}</option>`))}</select></div>
            <div class="row" style="margin-top:8px"><label class="small muted" for="a-notes">Notes</label><textarea id="a-notes" maxlength="4000" placeholder="e.g. Confirmed by vendor advisory."></textarea></div>
            <div class="fe" id="a-err"></div>
            <div style="display:flex;gap:8px"><button class="primary" id="a-save">Save decision</button><button id="a-note">Add note only</button></div>
          </div><div><h3>History</h3>${e.analyst_history.length ? [...e.analyst_history].reverse().map((h) => html`<div class="hist"><div class="small mono muted">${fmtTs(h.ts)} · ${h.analyst}</div><div>${h.kind === "note" ? html`<span class="badge b-mute">NOTE</span>` : html`${statusBadge(h.previous_status)} → ${statusBadge(h.status)}`}</div>${h.notes ? html`<div class="small" style="white-space:pre-wrap">${h.notes}</div>` : ""}</div>`) : html`<p class="muted small">No analyst decisions yet. Status is “Potential” until reviewed.</p>`}</div></div>
        </div>
      </div>`,
      after: (root) => {
        const submit = async (kind) => {
          const err = root.querySelector("#a-err"); err.textContent = "";
          const body = { analyst: root.querySelector("#a-name").value.trim(), status: root.querySelector("#a-status").value, notes: root.querySelector("#a-notes").value.trim() };
          if (!body.analyst) { err.textContent = "Analyst name is required."; return; }
          if (kind === "note" && !body.notes) { err.textContent = "Write a note first."; return; }
          const btns = root.querySelectorAll("#a-save,#a-note"); btns.forEach((b) => (b.disabled = true));
          try { await api(`/vulns/${encodeURIComponent(id)}/${kind === "note" ? "notes" : "review"}`, { method: "POST", body }); E.toast(kind === "note" ? "Note added" : `Marked ${label(body.status)}`, "ok"); E.reload(); }
          catch (x) { err.textContent = x.message; btns.forEach((b) => (b.disabled = false)); }
        };
        root.querySelector("#a-save").onclick = () => submit("decision");
        root.querySelector("#a-note").onclick = () => submit("note");
      },
    };
  });

  // ── Zero-days ──
  E.route(/^zerodays$/, async ({ params }) => {
    const r = await api("/zerodays" + qs({ min_score: params.min_score || 45, page: params.page, per_page: 20 }));
    return {
      title: "Potential Zero-Days", html: html`<h1>Potential zero-day candidates</h1>
      <p class="sub">Findings with <b>no CVE yet</b> and zero-day terminology, exploitation or PoC evidence. These are <b>unconfirmed candidates, not certainties</b>.</p>
      ${filterBar([{ name: "min_score", label: "Minimum confidence", type: "select", options: [["30", "30+"], ["45", "45+ (default)"], ["60", "60+"], ["75", "75+"]] }], { min_score: params.min_score || "45" })}
      ${r.items.length ? r.items.map((e) => html`<div class="card" style="margin-bottom:12px"><div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap"><div style="flex:1;min-width:260px"><a href="#/finding/${e.id}" style="font-size:16px;font-weight:600">${e.title}</a>
        <div class="chips">${statusBadge(e.analyst.status)}${e.active_exploitation ? html`<span class="badge b-act">ACTIVE EXPLOITATION</span>` : ""}${e.poc ? html`<span class="badge b-poc">PoC AVAILABLE</span>` : html`<span class="badge b-mute">NO PoC SEEN</span>`}<span class="badge ${e.has_cve ? "b-ok" : "b-warn"}">${e.has_cve ? "CVE ASSIGNED" : "NO CVE FOUND"}</span></div></div>
        <div style="text-align:right"><div class="mono" style="font-size:26px;font-weight:800;color:#c98bff">${e.zero_day_score}<span class="faint" style="font-size:13px">/100</span></div><div class="small muted">confidence</div></div></div>
        <div class="meter" style="margin:10px 0"><i style="width:${e.zero_day_score}%;background:#b45cff"></i></div>
        <div class="grid g3"><div><h3>Evidence</h3><ul class="chk">${e.zero_day_evidence.map((x) => html`<li>${x}</li>`)}</ul></div>
        <div><h3>Assessment</h3>${kv([["Risk", html`${riskBadge(e.risk_score)} ${sevBadge(e.severity)}`], ["Sources", e.sources.join(", ")], ["First seen", fmtTs(e.first_seen)]])}</div></div></div>`) : html`<div class="card">${empty("No potential zero-day candidates at this confidence level. Lower the minimum confidence or wait for more collection.")}</div>`}
      ${r.items.length ? pager(r.page, r.pages, r.total) : ""}`,
    };
  });

  // ── CVEs ──
  E.route(/^cves$/, async ({ params }) => {
    const r = await api("/cves" + qs(pick(params, ["q", "severity", "nvd", "min_risk", "sort", "order", "page"])));
    const fields = [{ name: "q", label: "Search", ph: "CVE, description, product", w: 220 }, { name: "severity", label: "Severity", type: "select", options: [any, ...SEV.map((s) => [s, label(s)])] },
      { name: "nvd", label: "NVD record", type: "select", options: [["", "Any"], ["true", "Available"], ["false", "Missing"]] }, { name: "min_risk", label: "Min risk", ph: "0-100", w: 70 },
      { name: "sort", label: "Sort by", type: "select", options: [["risk", "Risk"], ["cvss", "CVSS"], ["epss", "EPSS"], ["first_seen", "First seen"], ["published", "Published"], ["sources", "Sources"]] }, { name: "order", label: "Order", type: "select", options: [["desc", "High → low"], ["asc", "Low → high"]] }];
    return {
      title: "CVEs", html: html`<h1>CVE intelligence</h1><p class="sub">CVE identifiers found in collected evidence, enriched with NVD (CVSS) and EPSS where available.</p>${filterBar(fields, params)}
      ${r.items.length ? html`<div class="card tw"><table><thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>Risk</th><th>Sources</th><th>First seen</th><th>NVD</th></tr></thead><tbody>${r.items.map((c) => html`<tr><td><a class="mono" href="#/cve/${c.cve_id}">${c.cve_id}</a><div class="small muted" style="max-width:420px">${(c.description || c.title || "").slice(0, 110)}</div></td><td>${sevBadge(c.severity)}</td><td class="mono">${c.cvss != null ? num(c.cvss) : html`<span class="faint">n/a</span>`}</td><td class="mono">${c.epss != null ? pct(c.epss, 2) : html`<span class="faint">n/a</span>`}</td><td>${riskBadge(c.risk_score)}</td><td class="mono" title="${c.sources.join(", ")}">${c.cross_source_count}</td><td class="small">${fmtTs(c.first_seen)}</td><td>${c.nvd_available ? html`<span class="badge b-ok">YES</span>` : html`<span class="badge b-mute">NO</span>`}</td></tr>`)}</tbody></table></div>${pager(r.page, r.pages, r.total)}` : html`<div class="card">${empty("No CVEs match these filters.")}</div>`}`,
    };
  });

  E.route(/^cve\/([^/]+)$/, async ({ args: [id] }) => {
    const c = await api("/cves/" + encodeURIComponent(id));
    const view = { ...c, timeline: c.timeline, lead_time: c.lead_time };
    return {
      title: c.cve_id, html: html`<p class="small"><a href="#/cves">← All CVEs</a></p><h1 class="mono">${c.cve_id}</h1>
      <div class="chips" style="margin:6px 0 14px">${sevBadge(c.severity)} ${statusBadge(c.analyst.status)}${c.active_exploitation ? html`<span class="badge b-act">ACTIVE EXPLOITATION</span>` : ""}${c.poc ? html`<span class="badge b-poc">PoC</span>` : ""}${c.nvd_available ? html`<span class="badge b-ok">NVD RECORD</span>` : html`<span class="badge b-warn">NVD RECORD NOT AVAILABLE</span>`}</div>
      <div class="card" style="margin-bottom:14px"><h2>Description</h2><p style="margin:0;white-space:pre-wrap">${c.description || html`<span class="faint">Not available — NVD has no record for this CVE yet (or enrichment was unavailable).</span>`}</p><p class="small" style="margin:10px 0 0"><a href="#/finding/${c.entity_id}">Open the full finding / analyst workflow →</a></p></div>
      <div class="grid g2">
        <div class="card"><h2>Scores</h2>${kv([["CVSS v3", c.cvss != null ? html`<b class="mono">${num(c.cvss)}</b> ${sevBadge(c.severity)}` : null], ["CVSS vector", c.cvss_vector ? html`<span class="mono small">${c.cvss_vector}</span>` : null], ["EPSS", c.epss != null ? html`<b class="mono">${pct(c.epss, 2)}</b>` : null], ["EPSS percentile", c.epss_percentile != null ? pct(c.epss_percentile, 1) : null], ["Risk", html`${riskBadge(c.risk_score)}`]])}</div>
        <div class="card"><h2>Record</h2>${kv([["Published", fmtTs(c.published)], ["Last modified", fmtTs(c.modified)], ["First seen", fmtTs(c.first_seen)], ["Affected products", (c.affected_products || []).join(", ")], ["Independent sources", html`<b>${c.cross_source_count}</b> — ${c.sources.join(", ")}`], ["Mentions", c.mentions]])}</div>
        ${leadPanel(view)}${timelinePanel(view)}
        <div class="card"><h2>References</h2>${c.references.length ? html`<ul style="padding-left:18px;margin:0">${c.references.map((u) => html`<li class="small">${ext(u)}</li>`)}</ul>` : html`<p class="muted">Not available</p>`}</div>
        <div class="card"><h2>MITRE ATT&amp;CK</h2>${c.attack_techniques.length ? html`<ul class="chk">${c.attack_techniques.map((t) => html`<li><span class="mono">${t.id}</span> ${t.name}</li>`)}</ul>` : html`<p class="muted">No technique mapped.</p>`}</div>
      </div>`,
    };
  });

  // ── Trending ──
  E.route(/^trending$/, async ({ params }) => {
    const hours = params.hours || "0", r = await api("/trending" + qs({ hours, top: 25 }));
    return {
      title: "Trending", html: html`<h1>Trending vulnerabilities</h1><p class="sub">Ranked by <b>mentions</b>, <b>independent sources</b>, <b>24h velocity</b>, <b>risk</b> and <b>exploitation</b> — not by recency alone.</p>
      ${filterBar([{ name: "hours", label: "Activity window", type: "select", options: [["0", "All time"], ["24", "Last 24 hours"], ["72", "Last 3 days"], ["168", "Last 7 days"]] }], { hours })}
      ${r.length ? html`<div class="card tw"><table><thead><tr><th>#</th><th>Vulnerability</th><th>Mentions</th><th>Sources</th><th>Risk</th><th>Severity</th><th title="Evidence in the last 24h vs the 24h before">Trend</th></tr></thead><tbody>${r.map((t, i) => html`<tr><td class="muted">${i + 1}</td><td><a href="#/finding/${t.entity_id}">${t.cve_id || t.title}</a>${t.cve_id ? html`<div class="small muted">${t.title}</div>` : ""}<div class="chips">${t.zero_day_candidate ? html`<span class="badge b-zd">POTENTIAL ZERO-DAY</span>` : ""}${t.active_exploitation ? html`<span class="badge b-act">ACTIVE</span>` : ""}</div></td><td class="mono">${t.mentions}</td><td class="mono" title="${t.sources.join(", ")}">${t.source_count}</td><td>${riskBadge(t.risk_score)}</td><td>${sevBadge(t.severity)}</td><td class="mono" title="${t.trend.recent_24h} in last 24h, ${t.trend.previous_24h} in the 24h before">${trendArrow(t.trend)}<div class="small faint">${t.trend.recent_24h}/${t.trend.previous_24h} (24h)</div></td></tr>`)}</tbody></table></div>` : html`<div class="card">${empty("Nothing trending in this window.")}</div>`}`,
    };
  });

  // ── Threat landscape ──
  E.route(/^landscape$/, async ({ params }) => {
    const days = params.days || "0", t = await api("/threat-landscape" + qs({ days }));
    return {
      title: "Threat Landscape", html: html`<h1>Threat landscape</h1><p class="sub">Aggregate view of what the collected intelligence says about the current threat environment.</p>
      ${filterBar([{ name: "days", label: "Window", type: "select", options: [["0", "All time"], ["7", "Last 7 days"], ["30", "Last 30 days"], ["90", "Last 90 days"]] }], { days })}
      <div class="stats">${[["Findings", t.total, "var(--accent)"], ["Critical", t.critical, "var(--crit)"], ["High", t.high, "var(--high)"], ["Medium", t.medium, "var(--med)"], ["Low", t.low, "var(--low)"], ["Potential zero-days", t.zero_day_candidates, "#c98bff"], ["Active exploitation", t.active_exploitation, "var(--bad)"], ["Average risk", t.average_risk, "var(--warn)"]].map(([l, v, c]) => html`<div class="stat" style="border-top-color:${c}"><div class="v" style="color:${c}">${v}</div><div class="l">${l}</div></div>`)}</div>
      <div class="grid g2">
        <div class="card"><h2>Top vulnerability categories</h2>${hbars(t.categories.map((c) => ({ name: `${c.name} (${c.share}%)`, count: c.count })))}</div>
        <div class="card"><h2>High-risk categories <span class="faint small">(average risk)</span></h2>${hbars(t.high_risk_categories.map((c) => ({ name: c.name, count: c.avg_risk })), { color: "var(--high)", max: 100 })}</div>
        <div class="card"><h2>Top attack techniques</h2>${hbars(t.attack_techniques, { color: "#b45cff" })}</div>
        <div class="card"><h2>Top sources</h2>${hbars(t.top_sources, { color: "var(--ok)" })}</div>
        <div class="card"><h2>Trending threats</h2>${t.trending.length ? html`<table><tbody>${t.trending.map((e) => html`<tr><td><a href="#/finding/${e.id}">${e.title}</a></td><td>${sevBadge(e.severity)}</td><td class="mono">${e.trend.score}</td></tr>`)}</tbody></table>` : empty("None")}</div>
        <div class="card"><h2>Highest-risk findings</h2>${t.top_risk_items.length ? html`<table><tbody>${t.top_risk_items.slice(0, 6).map((e) => html`<tr><td>${riskBadge(e.risk_score)}</td><td><a href="#/finding/${e.id}">${e.title}</a></td></tr>`)}</tbody></table>` : empty("None")}</div>
      </div>`,
    };
  });

  // ── Source manager ──
  const srcStatus = (s) => (!s.enabled ? html`<span class="badge b-mute">DISABLED</span>` : !s.collectable ? html`<span class="badge b-warn" title="Registered, but EVVP has no collector adapter for this source type yet">NO ADAPTER</span>` : s.status === "healthy" ? html`<span class="badge b-ok">HEALTHY</span>` : s.status === "error" ? html`<span class="badge b-act">ERROR</span>` : html`<span class="badge b-mute">NOT YET COLLECTED</span>`);
  function sourceForm(opts, src) {
    const o = (list, cur) => list.map((x) => raw(`<option value="${esc(x)}"${x === cur ? " selected" : ""}>${esc(label(x))}</option>`));
    const s = src || { name: "", url: "", type: "rss", category: "news", trust: "medium", interval_minutes: 30, enabled: true };
    return html`<h2>${src ? "Edit source" : "Add source"}</h2>
      <div class="row"><label class="l" for="f-name">Name</label><input id="f-name" value="${s.name}" maxlength="120" placeholder="SecurityWeek"></div>
      <div class="row"><label class="l" for="f-url">Feed / API URL</label><input id="f-url" value="${s.url}" ${s.builtin ? "disabled" : ""} placeholder="https://example.com/feed"></div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
        <div class="row"><label class="l" for="f-type">Type</label><select id="f-type">${o(opts.types, s.type)}</select></div>
        <div class="row"><label class="l" for="f-cat">Category</label><select id="f-cat">${o(opts.categories, s.category)}</select></div>
        <div class="row"><label class="l" for="f-trust">Trust level</label><select id="f-trust">${o(opts.trust, s.trust)}</select></div>
        <div class="row"><label class="l" for="f-int">Collection interval (minutes, ${opts.interval_minutes.min}–${opts.interval_minutes.max})</label><input id="f-int" type="number" min="${opts.interval_minutes.min}" max="${opts.interval_minutes.max}" value="${s.interval_minutes}"></div>
      </div>
      <fieldset id="f-map" class="small" style="border:1px solid var(--line, #2a3550);border-radius:8px;padding:8px 10px;margin:0 0 8px" ${s.builtin || !["api", "custom"].includes(s.type) ? "hidden" : ""}>
        <legend class="muted">JSON field mapping (dotted paths into the response)</legend>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
          ${[["m-items", "Items list path", "items_path", "data.advisories"], ["m-id", "ID field", "id_field", "advisory_id"], ["m-title", "Title field (required)", "title_field", "name"], ["m-url", "Link field", "url_field", "link"], ["m-date", "Date field", "date_field", "issued"], ["m-text", "Description field", "text_field", "summary"]].map(([id, lab, key, ph]) => html`<div class="row"><label class="l" for="${id}">${lab}</label><input id="${id}" value="${(s.mapping || {})[key] || ""}" placeholder="${ph}"></div>`)}
        </div>
      </fieldset>
      <label style="display:flex;gap:6px;align-items:center;margin-bottom:8px"><input type="checkbox" id="f-en" ${s.enabled ? "checked" : ""}> Enabled — collect automatically on this interval</label>
      <p class="small muted" id="f-hint">Sources are never trusted automatically: choose the trust level deliberately. It feeds the risk score.</p>
      <div id="f-test"></div><div class="fe" id="f-err"></div>
      <div class="acts"><button data-close>Cancel</button><button id="f-try">Test source</button><button class="primary" id="f-save">${src ? "Save changes" : "Add source"}</button></div>`;
  }
  function openSourceModal(opts, src) {
    E.modal(sourceForm(opts, src), (m, close) => {
      const g = (id) => m.querySelector(id), err = g("#f-err");
      const read = () => ({ name: g("#f-name").value.trim(), url: g("#f-url").value.trim(), type: g("#f-type").value, category: g("#f-cat").value, trust: g("#f-trust").value, interval_minutes: Number(g("#f-int").value), enabled: g("#f-en").checked, actor: E.analyst(), ...mapping() });
      const mapping = () => {                         // only API/custom sources carry a field mapping
        if (!["api", "custom"].includes(g("#f-type").value) || (src && src.builtin)) return {};
        const m = {}; [["m-items", "items_path"], ["m-id", "id_field"], ["m-title", "title_field"], ["m-url", "url_field"], ["m-date", "date_field"], ["m-text", "text_field"]].forEach(([id, k]) => { const v = g("#" + id).value.trim(); if (v) m[k] = v; });
        return { mapping: m };
      };
      const hint = () => { const t = g("#f-type").value, map = ["api", "custom"].includes(t) && !(src && src.builtin); g("#f-map").hidden = !map;
        g("#f-hint").textContent = map ? "API/custom source: describe where the fields are in the JSON response (title field is required). Use Test source to preview the parsed entries." : "Sources are never trusted automatically: choose the trust level deliberately. It feeds the risk score."; };
      g("#f-type").onchange = hint; hint();
      g("#f-try").onclick = async () => {
        const d = read(), box = g("#f-test"); err.textContent = ""; if (!d.url) { err.textContent = "Enter a URL to test."; return; }
        box.innerHTML = '<p class="muted small"><span class="spin"></span>Testing…</p>';
        try { const r = await api("/sources/test", { method: "POST", body: { url: d.url, type: d.type, mapping: d.mapping, actor: d.actor }, okStatuses: [422] });
          box.innerHTML = r.valid ? html`<div class="note" style="border-left-color:var(--ok)"><b>Source test passed</b>${r.feed_title ? ` — ${r.feed_title}` : ""}${r.entry_count != null ? ` · ${r.entry_count} entries` : ""}${(r.entries || []).slice(0, 3).map((x) => html`<div class="small">• ${x.title}</div>`)}</div>`.s : html`<div class="note" style="border-left-color:var(--bad)"><b>Source test failed</b> — ${r.error || "unknown error"}</div>`.s;
        } catch (x) { box.innerHTML = html`<div class="note" style="border-left-color:var(--bad)">${x.message}</div>`.s; }
      };
      g("#f-save").onclick = async () => {
        const d = read(); err.textContent = ""; if (!d.name) { err.textContent = "Name is required."; return; } if (!src && !d.url) { err.textContent = "URL is required."; return; }
        g("#f-save").disabled = true;
        try { if (src) { delete d.url; if (!src.builtin) d.url = g("#f-url").value.trim(); await api("/sources/" + src.id, { method: "PATCH", body: d }); } else await api("/sources", { method: "POST", body: d });
          close(); E.toast(src ? "Source updated" : "Source added", "ok"); E.reload();
        } catch (x) { err.textContent = x.message; g("#f-save").disabled = false; }
      };
    });
  }
  let SRC = { sources: [], options: null };
  E.route(/^sources$/, async ({ params }) => {
    SRC = await api("/sources"); const f = (params.status || ""), q = (params.q || "").toLowerCase();
    const rows = SRC.sources.filter((s) => (!q || `${s.name} ${s.url}`.toLowerCase().includes(q)) && (!f || (f === "enabled" ? s.enabled : f === "disabled" ? !s.enabled : f === "error" ? s.status === "error" && s.enabled : true)));
    const healthy = SRC.sources.filter((s) => s.enabled && s.status === "healthy").length, failing = SRC.sources.filter((s) => s.enabled && s.status === "error").length;
    return {
      title: "Sources", html: html`<div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:flex-start"><div><h1>Source manager</h1><p class="sub">Analysts approve sources manually; once enabled, collection and analysis are automatic on each source's interval. ${SRC.sources.length} sources · ${healthy} healthy · ${failing} failing.</p></div><button class="primary" data-act="src-add">+ Add source</button></div>
      ${filterBar([{ name: "q", label: "Search", ph: "name or URL", w: 200 }, { name: "status", label: "Show", type: "select", options: [["", "All"], ["enabled", "Enabled"], ["disabled", "Disabled"], ["error", "Failing"]] }], params)}
      ${rows.length ? html`<div class="card tw"><table><thead><tr><th>Source</th><th>Type</th><th>Category</th><th>Trust</th><th>Interval</th><th>Status</th><th>Last success</th><th>Collected</th><th>Actions</th></tr></thead><tbody>${rows.map((s) => html`<tr data-id="${s.id}"><td><b>${s.name}</b>${s.builtin ? html` <span class="badge b-mute">BUILT-IN</span>` : ""}<div class="small muted" style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${s.url}">${s.url}</div>${s.last_error ? html`<div class="small" style="color:var(--bad);max-width:300px" title="${s.last_error}">⚠ ${s.last_error.slice(0, 90)}${s.consecutive_failures > 1 ? ` (${s.consecutive_failures} failures in a row)` : ""}</div>` : ""}</td>
        <td class="mono">${s.type.toUpperCase()}</td><td>${label(s.category)}</td><td>${trustBadge(s.trust)}</td><td class="mono">${s.interval_minutes} min</td><td>${srcStatus(s)}</td><td class="small">${s.last_success ? html`${ago(s.last_success)}<div class="faint">${fmtTs(s.last_success)}</div>` : html`<span class="faint">never</span>`}</td><td class="mono">${s.total_collected}</td>
        <td style="white-space:nowrap"><button data-act="src-toggle" data-id="${s.id}" data-en="${s.enabled}">${s.enabled ? "Disable" : "Enable"}</button> <button data-act="src-test" data-id="${s.id}">Test</button> ${["rss", "atom"].includes(s.type) ? html`<button data-act="src-collect" data-id="${s.id}" ${s.enabled ? "" : "disabled"}>Collect now</button> ` : ""}<button data-act="src-edit" data-id="${s.id}">Edit</button> ${s.builtin ? "" : html`<button class="danger" data-act="src-del" data-id="${s.id}">Delete</button>`}</td></tr>`)}</tbody></table></div>` : html`<div class="card">${empty("No sources match.")}</div>`}
      <div class="card" style="margin-top:14px"><h3>Trust levels (feed the risk score)</h3><div class="small muted">${Object.entries(SRC.options.trust_weight).map(([k, v]) => `${label(k)} = ${v}`).join(" · ")}</div></div>`,
    };
  });
  const byId = (id) => SRC.sources.find((s) => s.id === id);
  const busy = async (el, fn) => { el.disabled = true; try { await fn(); } catch (x) { E.toast(x.message, "bad"); } finally { el.disabled = false; } };
  Object.assign(E.actions, {
    "src-add": () => openSourceModal(SRC.options),
    "src-edit": (el) => openSourceModal(SRC.options, byId(el.dataset.id)),
    "src-toggle": (el) => busy(el, async () => { const on = el.dataset.en !== "true"; await api("/sources/" + el.dataset.id, { method: "PATCH", body: { enabled: on, actor: E.analyst() } }); E.toast(on ? "Source enabled" : "Source disabled", "ok"); E.reload(); }),
    "src-test": (el) => busy(el, async () => { el.textContent = "Testing…"; const r = await api(`/sources/${el.dataset.id}/test`, { method: "POST", body: { actor: E.analyst() }, okStatuses: [422] }); E.toast(r.valid ? `Source test passed${r.entry_count != null ? ` — ${r.entry_count} entries` : ""}` : `Source test failed: ${r.error}`, r.valid ? "ok" : "bad"); E.reload(); }),
    "src-collect": (el) => busy(el, async () => { await api(`/sources/${el.dataset.id}/collect`, { method: "POST", body: {}, okStatuses: [202] }); E.toast("Collection started in the background — refresh in a few seconds", "ok"); setTimeout(E.reload, 6000); }),
    "src-del": (el) => { const s = byId(el.dataset.id); E.modal(html`<h2>Delete source?</h2><p>Remove <b>${s.name}</b>? Already-collected evidence stays; no new items will be collected.</p><div class="acts"><button data-close>Cancel</button><button class="danger" id="d-ok">Delete</button></div>`, (m, close) => { m.querySelector("#d-ok").onclick = async () => { try { await api("/sources/" + s.id, { method: "DELETE", body: { actor: E.analyst() } }); close(); E.toast("Source deleted", "ok"); E.reload(); } catch (x) { close(); E.toast(x.message, "bad"); } }; }); },
  });

  // ── Audit ──
  const EVENTS = ["source_added", "source_edited", "source_enabled", "source_disabled", "source_deleted", "source_tested", "source_collect_triggered", "source_collected", "source_fetch_fail", "finding_reviewed", "finding_confirmed", "finding_false_positive", "finding_resolved", "analyst_note_added", "item_collected", "item_passed", "item_dropped", "item_duplicate", "item_novel", "nvd_enriched", "nvd_fetch_fail", "trending_detected", "notification_sent", "worker_error", "system_start", "system_stop", "error"];
  E.route(/^audit$/, async ({ params }) => {
    const [rows, st] = await Promise.all([api("/audit" + qs({ n: params.n || 200, event: params.event, q: params.q })), api("/audit/stats")]);
    const list = [...rows].reverse();
    return {
      title: "Audit", html: html`<h1>Audit log</h1><p class="sub">Every source change, analyst decision and pipeline event is recorded.</p>
      <div class="stats">${[["Collected", st.items_collected], ["Passed filter", st.items_passed], ["Dropped (low signal)", st.items_dropped], ["Notifications", st.notifications], ["Trending alerts", st.trending_alerts], ["Errors", st.errors]].map(([l, v]) => html`<div class="stat"><div class="v">${v}</div><div class="l">${l} <span class="faint">(recent)</span></div></div>`)}</div>
      ${filterBar([{ name: "event", label: "Event", type: "select", options: [["", "All events"], ...EVENTS.map((e) => [e, label(e)])] }, { name: "q", label: "Search", ph: "text in entry", w: 200 }, { name: "n", label: "Show", type: "select", options: [["100", "100"], ["200", "200"], ["500", "500"], ["1000", "1000"]] }], { ...params, n: params.n || "200" })}
      ${list.length ? html`<div class="card tw"><table><thead><tr><th>Time</th><th>Event</th><th>Actor</th><th>Details</th></tr></thead><tbody>${list.map((a) => { const { ts, event, actor, ...rest } = a; return html`<tr><td class="small mono" style="white-space:nowrap">${fmtTs(ts)}</td><td><span class="badge ${/fail|error/.test(event) ? "b-act" : /^(source|finding|analyst)/.test(event) ? "b-poc" : "b-mute"}">${event}</span></td><td>${actor || html`<span class="faint">system</span>`}</td><td class="small muted" style="max-width:640px;word-break:break-word">${Object.entries(rest).map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : v}`).join(" · ").slice(0, 300)}</td></tr>`; })}</tbody></table></div>` : html`<div class="card">${empty("No audit entries yet.")}</div>`}`,
    };
  });
})();

// Boot once every page module has registered its routes.
window.EVVP.start();
