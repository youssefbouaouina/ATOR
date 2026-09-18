(function () {
  "use strict";
  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var histCache = {};   // host_id -> {t:[], series...}
  var errors = 0;

  function $(id) { return document.getElementById(id); }
  function esc(s) { var d = document.createElement("div"); d.textContent = s == null ? "" : s; return d.innerHTML; }
  function num(v, dp) { return (v == null || isNaN(v)) ? 0 : Number(v).toFixed(dp == null ? 0 : dp); }
  function fmtBytes(n) {
    if (!n) return "0 B";
    var u = ["B", "KB", "MB", "GB"], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return n.toFixed(n < 10 && i > 0 ? 1 : 0) + " " + u[i];
  }
  function fmtMB(v) { if (v == null || isNaN(v)) return "—"; return v >= 1024 ? (v / 1024).toFixed(1) + " GB" : Number(v).toFixed(0) + " MB"; }
  function ageSecs(iso) { if (!iso) return 1e9; var d = new Date(String(iso).replace(" ", "T")); return (Date.now() - d.getTime()) / 1000; }
  function hhmmss(iso) { if (!iso) return "—"; var d = new Date(String(iso).replace(" ", "T")); if (isNaN(d)) return "—"; return d.toISOString().slice(11, 19) + " UTC"; }

  // Smoothly count a number element from its current value to target.
  function animateNum(el, target, dp) {
    var start = parseFloat(el.getAttribute("data-cur") || "0") || 0;
    target = Number(target) || 0;
    el.setAttribute("data-cur", target);
    if (reduced || start === target) { el.textContent = dp ? target.toFixed(dp) : Math.round(target); return; }
    var t0 = null, dur = 600;
    function step(ts) {
      if (t0 === null) t0 = ts;
      var p = Math.min((ts - t0) / dur, 1), e = 1 - Math.pow(1 - p, 3);
      var v = start + (target - start) * e;
      el.textContent = dp ? v.toFixed(dp) : Math.round(v);
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  function setKpis(f) {
    document.querySelectorAll("[data-kpi]").forEach(function (el) {
      var k = el.getAttribute("data-kpi");
      if (!(k in f)) return;
      var dp = /pct|cpu|mem_mb|collection/.test(k) && k !== "avg_collection_ms" ? 1 : 0;
      var prev = el.getAttribute("data-cur");
      animateNum(el, f[k], /avg_agent_cpu_pct|avg_sys_cpu_pct|avg_sys_mem_pct|avg_agent_mem_mb/.test(k) ? 1 : 0);
      if (prev != null && Number(prev) !== Number(f[k])) {
        var tile = el.closest(".card-body"); if (tile) { tile.classList.remove("kpi-flash"); void tile.offsetWidth; tile.classList.add("kpi-flash"); }
      }
    });
    var b = document.querySelector("[data-kpi-bytes]");
    if (b) b.textContent = fmtBytes(f.telemetry_bytes_24h);
    $("reportingSub").textContent = "of " + f.endpoints + " endpoint" + (f.endpoints === 1 ? "" : "s");
    $("agentMemAvg").textContent = num(f.avg_agent_mem_mb, 1) + " MB avg / agent";
    var v = $("verdict"), vt = $("verdictText");
    vt.textContent = f.verdict + " footprint";
    v.className = "footprint-verdict verdict-" + f.verdict.toLowerCase();
  }

  function gaugeColor(pct) { return pct >= 90 ? "#c0392b" : pct >= 70 ? "#d35400" : pct >= 45 ? "#2456a6" : "#1e8e5a"; }
  function fillCls(pct) { return pct >= 90 ? "crit" : pct >= 70 ? "warn" : ""; }

  function gauge(val, cap, unit) {
    var pct = Math.max(0, Math.min(100, Number(val) || 0));
    return '<div><div class="gauge" style="--val:' + (pct * 3.6) + 'deg;--c:' + gaugeColor(pct) + '">' +
      '<div class="gauge-in"><span class="gv">' + num(val, val < 10 ? 1 : 0) + '</span><span class="gu">' + unit + '</span></div></div>' +
      '<div class="gauge-cap">' + cap + '</div></div>';
  }

  function bar(label, pct, valText) {
    pct = Math.max(0, Math.min(100, Number(pct) || 0));
    return '<div class="metric-row"><span class="m-label">' + label + '</span>' +
      '<span class="metric-track"><span class="metric-fill ' + fillCls(pct) + '" style="width:' + pct + '%"></span></span>' +
      '<span class="m-val">' + valText + '</span></div>';
  }

  function cardHtml(h, self) {
    var stale = ageSecs(h.sampled_at_utc) > 90;
    var memPct = h.mem_pct != null ? h.mem_pct : (h.mem_used_mb && h.mem_total_mb ? h.mem_used_mb / h.mem_total_mb * 100 : 0);
    var agentSharePct = (self && self.agent_cpu_pct != null && h.cpu_pct) ? Math.min(100, self.agent_cpu_pct / Math.max(h.cpu_pct, 0.1) * 100) : 0;
    var agentMemPct = (self && self.agent_mem_mb != null && h.mem_total_mb) ? self.agent_mem_mb / h.mem_total_mb * 100 : 0;
    var status = stale ? '<span class="status-pill offline"><span class="dot"></span>stale</span>'
                       : '<span class="status-pill online"><span class="dot"></span>live</span>';
    var hw = [];
    if (h.cpu_cores) hw.push(h.cpu_cores + " cores");
    if (h.mem_total_mb) hw.push(fmtMB(h.mem_total_mb) + " RAM");
    if (h.hw_tier) hw.push(esc(h.hw_tier));

    return '<div class="card ator-card res-card' + (stale ? " stale" : "") + '" data-host="' + h.id + '">' +
      '<div class="card-header"><div><span class="res-title">' + esc(h.hostname) + '</span> ' +
        '<span class="badge bg-dark">' + esc(h.os_type || "?") + '</span>' +
        (h.docker_engine_flag ? ' <span class="badge bg-info-subtle text-dark">docker</span>' : "") +
        '<div class="res-hw">' + hw.join(" · ") + '</div></div>' + status + '</div>' +
      '<div class="card-body">' +
        '<div class="gauge-trio">' +
          gauge(h.cpu_pct, "System CPU", "%") +
          gauge(memPct, "System RAM", "%") +
          gauge(self ? self.agent_cpu_pct : 0, "Agent CPU", "%") +
        '</div>' +
        '<div class="spark-box"><canvas></canvas></div>' +
        bar("Agent RAM", agentMemPct, self ? fmtMB(self.agent_mem_mb) : "—") +
        bar("Agent CPU share", agentSharePct, num(agentSharePct, 1) + "% of host") +
        bar("Swap", h.swap_pct, num(h.swap_pct, 0) + "%") +
        '<div class="res-stats mt-2">' +
          stat("Threads", self ? self.agent_threads : null) +
          stat("Open handles", self ? self.agent_fds : null) +
          stat("Collection", self && self.collection_duration_ms != null ? num(self.collection_duration_ms) + " ms" : null, true) +
          stat("Payload", self && self.payload_size_bytes != null ? fmtBytes(self.payload_size_bytes) : null, true) +
          stat("Spool", self ? self.spool_count : null) +
          stat("Mode", self ? self.telemetry_mode : null, true) +
        '</div>' +
        '<div class="d-flex justify-content-between mt-2">' +
          '<span class="io-chip"><i class="bi bi-arrow-down-up"></i> Net ' + num(h.net_recv_kbps) + '↓ / ' + num(h.net_sent_kbps) + '↑ KB/s</span>' +
          '<span class="io-chip"><i class="bi bi-hdd"></i> Disk ' + num(h.disk_read_kbps) + 'R / ' + num(h.disk_write_kbps) + 'W</span>' +
        '</div>' +
        '<div class="text-muted small mt-1">Last sample: ' + hhmmss(h.sampled_at_utc) + '</div>' +
      '</div></div>';
  }
  function stat(k, v, isText) {
    var val = v == null || v === "" ? "—" : (isText ? esc(v) : v);
    return '<div class="res-stat"><span class="rs-k">' + k + '</span><span class="rs-v">' + val + '</span></div>';
  }

  function updateGauges(card, h, self) {
    var memPct = h.mem_pct != null ? h.mem_pct : 0;
    var gs = card.querySelectorAll(".gauge");
    var vals = [h.cpu_pct || 0, memPct, self ? (self.agent_cpu_pct || 0) : 0];
    gs.forEach(function (g, i) {
      var p = Math.max(0, Math.min(100, vals[i]));
      g.style.setProperty("--val", (p * 3.6) + "deg");
      g.style.setProperty("--c", gaugeColor(p));
      var gv = g.querySelector(".gv"); if (gv) gv.textContent = num(vals[i], vals[i] < 10 ? 1 : 0);
    });
  }

  function drawSpark(card, hid) {
    var c = histCache[hid]; if (!c || !c.t.length) return;
    var canvas = card.querySelector(".spark-box canvas");
    if (canvas && window.ATOR.charts) {
      window.ATOR.charts.sparkline(canvas, c.t, [
        { label: "System CPU", data: c.cpu, color: "#2456a6" },
        { label: "System RAM", data: c.mem, color: "#8e44ad" },
        { label: "Agent CPU", data: c.acpu, color: "#1e8e5a" },
      ]);
    }
  }

  function loadHistory(hid) {
    return fetch("/api/v1/resources/history?host_id=" + hid + "&minutes=20&metrics=cpu_pct,mem_pct", { cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var t = [], cpu = [], mem = [];
        (d.points || []).forEach(function (p) { t.push(hhmmss(p.sampled_at_utc).slice(0, 8)); cpu.push(p.cpu_pct || 0); mem.push(p.mem_pct || 0); });
        histCache[hid] = histCache[hid] || {}; var c = histCache[hid];
        c.t = t; c.cpu = cpu; c.mem = mem; c.acpu = c.acpu && c.acpu.length === t.length ? c.acpu : cpu.map(function () { return 0; });
      });
  }
  function loadAgentHistory(hid) {
    return fetch("/api/v1/agent-self/history?host_id=" + hid + "&minutes=20&metrics=agent_cpu_pct", { cache: "no-store" })
      .then(function (r) { return r.json(); }).then(function (d) {
        var c = histCache[hid]; if (!c) return;
        var a = (d.points || []).map(function (p) { return p.agent_cpu_pct || 0; });
        // Align length to system series.
        while (a.length < c.t.length) a.unshift(0);
        c.acpu = a.slice(-c.t.length);
      }).catch(function () {});
  }

  var resById = {}, selfById = {};
  function render() {
    var grid = $("resGrid"), empty = $("resEmpty");
    var ids = Object.keys(resById);
    $("resCount").textContent = ids.length + (ids.length === 1 ? " endpoint" : " endpoints");
    // Drop the initial skeleton placeholders once we have real data.
    grid.querySelectorAll(".skeleton").forEach(function (s) { s.remove(); });
    if (!ids.length) { grid.innerHTML = ""; empty.hidden = false; return; }
    empty.hidden = true;
    ids.forEach(function (id) {
      var h = resById[id], self = selfById[id];
      var card = grid.querySelector('.res-card[data-host="' + id + '"]');
      if (!card) {
        grid.insertAdjacentHTML("beforeend", cardHtml(h, self));
        card = grid.querySelector('.res-card[data-host="' + id + '"]');
        loadHistory(id).then(function () { return loadAgentHistory(id); }).then(function () { drawSpark(card, id); });
      } else {
        // Update live values without full re-render (keeps gauge animation).
        card.classList.toggle("stale", ageSecs(h.sampled_at_utc) > 90);
        updateGauges(card, h, self);
        refreshBars(card, h, self);
        var ls = card.querySelector(".card-body > .text-muted.small"); if (ls) ls.textContent = "Last sample: " + hhmmss(h.sampled_at_utc);
      }
    });
    // Remove cards for hosts no longer present.
    grid.querySelectorAll(".res-card").forEach(function (card) {
      if (!resById[card.dataset.host]) card.remove();
    });
  }

  function refreshBars(card, h, self) {
    var memPct = h.mem_total_mb && self && self.agent_mem_mb ? self.agent_mem_mb / h.mem_total_mb * 100 : 0;
    var sharePct = (self && self.agent_cpu_pct != null && h.cpu_pct) ? Math.min(100, self.agent_cpu_pct / Math.max(h.cpu_pct, 0.1) * 100) : 0;
    var fills = card.querySelectorAll(".metric-fill");
    var pcts = [memPct, sharePct, h.swap_pct || 0];
    fills.forEach(function (f, i) { var p = Math.max(0, Math.min(100, pcts[i])); f.style.width = p + "%"; f.className = "metric-fill " + fillCls(p); });
    var vals = card.querySelectorAll(".metric-row .m-val");
    if (vals[0]) vals[0].textContent = self ? fmtMB(self.agent_mem_mb) : "—";
    if (vals[1]) vals[1].textContent = num(sharePct, 1) + "% of host";
    if (vals[2]) vals[2].textContent = num(h.swap_pct, 0) + "%";
    var rs = card.querySelectorAll(".res-stat .rs-v");
    if (self && rs.length >= 6) {
      rs[0].textContent = self.agent_threads == null ? "—" : self.agent_threads;
      rs[1].textContent = self.agent_fds == null ? "—" : self.agent_fds;
      rs[2].textContent = self.collection_duration_ms == null ? "—" : num(self.collection_duration_ms) + " ms";
      rs[3].textContent = self.payload_size_bytes == null ? "—" : fmtBytes(self.payload_size_bytes);
      rs[4].textContent = self.spool_count == null ? "—" : self.spool_count;
      rs[5].textContent = self.telemetry_mode || "—";
    }
  }

  function setLive(ok) {
    var dot = $("streamDot"), lbl = $("streamLabel");
    if (dot) { dot.classList.toggle("is-live", ok); dot.classList.toggle("is-stale", !ok); }
    if (lbl) lbl.textContent = ok ? "live · updating" : "reconnecting…";
  }

  function tick() {
    Promise.all([
      fetch("/api/v1/resources/latest", { cache: "no-store" }).then(function (r) { return r.json(); }),
      fetch("/api/v1/agent-self/latest", { cache: "no-store" }).then(function (r) { return r.json(); }),
      fetch("/api/v1/stats/footprint", { cache: "no-store" }).then(function (r) { return r.json(); }),
    ]).then(function (res) {
      errors = 0; setLive(true);
      resById = {}; (res[0].hosts || []).forEach(function (h) { if (h.sampled_at_utc) resById[h.id] = h; });
      selfById = {}; (res[1].hosts || []).forEach(function (h) { selfById[h.id] = h; });
      setKpis(res[2]);
      render();
      // Refresh sparkline data periodically.
      Object.keys(resById).forEach(function (id) {
        var card = $("resGrid").querySelector('.res-card[data-host="' + id + '"]');
        if (card && histCache[id]) {
          var c = histCache[id], h = resById[id], self = selfById[id];
          c.t.push(hhmmss(h.sampled_at_utc).slice(0, 8)); c.cpu.push(h.cpu_pct || 0);
          c.mem.push(h.mem_pct || 0); c.acpu.push(self ? (self.agent_cpu_pct || 0) : 0);
          [c.t, c.cpu, c.mem, c.acpu].forEach(function (a) { while (a.length > 60) a.shift(); });
          drawSpark(card, id);
        }
      });
    }).catch(function () { if (++errors >= 3) setLive(false); });
  }

  function init() {
    tick();
    setInterval(tick, Math.max(4000, (window.ATOR && window.ATOR.refreshInterval) || 5000));
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
})();
