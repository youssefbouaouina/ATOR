(function () {
    "use strict";

    var toast = window.ATOR && window.ATOR.toast;
    var eventSource = null;
    var pollTimer = null;
    var errorCount = 0;
    var statusDot = null;
    var streamLabel = null;
    var lastSampleId = 0;
    var lastAlertId = 0;
    var hostsCache = {};
    var trendChart = null;
    var selectedHosts = new Set();
    var currentMetric = "cpu_pct";
    var currentWindow = 15;
    var gaugeCache = {};
    var paused = false;
    var alertTtl = 8000;

    function esc(s) {
        var d = document.createElement("div");
        d.textContent = s == null ? "" : String(s);
        return d.innerHTML;
    }

    function humanKbps(v) {
        if (v == null || v === "") return "—";
        if (v >= 1024) return (v / 1024).toFixed(1) + " MB/s";
        return v.toFixed(0) + " KB/s";
    }

    function humanBytes(v) {
        if (v == null || v === "") return "—";
        if (v >= 1024) return (v / 1024).toFixed(1) + " GB";
        return v.toFixed(0) + " MB";
    }

    function pctColor(pct) {
        if (pct == null) return "#6c757d";
        if (pct >= 90) return "#dc3545";
        if (pct >= 75) return "#fd7e14";
        if (pct >= 50) return "#ffc107";
        return "#198754";
    }

    function gaugeHtml(label, value, unit, color, stale, meta) {
        var pct = (value != null && value !== "" && !isNaN(value)) ? Number(value) : null;
        var deg = pct != null ? Math.min(100, Math.max(0, pct)) * 3.6 : 0;
        var metaHtml = meta ? '<div class="gauge-meta small text-muted">' + esc(meta) + "</div>" : "";
        return '<div class="gauge-wrap' + (stale ? " stale" : "") + '" style="--val:' + deg + 'deg;--c:' + color + '">' +
            '<div class="gauge-ring"><div class="gauge-center">' +
            (pct != null ? '<span class="gauge-value fw-bold">' + esc(pct.toFixed(pct % 1 === 0 ? 0 : 1)) + '</span>' : '<span class="text-muted">—</span>') +
            '<span class="gauge-unit small">' + esc(unit || "") + '</span></div></div>' +
            '<div class="gauge-label small text-muted mt-1">' + esc(label) + '</div>' + metaHtml + '</div>';
    }

    function hostMatchesFilters(h) {
        var pf = document.getElementById("filterPlatform").value;
        var df = document.getElementById("filterDevice").value;
        var tf = document.getElementById("filterTier").value;
        var hf = (document.getElementById("filterHost").value || "").toLowerCase();
        if (pf && h.os_type !== pf) return false;
        if (df) {
            var dtype = inferDeviceType(h);
            if (dtype !== df) return false;
        }
        if (tf && h.hw_tier !== tf) return false;
        if (hf && (h.hostname || "").toLowerCase().indexOf(hf) === -1) return false;
        return true;
    }

    function inferDeviceType(h) {
        if (h.os_type === "docker_host") return "docker";
        if (h.battery_pct != null && h.battery_pct !== "") return "laptop";
        if (h.os_type === "linux") return "server";
        return "desktop";
    }

    function isStale(h) {
        if (!h || !h.sampled_at_utc) return true;
        var t = Date.parse(h.sampled_at_utc);
        if (isNaN(t)) return true;
        return (Date.now() - t) > 90000;   // > 6 missed 15s samples
    }

    function renderGauges(hosts) {
        var grid = document.getElementById("gaugeGrid");
        var empty = document.getElementById("emptyState");
        var visible = hosts.filter(hostMatchesFilters);
        if (visible.length === 0) {
            grid.innerHTML = "";
            empty.style.display = "block";
            return;
        }
        empty.style.display = "none";
        var html = "";
        visible.forEach(function (h) {
            var cpuCol = pctColor(h.cpu_pct);
            var memCol = pctColor(h.mem_pct);
            var gpuCol = pctColor(h.gpu_util_pct);
            var stale = isStale(h);
            var deviceType = inferDeviceType(h);
            var deviceIcon = h.os_type === "docker_host" ? "server"
                : h.battery_pct != null && h.battery_pct !== "" ? "battery" : (h.os_type === "linux" ? "server" : "pc");
            var meta = "Tier: " + esc(h.hw_tier || "—") + " · " + esc(deviceType) + " · " + esc(h.os_type);
            var cpuHtml = gaugeHtml("CPU", h.cpu_pct, "%", cpuCol, stale, meta);
            var memHtml = gaugeHtml("MEM", h.mem_pct, "%", pctColor(h.mem_pct), stale, humanBytes(h.mem_used_mb) + " / " + humanBytes(h.mem_total_mb));
            var netHtml = gaugeHtml("NET ↓", h.net_recv_kbps, "KB/s", "#0d6efd", stale, humanKbps(h.net_sent_kbps) + " ↑");
            var gpuHtml = "";
            if (h.gpu_present) {
                gpuHtml = gaugeHtml("GPU", h.gpu_util_pct, "%", gpuCol, stale, humanBytes(h.gpu_mem_used_mb));
            }
            var battHtml = "";
            if (h.battery_pct != null && h.battery_pct !== "") {
                var bc = h.battery_plugged ? "#0d6efd" : pctColor(h.battery_pct);
                var battIcon = h.battery_plugged ? "⚡" : "🔋";
                battHtml = gaugeHtml("BATT", h.battery_pct, "% " + battIcon, bc, stale);
            }
            var anomalyBadge = h.anomaly ? '<span class="badge bg-danger ms-1">ANOMALY</span>' : "";
            html += '<div class="col-12 col-md-6 col-lg-4 col-xl-3">' +
                '<div class="card h-100 gauge-card' + (selectedHosts.has(h.id) ? " border-primary" : "") + '" data-host-id="' + h.id + '" title="Click to add/remove from trend chart">' +
                '<div class="card-header d-flex justify-content-between align-items-center py-2">' +
                '<h6 class="mb-0"><span class="pulse-dot' + (h.stale ? " is-stale" : " is-live") + '"></span> ' +
                esc(h.hostname) + anomalyBadge + '</h6>' +
                '<small class="text-muted">' + esc(inferDeviceType(h)) + ' · ' + esc(h.os_type) + '</small>' +
                '</div>' +
                '<div class="card-body p-2">' +
                '<div class="row g-2">' +
                '<div class="col-6">' + cpuHtml + '</div>' +
                '<div class="col-6">' + memHtml + '</div>' +
                '<div class="col-6">' + netHtml + '</div>' +
                '<div class="col-6">' + (gpuHtml || '<div class="gauge-wrap text-muted small">GPU N/A</div>') + '</div>' +
                '<div class="col-6">' + (battHtml || '<div class="gauge-wrap text-muted small">BATT N/A</div>') + '</div>' +
                '<div class="col-6"><div class="text-muted small">Tier: ' + esc(h.hw_tier) + '</div></div>' +
                '<div class="col-6"><div class="text-muted small">Cores: ' + esc(h.cpu_cores) + '</div></div>' +
                '</div>' +
                '</div>' +
                '</div>' +
                '</div>';
        });
        var gridEl = document.getElementById("gaugeGrid");
        gridEl.innerHTML = html;
        // attach click to select for trend overlay
        gridEl.querySelectorAll(".gauge-card").forEach(function (el) {
            el.addEventListener("click", function () {
                var hid = parseInt(this.dataset.hostId, 10);
                if (selectedHosts.has(hid)) selectedHosts.delete(hid);
                else selectedHosts.add(hid);
                this.classList.toggle("border-primary", selectedHosts.has(hid));
                fetchTrends();
            });
        });
    }

    function fetchTrends() {
        if (!selectedHosts.size || !window.Chart) {
            if (trendChart) { trendChart.data.datasets = []; trendChart.update(); }
            return;
        }
        var metric = currentMetric;
        var mins = currentWindow;
        var promises = Array.from(selectedHosts).map(function (hid) {
            return fetch("/api/v1/resources/history?host_id=" + hid + "&minutes=" + mins + "&metrics=" + metric + "&limit=300")
                .then(function (r) { return r.json(); })
                .then(function (d) { return {host_id: hid, points: d.points || []}; });
        });
        Promise.all(promises).then(function (results) {
            var colors = ["#e74c3c", "#3498db", "#2ecc71", "#f39c12", "#9b59b6", "#1abc9c"];
            var datasets = results.map(function (r, i) {
                var color = colors[i % colors.length];
                var data = r.points
                    .map(function (p) { return {x: Date.parse(p.sampled_at_utc), y: p[metric]}; })
                    .filter(function (p) { return p.y != null && !isNaN(p.x); });
                var cached = hostsCache[r.host_id] || {};
                return {
                    label: cached.hostname || ("Host " + r.host_id),
                    data: data,
                    borderColor: color,
                    backgroundColor: color + "33",
                    borderWidth: 2,
                    pointRadius: 0,
                    tension: 0.3,
                    fill: false,
                };
            });
            if (trendChart) {
                trendChart.data.datasets = datasets;
                trendChart.update();
            } else {
                var ctx = document.getElementById("trendChart").getContext("2d");
                trendChart = new Chart(ctx, {
                    type: "line",
                    data: {datasets: datasets},
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        interaction: {mode: "nearest", axis: "x", intersect: false},
                        parsing: false,
                        normalized: true,
                        scales: {
                            x: {
                                type: "linear",
                                grid: {display: false},
                                ticks: {
                                    maxTicksLimit: 8,
                                    callback: function (v) {
                                        var d = new Date(v);
                                        return isNaN(d) ? "" :
                                            ("0" + d.getHours()).slice(-2) + ":" + ("0" + d.getMinutes()).slice(-2);
                                    }
                                }
                            },
                            y: {beginAtZero: true, grid: {color: "rgba(233,236,239,.5)"}},
                        },
                        plugins: {legend: {position: "bottom", labels: {font: {size: 10}}, boxWidth: 12}},
                        animation: {duration: 250},
                    }
                });
            }
        });
    }

    function renderAlerts(alerts) {
        var list = document.getElementById("alertList");
        var badge = document.getElementById("alertCount");
        if (!alerts.length) {
            list.innerHTML = '<li class="list-group-item text-center text-muted small py-4" id="noAlerts">No recent alerts</li>';
            badge.textContent = "0";
            return;
        }
        badge.textContent = alerts.length;
        list.innerHTML = alerts.map(function (a) {
            var sevCls = "sev-" + (a.severity || "info");
            var time = (a.ts_utc || "").replace("T", " ").slice(0, 19);
            return '<li class="list-group-item ' + sevCls + '">' +
                '<div class="d-flex justify-content-between"><strong>' + esc(a.hostname) + '</strong><small class="text-muted">' + esc(time) + '</small></div>' +
                '<div class="small text-muted">' + esc(a.message) + '</div>' +
                '</li>';
        }).join("");
    }

    function applyFilters() {
        renderGauges(Object.values(hostsCache));
    }

    function prependSamples(samples) {
        samples.forEach(function (s) {
            var hid = s.host_id || s.id;   // stream rows carry row-id + host_id; latest rows carry host id
            if (!hostsCache[hid]) hostsCache[hid] = {};
            var h = hostsCache[hid];
            Object.keys(s).forEach(function (k) { if (k !== "id") h[k] = s[k]; });
            h.id = hid;
        });
        applyFilters();
        if (selectedHosts.size) fetchTrends();
    }

    function prependAlerts(alerts) {
        var list = document.getElementById("alertList");
        var badge = document.getElementById("alertCount");
        var noAlerts = document.getElementById("noAlerts");
        if (noAlerts) noAlerts.remove();
        var optAlerts = document.getElementById("optAlerts");
        var toastsEnabled = !optAlerts || optAlerts.checked;
        alerts.forEach(function (a) {
            var sevCls = "sev-" + (a.severity || "info");
            var time = (a.ts_utc || "").replace("T", " ").slice(0, 19);
            var li = document.createElement("li");
            li.className = "list-group-item " + sevCls;
            li.innerHTML =
                '<div class="d-flex justify-content-between"><strong>' + esc(a.hostname) + '</strong><small class="text-muted">' + esc(time) + '</small></div>' +
                '<div class="small text-muted">' + esc(a.message) + '</div>';
            list.prepend(li);
            if (toast && toastsEnabled && (a.severity === "critical" || a.severity === "high")) {
                toast("Resource alert on " + a.hostname + ": " + a.message, "warning", {ttl: alertTtl});
            }
        });
        while (list.children.length > 50) list.lastElementChild.remove();
        badge.textContent = list.children.length;
    }

    function setStreamState(live) {
        if (statusDot) {
            statusDot.classList.toggle("is-live", live);
            statusDot.classList.toggle("is-stale", !live);
            statusDot.title = live ? "Live stream connected" : "Live stream disconnected - polling";
        }
        if (streamLabel) streamLabel.textContent = live ? "live" : "polling";
    }

    function startPolling() {
        if (pollTimer) return;
        setStreamState(false);
        var interval = (window.ATOR && window.ATOR.refreshInterval) || 5000;
        async function tick() {
            if (paused) return;
            try {
                var resp = await fetch("/api/v1/resources/latest");
                if (!resp.ok) throw new Error("bad status " + resp.status);
                var data = await resp.json();
                data.hosts.forEach(function (h) {
                    if (!hostsCache[h.id]) hostsCache[h.id] = {};
                    Object.assign(hostsCache[h.id], h);
                });
                applyFilters();
                errorCount = 0;
            } catch (err) {
                errorCount++;
            }
        }
        tick();
        pollTimer = setInterval(tick, Math.max(3000, interval));
    }

    function startStream() {
        if (!window.EventSource || !document.getElementById("gaugeGrid")) {
            startPolling();
            return;
        }
        var intervalMs = (window.ATOR && window.ATOR.refreshInterval) || 5000;
        var seconds = Math.max(2, Math.round(intervalMs / 1000));
        eventSource = new EventSource("/api/v1/stream/resources?interval=" + seconds);

        eventSource.onmessage = function (msg) {
            errorCount = 0;
            setStreamState(true);
            try {
                var frame = JSON.parse(msg.data);
                if (frame.samples && frame.samples.length) prependSamples(frame.samples);
                if (frame.alerts && frame.alerts.length) prependAlerts(frame.alerts);
            } catch (e) { /* ignore */ }
        };
        eventSource.onerror = function () {
            errorCount++;
            setStreamState(false);
            if (errorCount >= 4) {
                eventSource.close();
                eventSource = null;
                startPolling();
            }
        };
    }

    function init() {
        statusDot = document.getElementById("streamDot");
        streamLabel = document.getElementById("streamLabel");
        // filters
        ["filterPlatform", "filterDevice", "filterTier", "filterHost"].forEach(function (id) {
            var el = document.getElementById(id);
            if (el) el.addEventListener("change", applyFilters);
            if (el && el.tagName === "INPUT") el.addEventListener("input", applyFilters);
        });
        // metric chips
        document.querySelectorAll('input[name="metric"]').forEach(function (el) {
            el.addEventListener("change", function () {
                currentMetric = this.value;
                fetchTrends();
            });
        });
        document.querySelectorAll('input[name="window"]').forEach(function (el) {
            el.addEventListener("change", function () {
                currentWindow = parseInt(this.value, 10);
                fetchTrends();
            });
        });
        document.getElementById("multiHostToggle")?.addEventListener("change", function () {
            if (!this.checked) selectedHosts.clear();
            fetchTrends();
        });
        document.getElementById("optPauseHidden")?.addEventListener("change", function () {
            paused = this.checked;
        });
        document.getElementById("optAlerts")?.addEventListener("change", function () {
            alertTtl = this.checked ? 8000 : 0;
        });

        // initial data load + stream start
        fetch("/api/v1/resources/latest").then(function (r) { return r.json(); })
            .then(function (data) {
                data.hosts.forEach(function (h) { hostsCache[h.id] = h; });
                applyFilters();
                if (!selectedHosts.size && data.hosts.length) {
                    selectedHosts.add(data.hosts[0].id);
                    fetchTrends();
                }
            }).catch(function () {});

        fetch("/api/v1/resources/alerts?limit=30").then(function (r) { return r.json(); })
            .then(function (d) { renderAlerts(d.alerts || []); });

        startStream();

        document.addEventListener("visibilitychange", function () {
            if (document.hidden && eventSource) { eventSource.close(); eventSource = null; setStreamState(false); }
            else if (!document.hidden && !eventSource && !pollTimer) { startStream(); }
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }

    window.ATOR = window.ATOR || {};
    window.ATOR.telemetry = { fetchTrends: fetchTrends, renderGauges: function () { applyFilters(); } };
})();