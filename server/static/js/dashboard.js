(function () {
    "use strict";

    var reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    function countUp(el) {
        var target = parseInt(el.getAttribute("data-count"), 10) || 0;
        if (reducedMotion || target === 0) {
            el.textContent = String(target);
            return;
        }
        var duration = 900;
        var startTs = null;
        function frame(ts) {
            if (startTs === null) startTs = ts;
            var p = Math.min((ts - startTs) / duration, 1);
            var eased = 1 - Math.pow(1 - p, 3);
            el.textContent = String(Math.round(eased * target));
            if (p < 1) requestAnimationFrame(frame);
        }
        requestAnimationFrame(frame);
    }

    function initCounters() {
        var els = document.querySelectorAll("[data-count]");
        if (!els.length) return;
        if (!("IntersectionObserver" in window)) {
            els.forEach(countUp);
            return;
        }
        var io = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (entry.isIntersecting) {
                    countUp(entry.target);
                    io.unobserve(entry.target);
                }
            });
        }, { threshold: 0.4 });
        els.forEach(function (el) { io.observe(el); });
    }

    async function refreshStats() {
        try {
            var resp = await fetch("/api/v1/stats/overview");
            if (!resp.ok) return;
            var stats = await resp.json();
            ["critical", "high", "medium", "low"].forEach(function (sev) {
                var el = document.querySelector('[data-kpi="' + sev + '"]');
                if (el && parseInt(el.textContent, 10) !== stats.counts[sev]) {
                    el.textContent = String(stats.counts[sev]);
                    el.classList.add("skeleton");
                    setTimeout(function () { el.classList.remove("skeleton"); }, 500);
                }
            });
            var hostsEl = document.querySelector('[data-kpi="hosts"]');
            if (hostsEl) hostsEl.textContent = String(stats.hosts_active);
            var manEl = document.querySelector('[data-kpi="manifests"]');
            if (manEl) manEl.textContent = String(stats.manifests);
            var trendCanvas = document.getElementById("trendChart");
            if (trendCanvas && window.ATOR.charts) {
                window.ATOR.charts.trendLine("trendChart", stats.trend);
            }
            updateTrendChip(stats.trend);
        } catch (err) {
            if (window.console && console.warn) console.warn("[ator] stats refresh failed", err);
        }
    }

    function updateTrendChip(trend) {
        var chip = document.getElementById("trendChip");
        if (!chip || !trend || trend.length < 2) return;
        var last = trend[trend.length - 1].count;
        var prev = trend[trend.length - 2].count;
        var cls, icon, text;
        if (last > prev) { cls = "trend-up"; icon = "\u25B2"; text = "+" + (last - prev) + " last hour"; }
        else if (last < prev) { cls = "trend-down"; icon = "\u25BC"; text = (last - prev) + " last hour"; }
        else { cls = "trend-flat"; icon = "\u2013"; text = "no change"; }
        chip.className = "trend-chip " + cls;
        chip.textContent = icon + " " + text;
    }

    function initTimezoneDisplay() {
        var zone = "Africa/Tunis";
        try {
            var detected = Intl.DateTimeFormat().resolvedOptions().timeZone;
            if (detected && detected !== "UTC" && detected !== "Etc/UTC") zone = detected;
        } catch (err) {}
        var zoneLabel = document.getElementById("dashboardTimezone");
        var formatter = new Intl.DateTimeFormat(undefined, {
            year: "numeric", month: "2-digit", day: "2-digit",
            hour: "2-digit", minute: "2-digit", second: "2-digit",
            timeZoneName: "short"
        });
        var offset = formatter.formatToParts(new Date()).filter(function (part) {
            return part.type === "timeZoneName";
        }).map(function (part) { return part.value; })[0] || "local";
        if (zoneLabel) zoneLabel.textContent = zone + " (" + offset + ")";
        window.ATOR.timezone = zone;
    }

    function formatLocalTimestamp(value) {
        if (!value) return;
        var normalized = String(value);
        if (!/[zZ]|[+-]\d{2}:\d{2}$/.test(normalized)) normalized += "Z";
        var date = new Date(normalized);
        if (isNaN(date.getTime())) return;
        var formatted = new Intl.DateTimeFormat(undefined, {
            year: "numeric", month: "2-digit", day: "2-digit",
            hour: "2-digit", minute: "2-digit", second: "2-digit",
            timeZoneName: "short",
            timeZone: (window.ATOR && window.ATOR.timezone) || "Africa/Tunis"
        }).format(date);
        document.querySelectorAll("[data-ator-time]").forEach(function (el) {
            if (el.getAttribute("data-ator-time") !== String(value)) return;
            el.textContent = formatted;
            el.title = String(value) + " (UTC)";
        });
    }

    function formatAllTimestamps() {
        document.querySelectorAll("[data-ator-time]").forEach(function (el) {
            formatLocalTimestamp(el.getAttribute("data-ator-time"));
        });
    }

    function bumpKpis(delta) {
        if (delta <= 0) return;
        var total = document.querySelector('[data-kpi-total]');
        if (total) total.textContent = String(parseInt(total.textContent, 10) + delta);
    }

    function init() {
        initTimezoneDisplay();
        formatAllTimestamps();
        initCounters();
        if (window.ATOR.ajax) window.ATOR.ajax.interceptForms();
        if (window.ATOR.tables) window.ATOR.tables.enhanceAll();
        if (window.ATOR.realtime) window.ATOR.realtime.init();

        var doughnut = document.getElementById("sevChart");
        if (doughnut && window.ATOR.charts) {
            var counts = JSON.parse(doughnut.getAttribute("data-counts") || "{}");
            window.ATOR.charts.severityDoughnut("sevChart", counts, counts.total || 0);
        }
        var trendCanvas = document.getElementById("trendChart");
        if (trendCanvas && !trendCanvas.hasAttribute("data-needs-fetch") && window.ATOR.charts) {
            var trendData = JSON.parse(trendCanvas.getAttribute("data-trend") || "[]");
            window.ATOR.charts.trendLine("trendChart", trendData);
        }

        document.addEventListener("ator:detection", function (e) { bumpKpis(1); });
        setInterval(refreshStats, (window.ATOR && window.ATOR.refreshInterval) || 8000);

        document.addEventListener("keydown", function (e) {
            if (e.key === "/" && document.activeElement === document.body) {
                var search = document.querySelector(".table-search");
                if (search && search.offsetParent) {
                    e.preventDefault();
                    search.focus();
                }
            }
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }

    window.ATOR = window.ATOR || {};
    window.ATOR.dashboard = {
        refreshStats: refreshStats,
        formatLocalTimestamp: formatLocalTimestamp
    };
})();
