(function () {
    "use strict";

    var SEV_COLORS = { critical: "#c0392b", high: "#d35400", medium: "#b7791f", low: "#1e8e5a" };

    var centerText = {
        id: "atorCenterText",
        afterDraw: function (chart) {
            if (chart.config.type !== "doughnut") return;
            var opts = chart.options.plugins.atorCenter;
            if (!opts) return;
            var ctx = chart.ctx;
            var meta = chart.getDatasetMeta(0);
            if (!meta.data.length) return;
            var model = meta.data[0];
            ctx.save();
            ctx.textAlign = "center";
            ctx.textBaseline = "middle";
            ctx.font = "700 26px 'Segoe UI', sans-serif";
            ctx.fillStyle = "#1c2733";
            ctx.fillText(String(opts.total), model.x, model.y - 8);
            ctx.font = "500 11px 'Segoe UI', sans-serif";
            ctx.fillStyle = "#64748b";
            ctx.fillText(opts.label || "total", model.x, model.y + 12);
            ctx.restore();
        },
    };

    function registerPlugins() {
        if (window.Chart && !Chart.registry.plugins.get("atorCenterText")) {
            Chart.register(centerText);
        }
    }

    function severityDoughnut(canvasId, counts, total) {
        registerPlugins();
        var el = document.getElementById(canvasId);
        if (!el || !window.Chart) return null;
        var labels = ["Critical", "High", "Medium", "Low"];
        var values = [counts.critical || 0, counts.high || 0, counts.medium || 0, counts.low || 0];
        var sum = values.reduce(function (a, b) { return a + b; }, 0);
        if (sum === 0) {
            var parent = el.closest(".chart-box");
            if (parent) {
                var hint = document.createElement("div");
                hint.className = "chart-empty";
                hint.textContent = "No detections yet";
                parent.appendChild(hint);
            }
        }
        var existing = Chart.getChart(el);
        if (existing) {
            existing.data.datasets[0].data = values;
            existing.options.plugins.atorCenter.total = sum;
            existing.update();
            return existing;
        }
        var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        return new Chart(el, {
            type: "doughnut",
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: labels.map(function (l) { return SEV_COLORS[l.toLowerCase()]; }),
                    borderWidth: 2,
                    borderColor: "#ffffff",
                    hoverOffset: 8,
                }],
            },
            options: {
                cutout: "62%",
                animation: reduced ? false : { animateRotate: true, duration: 900, easing: "easeOutQuart" },
                plugins: {
                    legend: { position: "bottom", labels: { usePointStyle: true, boxWidth: 8 } },
                    tooltip: {
                        callbacks: {
                            label: function (ctx) {
                                var v = ctx.parsed;
                                var pct = sum ? Math.round((v / sum) * 100) : 0;
                                return " " + ctx.label + ": " + v + " (" + pct + "%)";
                            },
                        },
                    },
                    atorCenter: { total: sum, label: "detections" },
                },
            },
        });
    }

    function trendLine(canvasId, trend) {
        registerPlugins();
        var el = document.getElementById(canvasId);
        if (!el || !window.Chart || !trend || !trend.length) return null;
        var hasData = trend.some(function (p) { return p.count > 0; });
        var parent = el.closest(".chart-box");
        var existingHint = parent && parent.querySelector(".chart-empty");
        if (!hasData && parent && !existingHint) {
            var hint = document.createElement("div");
            hint.className = "chart-empty";
            hint.textContent = "No detection activity in the last 24h";
            parent.appendChild(hint);
        } else if (hasData && existingHint) {
            existingHint.remove();
        }
        var labels = trend.map(function (p) { return p.hour; });
        var values = trend.map(function (p) { return p.count; });
        var existing = Chart.getChart(el);
        if (existing) {
            existing.data.labels = labels;
            existing.data.datasets[0].data = values;
            existing.update();
            return existing;
        }
        var gradient = el.getContext("2d").createLinearGradient(0, 0, 0, 220);
        gradient.addColorStop(0, "rgba(36, 86, 166, 0.25)");
        gradient.addColorStop(1, "rgba(36, 86, 166, 0.02)");
        var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        return new Chart(el, {
            type: "line",
            data: {
                labels: labels,
                datasets: [{
                    label: "Detections",
                    data: values,
                    borderColor: "#2456a6",
                    backgroundColor: gradient,
                    fill: true,
                    tension: 0.35,
                    pointRadius: 3,
                    pointHoverRadius: 6,
                    pointBackgroundColor: "#2456a6",
                }],
            },
            options: {
                animation: reduced ? false : { duration: 800, easing: "easeOutQuart" },
                scales: {
                    y: { beginAtZero: true, ticks: { precision: 0 } },
                    x: { ticks: { maxTicksLimit: 8 }, grid: { display: false } },
                },
                plugins: {
                    legend: { display: false },
                    tooltip: { intersect: false, mode: "index" },
                },
            },
        });
    }

    // Compact multi-series sparkline for the resources page. series: [{label,
    // data:[], color}]. Reuses one Chart instance per canvas (live updates).
    function sparkline(canvasId, labels, series) {
        var el = typeof canvasId === "string" ? document.getElementById(canvasId) : canvasId;
        if (!el || !window.Chart) return null;
        var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        var existing = Chart.getChart(el);
        if (existing) {
            existing.data.labels = labels;
            series.forEach(function (s, i) {
                if (existing.data.datasets[i]) existing.data.datasets[i].data = s.data;
            });
            existing.update(reduced ? "none" : undefined);
            return existing;
        }
        var ctx = el.getContext("2d");
        return new Chart(el, {
            type: "line",
            data: {
                labels: labels,
                datasets: series.map(function (s) {
                    var grad = ctx.createLinearGradient(0, 0, 0, 70);
                    grad.addColorStop(0, s.color + "40");
                    grad.addColorStop(1, s.color + "05");
                    return {
                        label: s.label, data: s.data, borderColor: s.color,
                        backgroundColor: s.fill === false ? "transparent" : grad,
                        fill: s.fill !== false, borderWidth: 1.8, tension: 0.4,
                        pointRadius: 0, pointHoverRadius: 3,
                    };
                }),
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                animation: reduced ? false : { duration: 400 },
                interaction: { intersect: false, mode: "index" },
                scales: {
                    y: { beginAtZero: true, suggestedMax: 100, display: false, grid: { display: false } },
                    x: { display: false, grid: { display: false } },
                },
                plugins: { legend: { display: false }, tooltip: {
                    enabled: true, displayColors: false,
                    callbacks: { title: function (i) { return i[0] ? i[0].label : ""; },
                        label: function (c) { return c.dataset.label + ": " + Math.round(c.parsed.y); } } } },
            },
        });
    }

    window.ATOR = window.ATOR || {};
    window.ATOR.charts = { severityDoughnut: severityDoughnut, trendLine: trendLine, sparkline: sparkline };
})();
