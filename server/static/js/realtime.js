(function () {
    "use strict";

    var toast = window.ATOR && window.ATOR.toast;
    var feedList = null;
    var maxItems = 30;
    var lastSeenIds = new Set();
    var eventSource = null;
    var pollTimer = null;
    var errorCount = 0;
    var statusDot = null;

    function esc(s) {
        var d = document.createElement("div");
        d.textContent = s == null ? "" : String(s);
        return d.innerHTML;
    }

    function feedItemHtml(ev, fresh) {
        var time = (ev.detected_at_utc || "").replace("T", " ").slice(0, 19);
        var sev = (ev.severity || "info").toLowerCase();
        return '<div class="feed-item sev-' + esc(sev) + (fresh ? " fresh" : "") + '" data-detection-id="' + esc(ev.id) + '">' +
            '<span class="feed-time" data-ator-time="' + esc(ev.detected_at_utc || "") + '">' + esc(time) + "</span>" +
            '<span class="badge sev-badge badge-' + esc(sev) + '">' + esc(sev) + "</span>" +
            "<div><div class=\"feed-title\">" + esc(ev.rule_name) + "</div>" +
            '<div class="feed-meta">' + esc(ev.hostname || "") +
            (ev.technique_id ? " &middot; <span class='mono'>" + esc(ev.technique_id) + "</span>" : "") +
            " &middot; " + esc(ev.rule_type) + "</div></div></div>";
    }

    function prependEvent(ev, fresh) {
        if (!feedList) return;
        var id = ev.id;
        if (lastSeenIds.has(id)) return;
        lastSeenIds.add(id);
        var placeholder = feedList.querySelector(".skeleton-row");
        if (placeholder) placeholder.remove();
        var wrap = document.createElement("template");
        wrap.innerHTML = feedItemHtml(ev, fresh).trim();
        var node = wrap.content.firstChild;
        feedList.prepend(node);
        if (window.ATOR && window.ATOR.dashboard && window.ATOR.dashboard.formatLocalTimestamp) {
            window.ATOR.dashboard.formatLocalTimestamp(ev.detected_at_utc);
        }
        while (feedList.children.length > maxItems) feedList.lastElementChild.remove();
        setTimeout(function () { node.classList.remove("fresh"); }, 2600);
        if (fresh && ev.severity === "critical" && toast) {
            toast("CRITICAL detection on " + (ev.hostname || "endpoint") + ": " + ev.rule_name, "warning", { ttl: 8000 });
        }
        if (fresh) document.dispatchEvent(new CustomEvent("ator:detection", { detail: ev }));
    }

    function setStreamState(live) {
        if (statusDot) {
            statusDot.classList.toggle("is-live", live);
            statusDot.classList.toggle("is-stale", !live);
            statusDot.title = live ? "Live stream connected" : "Live stream disconnected - polling";
        }
        var label = document.getElementById("streamLabel");
        if (label) label.textContent = live ? "live" : "polling";
    }

    function startPolling() {
        if (pollTimer) return;
        setStreamState(false);
        var interval = (window.ATOR && window.ATOR.refreshInterval) || 5000;
        async function tick() {
            try {
                var resp = await fetch("/api/v1/detections");
                if (!resp.ok) throw new Error("bad status " + resp.status);
                var rows = await resp.json();
                rows.reverse().forEach(function (ev) { prependEvent(ev, false); });
                errorCount = 0;
            } catch (err) {
                errorCount++;
            }
        }
        tick();
        pollTimer = setInterval(tick, Math.max(3000, interval));
    }

    function startStream() {
        if (!window.EventSource || !feedList) {
            startPolling();
            return;
        }
        var intervalMs = (window.ATOR && window.ATOR.refreshInterval) || 5000;
        var seconds = Math.max(2, Math.round(intervalMs / 1000));
        eventSource = new EventSource("/api/v1/stream/events?interval=" + seconds);

        eventSource.onmessage = function (msg) {
            errorCount = 0;
            setStreamState(true);
            try {
                var ev = JSON.parse(msg.data);
                var fresh = !lastSeenIds.has(ev.id) && lastSeenIds.size > 0;
                prependEvent(ev, fresh);
            } catch (e) { /* ignore malformed frame */ }
        };
        eventSource.onerror = function () {
            errorCount++;
            setStreamState(false);
            if (errorCount >= 4) {
                eventSource.close();
                startPolling();
            }
        };
    }

    function init() {
        feedList = document.getElementById("liveFeed");
        statusDot = document.getElementById("streamDot");
        if (!feedList) return;
        startStream();
        document.addEventListener("visibilitychange", function () {
            if (document.hidden && eventSource) { eventSource.close(); eventSource = null; setStreamState(false); }
            else if (!document.hidden && !eventSource && !pollTimer) { startStream(); }
        });
    }

    window.ATOR = window.ATOR || {};
    window.ATOR.realtime = { init: init, prependEvent: prependEvent };
})();
