(function () {
    "use strict";

    var toast = window.ATOR && window.ATOR.toast;

    function setButtonLoading(btn, on, label) {
        if (!btn) return;
        if (on) {
            btn.dataset.originalLabel = btn.innerHTML;
            btn.classList.add("btn-loading");
            btn.disabled = true;
            if (label) {
                var sr = document.createElement("span");
                sr.className = "visually-hidden";
                sr.textContent = label;
                btn.appendChild(sr);
            }
        } else {
            btn.classList.remove("btn-loading");
            btn.disabled = false;
            btn.innerHTML = btn.dataset.originalLabel || btn.innerHTML;
        }
    }

    function buildPayload(form) {
        var data = {};
        var submitterValue = null;
        Array.prototype.forEach.call(form.elements, function (el) {
            if (!el.name || el.disabled) return;
            if ((el.type === "checkbox" || el.type === "radio") && !el.checked) return;
            if (el.tagName === "BUTTON" && el.type === "submit") return;
            data[el.name] = el.value;
        });
        if (form.__lastSubmitter && form.__lastSubmitter.name && form.__lastSubmitter.value) {
            data[form.__lastSubmitter.name] = form.__lastSubmitter.value;
        }
        return data;
    }

    function applySuccess(form, result) {
        var action = form.getAttribute("data-on-success") || "toast";
        if (action.indexOf("remove-row") !== -1) {
            var row = form.closest("tr");
            if (row) {
                row.style.transition = "opacity 300ms ease";
                row.style.opacity = "0";
                setTimeout(function () { row.remove(); }, 320);
            }
        }
        if (action.indexOf("reset") !== -1) form.reset();
        if (action.indexOf("reload-badge") !== -1) {
            var cell = form.closest("td");
            if (cell) {
                var rowEl = form.closest("tr");
                var badge = rowEl && rowEl.querySelector(".status-pill, .badge");
                if (badge) {
                    badge.className = "badge bg-danger";
                    badge.textContent = "revoked";
                }
                var btnWrap = form.closest("td");
                if (btnWrap) form.remove();
            }
        }
    }

    async function submitViaFetch(form) {
        var apiPath = form.getAttribute("data-api");
        var btn = form.querySelector("button[type=submit], button:not([type])");
        var loadingLabel = form.getAttribute("data-loading-label") || "Working...";
        setButtonLoading(btn, true);
        try {
            var resp = await fetch(apiPath || form.action, {
                method: (form.getAttribute("method") || "POST").toUpperCase(),
                headers: { "Content-Type": "application/json", "Accept": "application/json" },
                body: JSON.stringify(buildPayload(form)),
            });
            var text = await resp.text();
            var result = {};
            try { result = text ? JSON.parse(text) : {}; } catch (e) { result = { raw: text }; }
            if (!resp.ok) {
                var detail = result && (result.detail || result.error);
                var msg = typeof detail === "string" ? detail
                    : (detail ? JSON.stringify(detail).slice(0, 160) : "Request failed (" + resp.status + ")");
                toast(msg, "error");
                return;
            }
            toast(form.getAttribute("data-success-message") || "Action completed", "success");
            applySuccess(form, result);
            document.dispatchEvent(new CustomEvent("ator:action-success", {
                detail: { path: apiPath || form.action, result: result },
            }));
        } catch (err) {
            toast(err && err.name === "AbortError" || err && err.name === "TimeoutError"
                ? "Request timed out"
                : "Network error - the server may be unreachable", "error");
            if (window.console && console.warn) console.warn("[ator] request failed:", err);
        } finally {
            setButtonLoading(btn, false);
        }
    }

    function interceptForms() {
        document.addEventListener("submit", function (ev) {
            var form = ev.target;
            if (!(form instanceof HTMLFormElement)) return;
            if (!form.hasAttribute("data-ajax")) return;
            ev.preventDefault();
            if (ev.submitter) form.__lastSubmitter = ev.submitter;
            submitViaFetch(form);
        });
    }

    window.ATOR = window.ATOR || {};
    window.ATOR.ajax = { submitViaFetch: submitViaFetch, interceptForms: interceptForms };
})();
