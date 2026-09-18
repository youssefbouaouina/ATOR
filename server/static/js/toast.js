(function () {
    "use strict";

    var ICONS = { success: "\u2713", warning: "\u26A0", error: "\u2715", info: "\u2139" };

    function ensureStack() {
        var stack = document.querySelector(".toast-stack");
        if (!stack) {
            stack = document.createElement("div");
            stack.className = "toast-stack";
            stack.setAttribute("role", "status");
            stack.setAttribute("aria-live", "polite");
            document.body.appendChild(stack);
        }
        return stack;
    }

    function show(message, type, opts) {
        opts = opts || {};
        type = type || "info";
        var stack = ensureStack();
        var el = document.createElement("div");
        el.className = "ator-toast " + type;
        el.setAttribute("role", "alert");

        var icon = document.createElement("span");
        icon.className = "toast-icon";
        icon.textContent = ICONS[type] || ICONS.info;

        var body = document.createElement("div");
        body.className = "toast-body";
        body.textContent = message;

        var close = document.createElement("button");
        close.className = "toast-close";
        close.setAttribute("aria-label", "Dismiss notification");
        close.innerHTML = "&times;";

        el.appendChild(icon);
        el.appendChild(body);
        el.appendChild(close);
        stack.appendChild(el);

        var ttl = typeof opts.ttl === "number" ? opts.ttl : (type === "error" ? 6500 : 4200);
        el.style.setProperty("--toast-ttl", ttl + "ms");
        var timer = setTimeout(dismiss, ttl);

        function dismiss() {
            clearTimeout(timer);
            if (!el.isConnected) return;
            el.classList.add("leaving");
            el.addEventListener("animationend", function () { el.remove(); }, { once: true });
            setTimeout(function () { el.remove(); }, 400);
        }

        close.addEventListener("click", dismiss);
        return dismiss;
    }

    window.ATOR = window.ATOR || {};
    window.ATOR.toast = show;
})();
