(function () {
    "use strict";

    function init() {
        var button = document.getElementById("investigation-expand");
        if (!button) return;
        var sections = Array.from(document.querySelectorAll("[data-investigation-section]"));
        function update() {
            var allOpen = sections.every(function (section) { return section.open; });
            button.textContent = allOpen ? "Collapse all" : "Expand all";
        }
        button.hidden = false;
        button.addEventListener("click", function () {
            var open = !sections.every(function (section) { return section.open; });
            sections.forEach(function (section) { section.open = open; });
            update();
        });
        sections.forEach(function (section) { section.addEventListener("toggle", update); });
        update();

        var table = document.querySelector("[data-investigation-process-table]");
        if (!table) return;
        var rows = Array.from(table.tBodies[0].rows);
        var page = 0;
        var toolbar = document.createElement("div");
        toolbar.className = "table-toolbar";
        var search = document.createElement("input");
        search.type = "search";
        search.className = "table-search";
        search.placeholder = "Search process, PID or command…";
        search.setAttribute("aria-label", "Search process snapshot");
        var previous = document.createElement("button");
        var next = document.createElement("button");
        [previous, next].forEach(function (control) {
            control.type = "button";
            control.className = "btn btn-outline-secondary btn-sm";
        });
        previous.textContent = "Previous";
        next.textContent = "Next";
        var status = document.createElement("span");
        status.className = "small text-muted";
        status.setAttribute("aria-live", "polite");
        [search, previous, status, next].forEach(function (node) { toolbar.appendChild(node); });
        table.parentNode.insertBefore(toolbar, table);
        function apply() {
            var query = search.value.trim().toLowerCase();
            var matches = rows.filter(function (row) { return row.textContent.toLowerCase().includes(query); });
            var pages = Math.max(1, Math.ceil(matches.length / 15));
            page = Math.max(0, Math.min(page, pages - 1));
            var visible = new Set(matches.slice(page * 15, (page + 1) * 15));
            rows.forEach(function (row) { row.hidden = !visible.has(row); });
            status.textContent = matches.length ? "Page " + (page + 1) + "/" + pages + " · " + matches.length + " processes" : "No matching processes";
            previous.disabled = page === 0;
            next.disabled = page === pages - 1;
        }
        search.addEventListener("input", function () { page = 0; apply(); });
        previous.addEventListener("click", function () { page--; apply(); });
        next.addEventListener("click", function () { page++; apply(); });
        apply();
    }

    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
    else init();
})();
