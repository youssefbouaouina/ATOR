(function () {
    "use strict";

    var PAGE_SIZE = 10;

    function textOf(row) {
        return row.textContent.trim().toLowerCase();
    }

    function severityOf(row) {
        var badge = row.querySelector(".sev-badge");
        if (!badge) return null;
        var cls = badge.className;
        if (/badge-critical/.test(cls)) return "critical";
        if (/badge-high/.test(cls)) return "high";
        if (/badge-medium/.test(cls)) return "medium";
        if (/badge-low/.test(cls)) return "low";
        return null;
    }

    function enhance(table) {
        if (table.__atorEnhanced) return;
        table.__atorEnhanced = true;

        var thead = table.tHead;
        var tbody = table.tBodies[0];
        if (!tbody) return;
        var headRows = thead ? thead.rows : [];
        var headerCells = headRows.length ? Array.prototype.slice.call(headRows[0].cells) : [];

        var state = { query: "", severity: "all", sortCol: -1, sortDir: 1, page: 0 };
        var rows = Array.prototype.slice.call(tbody.rows);
        if (rows.length === 0 && !table.hasAttribute("data-interactive-empty")) return;

        var toolbar = document.createElement("div");
        toolbar.className = "table-toolbar";
        toolbar.setAttribute("role", "search");

        var search = document.createElement("input");
        search.type = "search";
        search.className = "table-search";
        search.placeholder = "Search...";
        search.setAttribute("aria-label", "Search table");

        var pillsWrap = document.createElement("div");
        pillsWrap.className = "d-flex gap-1 flex-wrap";
        pillsWrap.setAttribute("role", "group");
        pillsWrap.setAttribute("aria-label", "Filter by severity");

        ["all", "critical", "high", "medium", "low"].forEach(function (sev) {
            var pill = document.createElement("button");
            pill.type = "button";
            pill.className = "filter-pill" + (sev === "all" ? " active" : "");
            pill.textContent = sev.charAt(0).toUpperCase() + sev.slice(1);
            pill.dataset.severity = sev;
            pill.addEventListener("click", function () {
                pillsWrap.querySelectorAll(".filter-pill").forEach(function (p) { p.classList.remove("active"); });
                pill.classList.add("active");
                state.severity = sev;
                state.page = 0;
                apply();
            });
            pillsWrap.appendChild(pill);
        });

        var pagerInfo = document.createElement("span");
        pagerInfo.className = "pager";
        var prevBtn = document.createElement("button");
        prevBtn.type = "button";
        prevBtn.innerHTML = "&lsaquo;";
        prevBtn.setAttribute("aria-label", "Previous page");
        var nextBtn = document.createElement("button");
        nextBtn.type = "button";
        nextBtn.innerHTML = "&rsaquo;";
        nextBtn.setAttribute("aria-label", "Next page");
        var pageLabel = document.createElement("span");
        pageLabel.setAttribute("aria-live", "polite");
        pagerInfo.appendChild(prevBtn);
        pagerInfo.appendChild(pageLabel);
        pagerInfo.appendChild(nextBtn);

        toolbar.appendChild(search);
        toolbar.appendChild(pillsWrap);
        toolbar.appendChild(pagerInfo);
        table.parentNode.insertBefore(toolbar, table);

        function visibleRows() {
            var q = state.query.toLowerCase();
            var filtered = rows.filter(function (row) {
                if (row.classList.contains("ator-row-hidden-by-feed")) return false;
                if (state.severity !== "all" && severityOf(row) !== state.severity) return false;
                if (q && textOf(row).indexOf(q) === -1) return false;
                return true;
            });
            if (state.sortCol >= 0) {
                filtered.sort(function (a, b) {
                    var av = a.cells[state.sortCol] ? a.cells[state.sortCol].textContent.trim() : "";
                    var bv = b.cells[state.sortCol] ? b.cells[state.sortCol].textContent.trim() : "";
                    var an = parseFloat(av.replace(/[^\d.-]/g, ""));
                    var bn = parseFloat(bv.replace(/[^\d.-]/g, ""));
                    if (!isNaN(an) && !isNaN(bn) && av.match(/[\d.]/) && bv.match(/[\d.]/)) {
                        return (an - bn) * state.sortDir;
                    }
                    return av.localeCompare(bv) * state.sortDir;
                });
            }
            return filtered;
        }

        function apply() {
            var vis = visibleRows();
            var pages = Math.max(1, Math.ceil(vis.length / PAGE_SIZE));
            if (state.page >= pages) state.page = pages - 1;
            if (state.page < 0) state.page = 0;
            var startIdx = state.page * PAGE_SIZE;
            var shown = new Set(vis.slice(startIdx, startIdx + PAGE_SIZE));
            rows.forEach(function (row) {
                row.style.display = shown.has(row) ? "" : "none";
            });
            pageLabel.textContent = vis.length ? "page " + (state.page + 1) + "/" + pages +
                " \u00B7 " + vis.length + " row" + (vis.length === 1 ? "" : "s") : "no matches";
            prevBtn.disabled = state.page === 0;
            nextBtn.disabled = state.page >= pages - 1;
            headerCells.forEach(function (cell, idx) {
                cell.classList.remove("sorted-asc", "sorted-desc");
                if (idx === state.sortCol) {
                    cell.classList.add(state.sortDir === 1 ? "sorted-asc" : "sorted-desc");
                }
            });
            var emptyRow = tbody.querySelector(".empty-hint-row");
            if (vis.length === 0 && emptyRow) emptyRow.style.display = "";
            if (vis.length > 0 && emptyRow) emptyRow.style.display = "none";
        }

        search.addEventListener("input", function () {
            state.query = search.value;
            state.page = 0;
            apply();
        });
        prevBtn.addEventListener("click", function () { state.page--; apply(); });
        nextBtn.addEventListener("click", function () { state.page++; apply(); });

        headerCells.forEach(function (cell, idx) {
            if (!cell.hasAttribute || !cell.hasAttribute("data-sort")) return;
            cell.classList.add("sortable");
            cell.setAttribute("tabindex", "0");
            cell.setAttribute("role", "columnheader button");
            function toggle() {
                if (state.sortCol === idx) { state.sortDir *= -1; }
                else { state.sortCol = idx; state.sortDir = 1; }
                apply();
            }
            cell.addEventListener("click", toggle);
            cell.addEventListener("keydown", function (e) {
                if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); }
            });
        });

        apply();

        table.__atorRefresh = function () {
            rows = Array.prototype.slice.call(tbody.rows);
            apply();
        };
        var observer = new MutationObserver(function () { table.__atorRefresh(); });
        observer.observe(tbody, { childList: true });
    }

    function enhanceAll(root) {
        (root || document).querySelectorAll("table[data-interactive]").forEach(enhance);
    }

    window.ATOR = window.ATOR || {};
    window.ATOR.tables = { enhanceAll: enhanceAll };
})();
