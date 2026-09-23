"""The behavioural-lead queue: search, filters, sorting and pagination.

The queue used to render a fixed 60 rows and count its headline numbers from that slice.
Now filtering and paging happen in SQL, which introduces two risks these tests pin down:
the SQL filter disagreeing with the badge the row shows (priority), and the page rendering
more rows than it claims to.
"""
import json
import re

import pytest

from server import db as database
from server.engine import ml_vocabulary as vocab
from server.ui import lead_page, lead_page_numbers, lead_query, read_lead_params

TACTICS = ("execution", "credential_access", "defense_evasion")


class _Request:
    """Just enough of a Starlette request for read_lead_params."""

    def __init__(self, query=""):
        from starlette.datastructures import QueryParams
        self.query_params = QueryParams(query)


def _seed(db, n=60):
    conn = database.connect(db)
    host_ids = []
    for name in ("WIN-A", "WIN-B"):
        host_ids.append(conn.execute(
            """INSERT INTO hosts (client_id, hostname, os_type, api_key_hash, enrolled_at_utc)
               VALUES (?, ?, 'windows', 'h', '2026-09-01T00:00:00+00:00')""",
            (f"c-{name}", name)).lastrowid)
    for i in range(n):
        confidence = None if i % 7 == 0 else round((i % 10) / 10, 2)
        anomaly = 0.9995 if i % 7 == 0 and i % 2 == 0 else round(0.99 + (i % 9) / 1000, 4)
        tactics = (json.dumps({"suggestions": [{"tactic": TACTICS[i % 3], "probability": 0.9}]})
                   if i % 4 == 0 else None)
        det = conn.execute(
            """INSERT INTO detections (host_id, rule_type, rule_name, severity, summary,
                    detected_at_utc, anomaly_score, confidence_score, suggested_tactics,
                    hit_count, last_seen_utc)
               VALUES (?, 'ml_anomaly', ?, 'medium', ?, ?, ?, ?, ?, ?, ?)""",
            (host_ids[i % 2], f"ML Anomaly: proc{i}.exe",
             json.dumps({"pid": str(1000 + i), "name": f"proc{i}.exe",
                         "cmdline": f"proc{i}.exe --flag{i}",
                         "exe_path": rf"C:\Tools\proc{i}.exe"}),
             f"2026-09-{(i % 27) + 1:02d}T10:00:00+00:00", anomaly, confidence, tactics,
             (i % 5) + 1, f"2026-09-{(i % 27) + 1:02d}T11:00:00+00:00")).lastrowid
        if i % 11 == 0:
            conn.execute("""INSERT INTO ml_feedback (detection_id, verdict, recorded_at_utc)
                            VALUES (?, ?, '2026-09-20T00:00:00+00:00')""",
                         (det, "confirmed" if i % 22 == 0 else "benign"))
    # a rule detection: never part of the behavioural queue
    conn.execute("""INSERT INTO detections (host_id, rule_type, rule_name, severity, summary,
                        detected_at_utc) VALUES (?, 'sigma', 'Sigma: rule', 'high', '{}', 't')""",
                 (host_ids[0],))
    conn.commit()
    conn.close()
    return host_ids


@pytest.fixture()
def seeded(tmp_db):
    hosts = _seed(tmp_db)
    conn = database.connect(tmp_db)
    yield {"db": tmp_db, "conn": conn, "hosts": hosts}
    conn.close()


def _page(conn, query=""):
    return lead_page(conn, read_lead_params(_Request(query)))


class TestFiltering:
    def test_only_behavioural_leads_are_listed(self, seeded):
        assert _page(seeded["conn"])["total"] == 60           # the sigma row is excluded

    def test_search_matches_process_command_line_and_host(self, seeded):
        by_name = _page(seeded["conn"], "q=proc7.exe")
        assert [l["process"] for l in by_name["leads"]] == ["proc7.exe"]
        assert _page(seeded["conn"], "q=--flag12")["total"] == 1
        assert _page(seeded["conn"], "q=win-a")["total"] == 30
        assert _page(seeded["conn"], "q=" + "no-such-process")["total"] == 0

    def test_search_is_case_insensitive(self, seeded):
        assert _page(seeded["conn"], "q=PROC7.EXE")["total"] == 1

    @pytest.mark.parametrize("label", ["P1", "P2", "P3", "P4"])
    def test_priority_filter_matches_the_badge_on_every_row(self, seeded, label):
        """The chip and the badge must select the same leads - they share the thresholds."""
        result = _page(seeded["conn"], f"priority={label}&per_page=100")
        assert result["leads"], f"no lead is {label} in the fixture"
        assert {l["priority"]["label"] for l in result["leads"]} == {label}
        everything = _page(seeded["conn"], "per_page=100")["leads"]
        expected = sum(1 for l in everything if l["priority"]["label"] == label)
        assert result["total"] == expected

    def test_priority_chips_combine(self, seeded):
        both = _page(seeded["conn"], "priority=P1&priority=P2&per_page=100")
        assert {l["priority"]["label"] for l in both["leads"]} == {"P1", "P2"}
        assert both["total"] == (_page(seeded["conn"], "priority=P1")["total"]
                                 + _page(seeded["conn"], "priority=P2")["total"])

    def test_host_filter(self, seeded):
        result = _page(seeded["conn"], f"host_id={seeded['hosts'][0]}")
        assert result["total"] == 30
        assert {l["hostname"] for l in result["leads"]} == {"WIN-A"}

    def test_verdict_filter(self, seeded):
        assert _page(seeded["conn"], "verdict=confirmed")["total"] == 3
        assert _page(seeded["conn"], "verdict=benign")["total"] == 3
        assert _page(seeded["conn"], "verdict=unreviewed")["total"] == 54

    def test_tactic_filter(self, seeded):
        assert _page(seeded["conn"], "tactic=any")["total"] == 15
        assert _page(seeded["conn"], "tactic=none")["total"] == 45
        named = _page(seeded["conn"], "tactic=execution&per_page=100")
        assert named["total"] == 5
        assert all(l["tactics"][0]["name"] == vocab.tactic("execution")["name"]
                   for l in named["leads"])

    def test_filters_combine(self, seeded):
        result = _page(seeded["conn"], f"q=proc&host_id={seeded['hosts'][0]}&tactic=any"
                                       "&per_page=100")
        assert result["total"] == 15
        assert all(l["hostname"] == "WIN-A" and l["tactics"] for l in result["leads"])
        # the same filters on the other host: every tactic-bearing lead is on WIN-A
        assert _page(seeded["conn"], f"host_id={seeded['hosts'][1]}&tactic=any")["total"] == 0

    def test_filters_active_flag_drives_the_clear_button(self, seeded):
        assert _page(seeded["conn"])["filters_active"] is False
        assert _page(seeded["conn"], "q=proc")["filters_active"] is True
        assert _page(seeded["conn"], "sort=newest")["filters_active"] is False


class TestSortingAndPaging:
    def test_default_sort_is_threat_likelihood_with_unscored_last(self, seeded):
        leads = _page(seeded["conn"], "per_page=100")["leads"]
        scored = [l["confidence_score"] for l in leads if l["confidence_score"] is not None]
        assert scored == sorted(scored, reverse=True)
        unscored_at = [i for i, l in enumerate(leads) if l["confidence_score"] is None]
        assert min(unscored_at) > max(i for i, l in enumerate(leads)
                                      if l["confidence_score"] is not None)

    @pytest.mark.parametrize("sort,key", [("rarity", "anomaly_score"),
                                          ("sightings", "hit_count")])
    def test_other_sorts(self, seeded, sort, key):
        leads = _page(seeded["conn"], f"sort={sort}&per_page=100")["leads"]
        values = [l[key] for l in leads]
        assert values == sorted(values, reverse=True)

    def test_newest_sort(self, seeded):
        leads = _page(seeded["conn"], "sort=newest&per_page=100")["leads"]
        seen = [l["last_seen_utc"] for l in leads]
        assert seen == sorted(seen, reverse=True)

    def test_pages_are_disjoint_and_cover_everything(self, seeded):
        first = _page(seeded["conn"], "per_page=25")
        second = _page(seeded["conn"], "per_page=25&page=2")
        third = _page(seeded["conn"], "per_page=25&page=3")
        assert (first["pages"], first["total"]) == (3, 60)
        assert (len(first["leads"]), len(second["leads"]), len(third["leads"])) == (25, 25, 10)
        ids = [l["id"] for l in first["leads"] + second["leads"] + third["leads"]]
        assert len(set(ids)) == 60

    def test_page_counters_describe_the_slice(self, seeded):
        second = _page(seeded["conn"], "per_page=25&page=2")
        assert (second["first"], second["last"], second["total"]) == (26, 50, 60)

    def test_page_beyond_the_end_is_clamped(self, seeded):
        result = _page(seeded["conn"], "per_page=25&page=99")
        assert result["page"] == 3 and result["leads"]

    def test_empty_result_reports_zero_not_a_crash(self, seeded):
        result = _page(seeded["conn"], "q=nothing-matches-this")
        assert (result["total"], result["first"], result["last"], result["pages"]) == (0, 0, 0, 1)
        assert result["leads"] == []


class TestParameterHandling:
    @pytest.mark.parametrize("query,field,expected", [
        ("page=abc", "page", 1), ("page=-4", "page", 1),
        ("per_page=7", "per_page", 25), ("per_page=100", "per_page", 100),
        ("sort=nonsense", "sort", "likelihood"),
        ("verdict=maybe", "verdict", None),
        ("host_id=abc", "host_id", None), ("host_id=any", "host_id", None),
        ("priority=P9", "priority", []),
    ])
    def test_bad_values_fall_back_to_defaults(self, query, field, expected):
        assert read_lead_params(_Request(query))[field] == expected

    def test_search_is_length_capped(self):
        assert len(read_lead_params(_Request("q=" + "x" * 500))["q"]) == 200

    def test_a_hand_edited_url_still_renders(self, seeded):
        assert _page(seeded["conn"], "page=abc&per_page=7&sort=x&priority=P9")["total"] == 60


class TestQueryStringHelpers:
    QUEUE = {"filters": {"q": "node", "priority": ["P1"], "host_id": 3, "verdict": "unreviewed",
                         "tactic": None, "sort": "rarity", "per_page": 50, "page": 2},
             "page": 2, "pages": 9}

    def test_pager_links_keep_every_filter(self):
        qs = lead_query(self.QUEUE, page=3)
        assert "q=node" in qs and "priority=P1" in qs and "host_id=3" in qs
        assert "verdict=unreviewed" in qs and "sort=rarity" in qs and "per_page=50" in qs
        assert "page=3" in qs

    def test_page_one_is_left_out_of_the_url(self):
        from urllib.parse import parse_qs
        assert "page" not in parse_qs(lead_query(self.QUEUE, page=1))

    def test_page_numbers_collapse_with_gaps(self):
        assert lead_page_numbers({"pages": 20, "page": 10}) == [1, None, 8, 9, 10, 11, 12, None, 20]
        assert lead_page_numbers({"pages": 5, "page": 2}) == [1, 2, 3, 4, 5]


class TestRendering:
    @pytest.fixture()
    def client(self, tmp_db, tmp_path, monkeypatch):
        _seed(tmp_db)
        monkeypatch.setenv("ATOR_DFIR_DB", tmp_db)
        monkeypatch.setenv("ATOR_MLOPS_HOME", str(tmp_path / "mlops"))
        from fastapi.testclient import TestClient
        from server.app import app
        with TestClient(app) as tc:
            yield tc

    def test_page_renders_only_one_page_of_rows(self, client):
        """The DOM stays small however many leads exist - that is what keeps it smooth."""
        html = client.get("/ml?per_page=25").text
        assert len(re.findall(r'class="lead-row"', html)) == 25
        assert len(re.findall(r'class="lead-row"', client.get("/ml?per_page=50").text)) == 50

    def test_filter_controls_are_present_and_reflect_the_url(self, client):
        html = client.get("/ml?q=proc7&priority=P1&sort=rarity").text
        assert 'id="leadFilters"' in html and 'method="get"' in html
        assert 'value="proc7"' in html
        assert re.search(r'name="priority" value="P1"[^>]*checked', html)
        assert re.search(r'<option value="rarity"[^>]*selected', html)

    def test_partial_returns_the_table_only(self, client):
        partial = client.get("/ml?partial=1")
        assert partial.status_code == 200
        body = partial.text
        assert "lead-row" in body
        assert "navbar" not in body and "Detection model updates" not in body
        assert "<html" not in body
        assert 'id="leadFilters"' not in body          # controls keep focus, so never swapped

    def test_headline_counts_cover_every_lead_not_the_page(self, client):
        html = client.get("/ml?per_page=25").text
        kpi = re.search(r'kpi-label">Open leads</div>\s*<div class="kpi-num">(\d+)', html)
        assert kpi and kpi.group(1) == "60"

    def test_counts_ignore_filters(self, client):
        """Filtering the queue must not change the posture headline."""
        html = client.get("/ml?q=proc7").text
        kpi = re.search(r'kpi-label">Open leads</div>\s*<div class="kpi-num">(\d+)', html)
        assert kpi.group(1) == "60"

    def test_pager_appears_and_links_carry_filters(self, client):
        html = client.get("/ml?per_page=25&q=proc").text
        assert "Showing <b>1&ndash;25</b> of" in html
        assert re.search(r'href="\?[^"]*q=proc[^"]*page=2"', html)

    def test_no_leads_at_all_versus_no_match(self, client, tmp_db):
        assert "No lead matches these filters" in client.get("/ml?q=zzzz").text
        conn = database.connect(tmp_db)
        conn.execute("""DELETE FROM ml_feedback WHERE detection_id IN
                        (SELECT id FROM detections WHERE rule_type='ml_anomaly')""")
        conn.execute("DELETE FROM detections WHERE rule_type='ml_anomaly'")
        conn.commit()
        conn.close()
        assert "No behavioural leads yet" in client.get("/ml").text
