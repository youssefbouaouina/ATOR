import glob
import json
import os
import re

import yaml

TABLE_FOR_CATEGORY = {
    "process_creation": ("raw_processes", ["cmdline", "name", "exe_path"]),
    "network_connection": ("raw_connections", ["remote_ip", "process_name"]),
}

FIELD_MAP = {
    "commandline": "cmdline",
    "processcommandline": "cmdline",
    "image": "exe_path",
    "imagefilename": "exe_path",
    "processpath": "exe_path",
    "parentimage": "parent_exe_path",
    "parentimagefilename": "parent_exe_path",
    "user": "username",
    "username": "username",
    "destinationip": "remote_ip",
    "destinationhostname": "remote_ip",
    "destinationport": "remote_port",
    "remoteport": "remote_port",
    "sourceip": "local_ip",
    "sourceport": "local_port",
    "localport": "local_port",
    "protocol": "proto",
    "processname": "process_name",
    "servicename": "name",
}

RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "rules", "behavioral",
)


def _escape_like(value):
    return str(value).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _wildcard_to_like(value):
    return str(value).replace("*", "%").replace("?", "_")


def _like_clause(column, value):
    return f"{column} LIKE ? ESCAPE '\\'", [f"%{_escape_like(value)}%"]


def _b64_variants(text):
    import base64
    return [
        base64.b64encode(text.encode()).decode(),
        base64.b64encode((" " + text).encode()).decode(),
        base64.b64encode(("  " + text).encode()).decode(),
    ]


def _field_condition(column, modifier, value):
    if column == "parent_exe_path":
        like_val = _wildcard_to_like(value)
        pattern = "%" + _escape_like(like_val.lstrip("%")) if not like_val.startswith("%") else like_val
        return (
            "(EXISTS (SELECT 1 FROM raw_processes parent "
            "WHERE parent.pid = t.ppid AND parent.host_id = t.host_id "
            f"AND parent.exe_path LIKE ? ESCAPE '\\'))",
            [pattern],
        )
    if modifier in (None, "", "all"):
        plain = _wildcard_to_like(value)
        if "*" in plain or "?" in plain:
            return f"{column} LIKE ? ESCAPE '\\'", [_escape_like(plain)]
        return f"{column} = ?", [value]
    if modifier == "contains":
        return _like_clause(column, value)
    if modifier == "endswith":
        stripped = str(value).rstrip("*")
        return f"{column} LIKE ? ESCAPE '\\'", ["%" + _escape_like(_wildcard_to_like(stripped))]
    if modifier == "startswith":
        stripped = str(value).lstrip("*")
        return f"{column} LIKE ? ESCAPE '\\'", [_escape_like(_wildcard_to_like(stripped)) + "%"]
    if modifier == "re":
        return f"{column} REGEXP ?", [str(value)]
    if modifier == "base64":
        parts = [_like_clause(column, v) for v in _b64_variants(str(value))]
        return "(" + " OR ".join(p[0] for p in parts) + ")", [x for p in parts for x in p[1]]
    if modifier in ("gt", "gte", "lt", "lte"):
        op = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[modifier]
        try:
            num = int(value)
        except (TypeError, ValueError):
            num = float(value)
        return f"CAST({column} AS NUMERIC) {op} ?", [num]
    if modifier == "exists":
        return (f"{column} IS NOT NULL" if value else f"{column} IS NULL"), []
    return None


def _lookup_field(field_name):
    low = field_name.lower()
    if low in FIELD_MAP:
        return FIELD_MAP[low]
    compact = low.replace("_", "").replace("-", "")
    return FIELD_MAP.get(compact)


def _selection_item(key, raw_value):
    pieces = key.split("|")
    field_name = pieces[0].strip()
    modifier_chain = [p.strip() for p in pieces[1:]]
    column = _lookup_field(field_name)
    if column is None:
        return None
    values = raw_value if isinstance(raw_value, list) else [raw_value]
    if not isinstance(raw_value, list):
        values = [raw_value]
    joiner = " AND " if "all" in modifier_chain else " OR "
    primary_modifiers = [m for m in modifier_chain if m != "all" and m != "exists"]
    modifier = primary_modifiers[0] if primary_modifiers else None
    conditions = []
    params = []
    for v in values:
        result = _field_condition(column, modifier, v)
        if result is None:
            return None
        clause, p = result
        conditions.append(clause)
        params += p
    if len(conditions) == 1:
        body = conditions[0]
    else:
        body = "(" + joiner.join(conditions) + ")"
    if "exists" in modifier_chain:
        exists_value = bool(raw_value)
        null_check = f"{column} IS NOT NULL" if exists_value else f"{column} IS NULL"
        body = f"({body}) AND {null_check}" if body else null_check
    return body, params


def selection_clause(selection, table, keyword_cols):
    field_clauses = []
    all_params = []
    for key, raw_value in selection.items():
        base_key = key.split("|")[0].strip()
        if base_key.lower() == "keywords" or (isinstance(raw_value, list) and base_key == key and all(isinstance(x, str) for x in raw_value)):
            values = raw_value if isinstance(raw_value, list) else [raw_value]
            ors = []
            kw_params = []
            for v in values:
                sub_clauses = []
                for col in keyword_cols:
                    e, p = _like_clause(col, v)
                    sub_clauses.append(e)
                    kw_params += p
                ors.append("(" + " OR ".join(sub_clauses) + ")")
            field_clauses.append("(" + " OR ".join(ors) + ")")
            all_params += kw_params
            continue
        column = _lookup_field(base_key)
        if column is None:
            continue
        result = _selection_item(key, raw_value)
        if result is None:
            continue
        clause, params = result
        field_clauses.append(clause)
        all_params += params
    if not field_clauses:
        return None, []
    joined = " AND ".join(f"({c})" for c in field_clauses)
    return f"({joined})", all_params


def _resolve_targets(target, names):
    if target == "them":
        return sorted(names)
    if target.endswith("*"):
        prefix = target[:-1]
        return [n for n in names if n.startswith(prefix)]
    return [target] if target in names else []


def _resolve_condition(cond_text, compiled):
    names = set(compiled.keys())
    lowered = cond_text.strip().lower()

    if lowered.startswith(("1 of ", "any of ", "all of ")):
        want_all = lowered.startswith("all of ")
        target = cond_text.strip().split(" of ", 1)[1].strip()
        targets = _resolve_targets(target, names)
        if not targets:
            targets = sorted(names)
        joiner = " AND " if want_all else " OR "
        seq = [("op", "(")]
        for i, n in enumerate(targets):
            if i:
                seq.append(("op", joiner))
            seq.append(("sel", n))
        seq.append(("op", ")"))
        return seq

    tokens = re.findall(r"\(|\)|\bAND\b|\bOR\b|\bNOT\b|[A-Za-z_]\w*(?:\*)?",
                        cond_text, flags=re.IGNORECASE)
    seq = []
    for tok in tokens:
        up = tok.upper()
        if tok == "(":
            seq.append(("op", "("))
        elif tok == ")":
            seq.append(("op", ")"))
        elif up in ("AND", "OR", "NOT"):
            seq.append(("op", up))
        elif tok.rstrip("*") in names:
            seq.append(("sel", tok.rstrip("*")))
        else:
            seq.append(("op", "0"))
    if any(t == "sel" for t, _ in seq):
        return seq
    return None


def compile_rule(doc):
    detection = doc.get("detection") or {}
    category = ((doc.get("logsource") or {}).get("category")) or ""
    table_info = TABLE_FOR_CATEGORY.get(category)
    if table_info is None:
        return None
    table, keyword_cols = table_info

    raw_selections = {k: v for k, v in detection.items() if k not in ("condition", "timeframe")}
    compiled = {}
    for name, sel in raw_selections.items():
        if isinstance(sel, list):
            if sel and all(isinstance(x, str) for x in sel):
                sel = {"keywords": sel}
            else:
                merged = {}
                for item in sel:
                    if isinstance(item, dict):
                        merged.update(item)
                sel = merged
        if not isinstance(sel, dict):
            continue
        clause, params = selection_clause(sel, table, keyword_cols)
        if clause is not None:
            compiled[name] = (clause, params)
    if not compiled:
        return None

    cond_text = (detection.get("condition") or "selection").strip()
    resolved = _resolve_condition(cond_text, compiled)
    if resolved is None:
        first_name = sorted(compiled.keys())[0]
        final_clause, final_params = compiled[first_name]
        final_clause = f"({final_clause})"
    else:
        pieces = []
        final_params = []
        for token_type, token in resolved:
            if token_type == "sel":
                clause, params = compiled[token]
                pieces.append(f"({clause})")
                final_params += params
            else:
                pieces.append(token)
        final_clause = "(" + " ".join(pieces) + ")"

    tags = doc.get("tags") or []
    technique_id = None
    known_tactics = {
        "reconnaissance", "resource-development", "initial-access", "execution",
        "persistence", "privilege-escalation", "defense-evasion", "credential-access",
        "discovery", "lateral-movement", "collection", "command-and-control",
        "exfiltration", "impact",
    }
    tactic = None
    for tag in tags:
        m = re.match(r"^attack\.(t\d{4}(?:\.\d{3})?)$", tag, flags=re.IGNORECASE)
        if m:
            technique_id = m.group(1).upper()
        elif tag.startswith("attack.") and tag[7:] in known_tactics:
            tactic = tag[7:]
    return {
        "title": doc.get("title", "untitled"),
        "rule_id": doc.get("id", ""),
        "cause": doc.get("x-ator-cause"),
        "investigation_hint": doc.get("x-ator-investigation-hint"),
        "level": (doc.get("level") or "medium").lower(),
        "tags": tags,
        "table": table,
        "category": category,
        "sql_where": final_clause,
        "params": final_params,
        "technique_id": technique_id,
        "tactic": tactic,
    }


def validate_with_pysigma(rule_text):
    try:
        from sigma.rule import SigmaRule
        SigmaRule.from_yaml(rule_text)
        return True, None
    except ImportError:
        return False, "pysigma-not-installed"
    except Exception as exc:
        return False, str(exc)


def load_rules(rules_dir=None):
    directory = rules_dir or RULES_DIR
    paths = sorted(
        glob.glob(os.path.join(directory, "*.yml")) + glob.glob(os.path.join(directory, "*.yaml"))
    )
    rules = []
    errors = []
    for path in paths:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        ok, err = validate_with_pysigma(text)
        if not ok:
            errors.append({"rule": os.path.basename(path), "error": err})
            continue
        doc = yaml.safe_load(text)
        compiled_rule = compile_rule(doc)
        if compiled_rule is None:
            errors.append({"rule": os.path.basename(path), "error": "unsupported-target"})
            continue
        compiled_rule["path"] = path
        rules.append(compiled_rule)
    return rules, errors


def _regexp(pattern, value):
    if value is None:
        return 0
    try:
        return 1 if re.search(pattern, str(value)) else 0
    except re.error:
        return 0


def run(conn, since_utc=None, host_ids=None, rules_dir=None):
    conn.create_function("REGEXP", 2, _regexp)
    rules, errors = load_rules(rules_dir)
    fired = []
    for rule in rules:
        sql = f"SELECT * FROM {rule['table']} t WHERE {rule['sql_where']}"
        params = list(rule["params"])
        conditions = []
        if since_utc:
            # >= not >: timestamps are second-resolution, so a collection that
            # lands in the same second as the previous engine run would be
            # skipped with a strict >, silently dropping its detections. Re-
            # scanned rows fold into existing detections via insert_detections'
            # dedupe, so the overlap is harmless.
            conditions.append("t.collected_at_utc >= ?")
            params.append(since_utc)
        if host_ids:
            placeholders = ",".join("?" for _ in host_ids)
            conditions.append(f"t.host_id IN ({placeholders})")
            params += host_ids
        if conditions:
            sql += " AND " + " AND ".join(conditions)
        sql += " LIMIT 200"
        try:
            rows = conn.execute(sql, params).fetchall()
        except Exception as exc:
            errors.append({"rule": rule["title"], "error": f"sql:{exc}", "sql": sql})
            continue
        for row in rows:
            fired.append({
                "rule_type": "sigma",
                "rule_name": rule["title"],
                "severity": rule["level"],
                "technique_id": rule["technique_id"],
                "host_id": row["host_id"],
                "collection_id": row["collection_id"],
                "detected_at_utc": row["collected_at_utc"],
                "summary": summarize_hit(
                    row, rule.get("cause"), rule.get("investigation_hint")
                ),
                "evidence": {"table": rule["table"], "row_id": row["id"], "sigma_id": rule["rule_id"]},
            })
    return fired, errors


def summarize_hit(row, cause=None, investigation_hint=None):
    keys = row.keys()
    out = {}
    for k in ("pid", "ppid", "name", "cmdline", "exe_path", "username",
              "remote_ip", "remote_port", "local_ip", "local_port", "proto", "process_name"):
        if k in keys and row[k]:
            out[k] = str(row[k])[:300]
    if cause:
        out["cause_category"] = cause
    if investigation_hint:
        out["investigation_hint"] = investigation_hint
    return json.dumps(out, default=str)
