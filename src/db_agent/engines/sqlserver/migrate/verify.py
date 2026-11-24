"""Read-only comparison of a source and a target database. Every statement goes through SafeConnection,
so the query guard checks it first. Rows are counted on the server and never returned."""

from __future__ import annotations

from typing import Any

from ..db import SafeConnection

Q_TABLES = (
    "SELECT s.name AS schema_name, t.name AS table_name FROM sys.tables t "
    "JOIN sys.schemas s ON s.schema_id = t.schema_id WHERE t.is_ms_shipped = 0 ORDER BY s.name, t.name"
)
Q_OBJECTS = "SELECT RTRIM(type) AS type, COUNT(*) AS n FROM sys.objects WHERE is_ms_shipped = 0 GROUP BY type"
Q_USERS = (
    "SELECT name, type_desc FROM sys.database_principals "
    "WHERE type IN ('S', 'U', 'G', 'E', 'X') AND is_fixed_role = 0 "
    "AND name NOT IN ('dbo', 'guest', 'INFORMATION_SCHEMA', 'sys')"
)
Q_DBINFO = "SELECT compatibility_level, collation_name FROM sys.databases WHERE name = DB_NAME()"


def _q(name: str) -> str:
    return "[" + name.replace("]", "]]") + "]"


def snapshot(conn: SafeConnection) -> dict[str, Any]:
    """Exact row count per table, object counts by type, database users and compatibility level."""
    tables = conn.query(Q_TABLES)
    counts: dict[str, int] = {}
    for t in tables:
        full = f"{t['schema_name']}.{t['table_name']}"
        counts[full] = int(conn.query(f"SELECT COUNT_BIG(*) AS n FROM {_q(t['schema_name'])}.{_q(t['table_name'])}")[0]["n"])
    info = conn.query(Q_DBINFO)
    return {
        "row_counts": counts,
        "object_counts": {r["type"]: int(r["n"]) for r in conn.query(Q_OBJECTS)},
        "users": sorted(f"{u['name']} ({u['type_desc']})" for u in conn.query(Q_USERS)),
        "compatibility_level": info[0]["compatibility_level"] if info else None,
        "collation": info[0]["collation_name"] if info else None,
    }


def total_rows(snap: dict[str, Any]) -> int:
    return sum(snap["row_counts"].values())


def source_drift(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """Tables whose row count changed between two source snapshots (writers were active)."""
    out = []
    for name in sorted(set(before["row_counts"]) | set(after["row_counts"])):
        a, b = before["row_counts"].get(name), after["row_counts"].get(name)
        if a != b:
            out.append(f"{name}: {a} -> {b}")
    return out


def compare(source: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    """Compare two snapshots. `status` is pass only if every table matches and nothing is missing."""
    rows = []
    for name in sorted(set(source["row_counts"]) | set(target["row_counts"])):
        s, t = source["row_counts"].get(name), target["row_counts"].get(name)
        status = "match" if s == t else "missing_in_target" if t is None else "extra_in_target" if s is None else "mismatch"
        rows.append({"table": name, "source": s, "target": t, "status": status})
    types = sorted(set(source["object_counts"]) | set(target["object_counts"]))
    obj_diff = [{"type": k, "source": source["object_counts"].get(k, 0), "target": target["object_counts"].get(k, 0)}
                for k in types if source["object_counts"].get(k, 0) != target["object_counts"].get(k, 0)]
    users_missing = sorted(set(source["users"]) - set(target["users"]))
    users_extra = sorted(set(target["users"]) - set(source["users"]))
    bad = [r for r in rows if r["status"] != "match"]
    return {
        "status": "pass" if not bad and not obj_diff else "fail",
        "tables": rows,
        "tables_compared": len(rows),
        "tables_not_matching": len(bad),
        "object_count_differences": obj_diff,
        "users_missing_in_target": users_missing,
        "users_only_in_target": users_extra,
        "compatibility_level": {"source": source["compatibility_level"], "target": target["compatibility_level"]},
        "collation": {"source": source["collation"], "target": target["collation"]},
    }
