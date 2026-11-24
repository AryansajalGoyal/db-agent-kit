"""Build a migration plan. Pure functions: no database access and no subprocess.

A plan is a JSON document: the source facts, a pre-flight verdict, what a BACPAC does not carry, and the
ordered steps. A person reads it first. `migrate run` then executes exactly the steps it lists, and only
if the plan's fingerprint (sha256 of its content) is the one that was approved.

Passwords are never part of a plan. Every command in it is shown with the password replaced by ***.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

PLAN_VERSION = 1
METHODS = ("bacpac",)
AZURE_SQL_DB_SUFFIX = ".database.windows.net"
REDACTED = "***"


class PlanError(ValueError):
    """The request cannot be planned. The message says why and what to do instead."""


def is_azure_sql_db(server: str) -> bool:
    return server.strip().lower().endswith(AZURE_SQL_DB_SUFFIX)


# ---- commands (one builder per command, used for both display and execution) -------------------------
def _tf(value: bool) -> str:
    return "True" if value else "False"


def export_argv(src: dict[str, Any], bacpac: str, password: str) -> list[str]:
    return [
        "sqlpackage", "/Action:Export",
        f"/SourceServerName:{src['server']},{src['port']}",
        f"/SourceDatabaseName:{src['database']}",
        f"/SourceUser:{src['user']}", f"/SourcePassword:{password}",
        f"/SourceEncryptConnection:{_tf(src['encrypt'])}",
        f"/SourceTrustServerCertificate:{_tf(src['trust_server_certificate'])}",
        f"/TargetFile:{bacpac}",
        "/Quiet:True",
    ]


def import_argv(tgt: dict[str, Any], bacpac: str, password: str) -> list[str]:
    return [
        "sqlpackage", "/Action:Import",
        f"/SourceFile:{bacpac}",
        f"/TargetServerName:{tgt['server']},{tgt['port']}",
        f"/TargetDatabaseName:{tgt['database']}",
        f"/TargetUser:{tgt['user']}", f"/TargetPassword:{password}",
        f"/TargetEncryptConnection:{_tf(tgt['encrypt'])}",
        f"/TargetTrustServerCertificate:{_tf(tgt['trust_server_certificate'])}",
        "/Quiet:True",
    ]


def az_create_argv(tgt: dict[str, Any], create: dict[str, Any]) -> list[str]:
    """`az sql db create` for the target. `create` holds resource_group, free_limit, service_objective."""
    server_name = tgt["server"].split(".")[0]
    argv = ["az", "sql", "db", "create", "--resource-group", create["resource_group"], "--server", server_name,
            "--name", tgt["database"], "--output", "none"]
    if create["free_limit"]:
        argv += ["--use-free-limit", "--free-limit-exhaustion-behavior", "AutoPause",
                 "--edition", "GeneralPurpose", "--family", "Gen5", "--capacity", "2", "--compute-model", "Serverless",
                 "--min-capacity", "0.5", "--auto-pause-delay", "60", "--backup-storage-redundancy", "Local"]
    else:
        argv += ["--service-objective", create["service_objective"]]
    return argv


# ---- pre-flight -----------------------------------------------------------------------------------
def preflight(inv: dict[str, Any], database: str, risks: list[dict[str, Any]]) -> dict[str, Any]:
    """Split the inventory risks into what blocks a move to Azure SQL Database and what does not."""
    db = next((d for d in inv["databases"] if d["name"].lower() == database.lower()), None)
    if db is None:
        raise PlanError(f"database {database!r} was not found on the source server (or it is not ONLINE).")
    mine = [r for r in risks if r["database"].lower() == database.lower()]
    blockers = [r for r in mine if r["azure_sql_database_only"]]
    warnings = [r for r in mine if not r["azure_sql_database_only"] and r["severity"] in ("high", "medium")]
    jobs = sorted({j["job_name"] for j in inv.get("agent_jobs", []) if (j.get("database_name") or "").lower() == database.lower()})
    objs = inv["objects"].get(db["name"], {})
    return {
        "verdict": "blocked" if blockers else "ready",
        "database": {k: db.get(k) for k in ("name", "compatibility_level", "recovery_model_desc", "data_mb", "log_mb")},
        "tables": len(objs.get("tables", [])),
        "rows": sum(t.get("rows") or 0 for t in objs.get("tables", [])),
        "blockers": [_slim(r) for r in blockers],
        "warnings": [_slim(r) for r in warnings],
        "agent_jobs_using_database": jobs,
        "linked_servers": [ls["name"] for ls in inv.get("linked_servers", [])],
    }


def _slim(r: dict[str, Any]) -> dict[str, str]:
    return {k: r[k] for k in ("id", "severity", "title", "object", "detail", "doc")}


NOT_CARRIED = [
    "Logins and server-level permissions. A BACPAC holds database users, not the server logins they map to. Create the logins or contained users on the target and check for orphaned users.",
    "SQL Server Agent jobs. Azure SQL Database has no SQL Server Agent. Re-create schedules as elastic jobs or in another scheduler.",
    "Linked servers, server-level triggers, credentials, Database Mail and server configuration.",
    "Anything outside this database: other databases, SSRS reports and their data sources.",
    "Consistency. A BACPAC export is not one transaction. Rows written to the source while it runs can be half in the file. Stop the writers first; the run compares row counts before and after the export and says if the source changed.",
]


# ---- the plan -------------------------------------------------------------------------------------
def build_plan(
    *, inv: dict[str, Any], risks: list[dict[str, Any]], source: dict[str, Any], target: dict[str, Any],
    method: str, create: dict[str, Any] | None, target_state: dict[str, Any], tool_version: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """source/target: server, port, database, user, encrypt, trust_server_certificate (no password).
    create: None, or resource_group, free_limit, service_objective. target_state: {"reachable": bool,
    "exists": bool, "detail": str} from a read-only look at the target server."""
    if method not in METHODS:
        raise PlanError(f"method {method!r} is not implemented. Available: {', '.join(METHODS)}.")
    if not is_azure_sql_db(target["server"]):
        raise PlanError("this version plans moves to Azure SQL Database only (a server name ending in .database.windows.net). "
                        "For SQL Server to SQL Server use BACKUP and RESTORE; that is not built yet.")
    when = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    pf = preflight(inv, source["database"], risks)
    exists = bool(target_state.get("exists"))
    if exists:
        raise PlanError(f"database {target['database']!r} already exists on the target; the import needs an empty new database. Choose a new name.")
    if not create:
        raise PlanError("the target database does not exist and --create-target was not given. "
                        "Import into an existing database is not supported; pass --create-target.")

    steps: list[dict[str, Any]] = []

    def step(id_: str, title: str, kind: str, writes: str, command: list[str] | None = None, note: str = "") -> None:
        steps.append({"id": id_, "title": title, "kind": kind, "writes": writes, "command": command or [], "note": note})

    cost = "free offer (AutoPause on limit exhaustion)" if create["free_limit"] else f"billable, service objective {create['service_objective']}"
    step("create-target-db", f"Create empty database {target['database']} on {target['server']}", "write",
         f"Creates database {target['database']} on the target server. Cost: {cost}.",
         az_create_argv(target, create), "Needs the Azure CLI, logged in to the right subscription.")
    step("baseline", f"Count rows in every table of {source['database']} (before)", "check", "Nothing. Read-only SELECTs on the source.")
    step("export", f"Export {source['database']} to a BACPAC file", "write",
         "Writes one local file (contains business data; mode 600). The source is not changed.",
         export_argv(source, "<out>/artifacts/" + source["database"] + ".bacpac", REDACTED))
    step("post-export-check", "Count rows again and compare with the baseline", "check",
         "Nothing. Tells you if the source changed during the export.")
    step("import", f"Import the BACPAC into {target['database']}", "write",
         f"Loads schema and data into {target['database']} on {target['server']}.",
         import_argv(target, "<out>/artifacts/" + source["database"] + ".bacpac", REDACTED))
    step("verify", "Compare source and target: row counts, object counts, users, compatibility level", "check",
         "Nothing. Read-only SELECTs on both servers.")

    plan: dict[str, Any] = {
        "plan_version": PLAN_VERSION,
        "tool": f"db-agent {tool_version}",
        "created_at": when.isoformat(),
        "method": method,
        "source": {**source, "version": inv["server"].get("product_version"), "edition": inv["server"].get("edition"),
                   "engine_edition": inv["server"].get("engine_edition")},
        "target": {**target, "kind": "azure-sql-database", "exists": exists, "reachable": bool(target_state.get("reachable")),
                   "target_check": target_state.get("detail", "")},
        "create": create,
        "preflight": pf,
        "not_carried": NOT_CARRIED,
        "steps": steps,
    }
    return seal(plan)


# ---- fingerprint ----------------------------------------------------------------------------------
def _digest(plan: dict[str, Any]) -> str:
    body = {k: v for k, v in plan.items() if k != "sha256"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def seal(plan: dict[str, Any]) -> dict[str, Any]:
    plan["sha256"] = _digest(plan)
    return plan


def verify_seal(plan: dict[str, Any]) -> bool:
    return bool(plan.get("sha256")) and plan["sha256"] == _digest(plan)


# ---- text -----------------------------------------------------------------------------------------
def render_markdown(plan: dict[str, Any]) -> str:
    s, t, pf = plan["source"], plan["target"], plan["preflight"]
    db = pf["database"]
    out = [
        f"# Migration plan: {s['database']} to {t['database']}",
        "",
        f"- Source: `{s['server']}` (SQL Server {s['version']}, {s['edition']}), database `{s['database']}`, compatibility level {db['compatibility_level']}, "
        f"data {db['data_mb']} MB, {pf['tables']} tables, about {pf['rows']:,} rows (from metadata).",
        f"- Target: `{t['server']}` (Azure SQL Database), new database `{t['database']}`.",
        f"- Method: {plan['method']} (sqlpackage export, then import).",
        f"- Pre-flight: **{pf['verdict'].upper()}**. {len(pf['blockers'])} blocker(s), {len(pf['warnings'])} warning(s).",
        f"- Plan fingerprint: `{plan['sha256']}`",
        "",
    ]
    if pf["blockers"]:
        out += ["## Blockers (Azure SQL Database does not support these)", ""]
        out += [f"- **{b['title']}**: {b['object'] or '(database)'}. {b['detail']}" for b in pf["blockers"]]
        out.append("")
    if pf["warnings"]:
        out += ["## Warnings", ""]
        out += [f"- [{w['severity']}] {w['title']}: {w['object'] or '(database)'}" for w in pf["warnings"]]
        out.append("")
    if pf["agent_jobs_using_database"]:
        out += ["## SQL Server Agent jobs that run against this database (possible writers, stop them before the export)", ""]
        out += [f"- {j}" for j in pf["agent_jobs_using_database"]]
        out.append("")
    out += ["## Steps", ""]
    for i, st in enumerate(plan["steps"], 1):
        out.append(f"{i}. **{st['title']}** ({st['kind']}). {st['writes']}")
        if st["command"]:
            out.append(f"   `{' '.join(st['command'])}`")
        if st["note"]:
            out.append(f"   {st['note']}")
    out += ["", "## What a BACPAC does not carry", ""] + [f"- {n}" for n in plan["not_carried"]]
    out += ["", "Passwords are never stored in this file. Approve with the fingerprint above:",
            f"`db-agent sqlserver migrate run --plan migration-plan.json --approve-plan {plan['sha256']}`", ""]
    return "\n".join(out)
