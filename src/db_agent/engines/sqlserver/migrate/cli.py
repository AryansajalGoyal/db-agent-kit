"""db-agent sqlserver migrate <plan|run>.

`plan` reads the source and the target (read-only) and writes a plan you review. `run` executes exactly that
plan, and only after you approve its fingerprint. Writes are done by sqlpackage and az, not by this tool's SQL.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Optional

import typer

from .. import __version__, inventory as inventory_mod, risks as risks_mod
from ..db import ConnectionConfig, DatabaseError, SafeConnection
from ..guard import GuardError, QueryGuard
from . import plan as plan_mod
from . import runner

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="Plan a database migration, then run it after you approve the plan. Writes to the target; reads the source only.")

Out = Annotated[Path, typer.Option("--out", help="Folder for the plan, the log and the BACPAC file.")]
STALE_HOURS = 24


def _say(msg: str) -> None:
    typer.echo(msg, err=True)


def _fail(exc: Exception) -> "typer.Exit":
    typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
    return typer.Exit(1)


def _spec(cfg: ConnectionConfig) -> dict[str, Any]:
    return {"server": cfg.server, "port": cfg.port, "database": cfg.database, "user": cfg.user,
            "encrypt": cfg.encrypt, "trust_server_certificate": cfg.trust_server_certificate}


def _cfg(spec: dict[str, Any], env_prefix: str, label: str) -> ConnectionConfig:
    from ..cli import _password  # imported late: sqlserver.cli imports this module

    return ConnectionConfig(server=spec["server"], port=int(spec["port"]), database=spec["database"], user=spec["user"],
                            password=_password(spec["user"], False, f"{env_prefix}_PASSWORD", label), driver="pymssql",
                            encrypt=bool(spec["encrypt"]), trust_server_certificate=bool(spec["trust_server_certificate"]))


@app.command()
def plan(
    source: Annotated[str, typer.Option("--source", help="server=HOST,database=DB,user=U[,port=1433,encrypt=yes,trust_cert=no]. The database is the one to move. Password: DBAGENT_SOURCE_PASSWORD.")],
    target: Annotated[str, typer.Option("--target", help="Same form. The database is the NEW name on the target. Password: DBAGENT_TARGET_PASSWORD.")],
    method: Annotated[str, typer.Option("--method", help="bacpac (the only one for now).")] = "bacpac",
    create_target: Annotated[bool, typer.Option("--create-target", help="Add a step that creates the empty target database with the Azure CLI.")] = False,
    resource_group: Annotated[Optional[str], typer.Option("--resource-group", help="Azure resource group of the target server (needed by --create-target).")] = None,
    free_limit: Annotated[bool, typer.Option("--free-limit", help="Create the target with the Azure SQL Database free offer.")] = False,
    service_objective: Annotated[Optional[str], typer.Option("--service-objective", help="For a billable target, for example GP_S_Gen5_1. Required when --free-limit is not used.")] = None,
    out: Out = Path("db-agent-migrate-output"),
) -> None:
    """Read the source and the target, check the move is possible, and write migration-plan.json and .md."""
    from ..cli import parse_conn_spec

    try:
        src = parse_conn_spec(source, "DBAGENT_SOURCE", "--source")
        tgt = parse_conn_spec(target, "DBAGENT_TARGET", "--target")
        for label, c in (("--source", src), ("--target", tgt)):
            if c.trusted or c.driver != "pymssql" or not c.user:
                raise ValueError(f"{label}: this version supports SQL logins only (no Windows authentication, no odbc driver).")
            if not c.database:
                raise ValueError(f"{label}: database=NAME is required.")
        create = None
        if create_target:
            if not resource_group:
                raise ValueError("--create-target needs --resource-group.")
            if not free_limit and not service_objective:
                raise ValueError("--create-target needs --free-limit or --service-objective, so a billable database is never created by default.")
            create = {"resource_group": resource_group, "free_limit": free_limit, "service_objective": service_objective}
        _say(f"reading {src.database} on {src.server} (read-only)")
        inv = inventory_mod.collect(src, [src.database], False, QueryGuard(), _say)
        risks = [r.as_dict() for r in risks_mod.assess(inv, 16)]
        state = _target_state(tgt)
        if not state["reachable"]:
            raise ValueError(f"cannot read the target server: {state['detail']}")
        built = plan_mod.build_plan(inv=inv, risks=risks, source=_spec(src), target=_spec(tgt), method=method, create=create,
                                    target_state=state, tool_version=__version__)
    except (plan_mod.PlanError, DatabaseError, GuardError, ValueError) as exc:
        raise _fail(exc)
    out.mkdir(parents=True, exist_ok=True)
    (out / "migration-plan.json").write_text(json.dumps(built, indent=2, default=str), encoding="utf-8")
    md = plan_mod.render_markdown(built)
    (out / "migration-plan.md").write_text(md, encoding="utf-8")
    typer.echo(md)
    typer.echo(f"Wrote {out / 'migration-plan.json'} and {out / 'migration-plan.md'}. Nothing was changed on any server.")
    if built["preflight"]["verdict"] == "blocked":
        raise typer.Exit(2)


def _target_state(tgt: ConnectionConfig) -> dict[str, Any]:
    try:
        with SafeConnection(tgt.with_database("master"), QueryGuard()) as c:
            n = c.query("SELECT COUNT(*) AS n FROM sys.databases WHERE name = %s", (tgt.database,))[0]["n"]
        return {"reachable": True, "exists": bool(n), "detail": "read the target's database list"}
    except (DatabaseError, GuardError) as exc:
        return {"reachable": False, "exists": False, "detail": str(exc)[:300]}


@app.command()
def run(
    plan_file: Annotated[Path, typer.Option("--plan", help="migration-plan.json written by `migrate plan`.")],
    approve_plan: Annotated[Optional[str], typer.Option("--approve-plan", help="The plan's sha256 fingerprint. Without it you are asked to confirm.")] = None,
    keep_bacpac: Annotated[bool, typer.Option("--keep-bacpac", help="Keep the BACPAC file (it contains business data) after a verified run.")] = False,
    allow_stale: Annotated[bool, typer.Option("--allow-stale", help=f"Run a plan older than {STALE_HOURS} hours.")] = False,
    out: Optional[Path] = typer.Option(None, "--out", help="Folder for the log and the BACPAC. Default: the plan's folder."),
) -> None:
    """Execute an approved plan: create the target, export, import, verify. Stops at the first failure."""
    try:
        plan_doc = json.loads(plan_file.read_text(encoding="utf-8"))
        if not plan_mod.verify_seal(plan_doc):
            raise ValueError("the plan file was changed after it was created (fingerprint mismatch). Run `migrate plan` again.")
        age = datetime.now(timezone.utc) - datetime.fromisoformat(plan_doc["created_at"])
        if age.total_seconds() > STALE_HOURS * 3600 and not allow_stale:
            raise ValueError(f"the plan is {age.total_seconds() / 3600:.0f} hours old and the source may have changed. Plan again, or pass --allow-stale.")
        if plan_doc["preflight"]["verdict"] != "ready":
            raise ValueError("pre-flight found blockers. Fix them and plan again; nothing was run.")
        sha = plan_doc["sha256"]
        if approve_plan is not None:
            if approve_plan != sha:
                raise ValueError("--approve-plan does not match this plan's fingerprint. Nothing was run.")
        else:
            typer.echo(plan_mod.render_markdown(plan_doc))
            typed = typer.prompt(f"This will WRITE to {plan_doc['target']['server']}. Type the first 8 characters of the fingerprint to approve", default="", show_default=False)
            if typed.strip() != sha[:8]:
                raise ValueError("not approved. Nothing was run.")
        src = _cfg(plan_doc["source"], "DBAGENT_SOURCE", "the source SQL Server")
        tgt = _cfg(plan_doc["target"], "DBAGENT_TARGET", "the target SQL Server")
        folder = out or plan_file.parent
        log = runner.run_plan(plan_doc, src, tgt, folder, keep_bacpac=keep_bacpac, say=_say)
    except (ValueError, OSError, KeyError) as exc:
        raise _fail(exc)
    for s in log["steps"]:
        typer.echo(f"  {s['status']:<7} {s['id']:<18} {s['seconds']:>6}s  {s['detail'][:100]}")
    for w in log["warnings"]:
        typer.secho(f"Warning: {w}", fg=typer.colors.YELLOW)
    if log["status"] != "completed":
        if log.get("cleanup_hint"):
            typer.echo(log["cleanup_hint"])
        raise typer.Exit(1)
    typer.echo(f"Migration completed and verified. Log: {folder / 'migration-log.json'}")
