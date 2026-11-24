"""Run an approved migration plan. This is the only module in the package that starts a process.

Reads (baseline, drift check, verification) go through SafeConnection, so the query guard still checks them.
Writes are `az` and `sqlpackage` subprocesses built from the plan, never T-SQL sent by this tool. The runner
stops at the first failure, records what happened, and never deletes anything on the target by itself.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ..db import ConnectionConfig, DatabaseError, SafeConnection, scrub
from ..guard import QueryGuard
from . import plan as plan_mod
from . import verify

Executor = Callable[[list[str], dict[str, str], int], tuple[int, str]]
TAIL = 3000


class StepFailed(Exception):
    pass


def default_executor(argv: list[str], env: dict[str, str], timeout: int) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=timeout)  # no shell
    except FileNotFoundError:
        return 127, f"{argv[0]}: command not found"
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout} s"
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def _cleanup_hint(plan: dict[str, Any], created: bool) -> str:
    t = plan["target"]
    if not created:
        return ""
    rg = (plan.get("create") or {}).get("resource_group", "<resource-group>")
    return (f"Database {t['database']} was created on {t['server']} and may be empty or partly loaded. Nothing was removed. "
            f"To remove it: az sql db delete --resource-group {rg} --server {t['server'].split('.')[0]} --name {t['database']}")


def run_plan(
    plan: dict[str, Any], src_cfg: ConnectionConfig, tgt_cfg: ConnectionConfig, out: Path, *,
    keep_bacpac: bool = False, executor: Executor = default_executor, say: Callable[[str], None] = lambda _m: None,
    step_timeout: int = 7200,
) -> dict[str, Any]:
    """Execute the plan's steps in order. Returns the log (also written to out/migration-log.json)."""
    if not plan_mod.verify_seal(plan):
        raise ValueError("the plan file was changed after it was created (fingerprint mismatch). Create a new plan.")
    secrets = [src_cfg.password, tgt_cfg.password]
    src_db, tgt_db = plan["source"]["database"], plan["target"]["database"]
    art = out / "artifacts"
    art.mkdir(parents=True, exist_ok=True)
    os.chmod(art, 0o700)
    bacpac = art / f"{src_db}.bacpac"
    guard = QueryGuard()
    log: dict[str, Any] = {"plan_sha256": plan["sha256"], "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                           "status": "running", "steps": [], "warnings": []}
    ctx: dict[str, Any] = {"created": False}
    log_path = out / "migration-log.json"

    def run_cmd(argv: list[str], log_name: str) -> str:
        """Run a command. Its full output (passwords removed) goes to out/<log_name>; returns one summary line."""
        code, text = executor(argv, dict(os.environ), step_timeout)
        text = scrub(text, secrets).strip()
        (out / log_name).write_text(text + "\n", encoding="utf-8")
        if code != 0:
            raise StepFailed(f"{argv[0]} exited with code {code}. Last output: {text[-TAIL:]}")
        lines = [ln for ln in text.splitlines() if ln.strip()]
        done = next((ln for ln in reversed(lines) if ln.lower().startswith("successfully")), lines[-1] if lines else "")
        return f"{done} (full output: {log_name})" if lines else ""

    def conn(cfg: ConnectionConfig, database: str) -> SafeConnection:
        return SafeConnection(cfg.with_database(database), guard)

    # ---- handlers -----------------------------------------------------------------------------------
    def create_target_db(step: dict[str, Any]) -> str:
        try:
            with conn(tgt_cfg, "master") as c:
                exists = c.query("SELECT COUNT(*) AS n FROM sys.databases WHERE name = %s", (tgt_db,))[0]["n"]
        except DatabaseError as exc:
            raise StepFailed(f"cannot read the target server: {exc}") from None
        if exists:
            raise StepFailed(f"database {tgt_db!r} already exists on the target. Nothing was changed. Choose a new name and plan again.")
        run_cmd(plan_mod.az_create_argv(plan["target"], plan["create"]), "az-create.log")
        ctx["created"] = True
        return f"created {tgt_db}"

    def baseline(step: dict[str, Any]) -> str:
        with conn(src_cfg, src_db) as c:
            ctx["before"] = verify.snapshot(c)
        return f"{len(ctx['before']['row_counts'])} tables, {verify.total_rows(ctx['before']):,} rows"

    def export(step: dict[str, Any]) -> str:
        if bacpac.exists():
            raise StepFailed(f"{bacpac} already exists. Move or delete it; the tool will not overwrite a data file.")
        run_cmd(plan_mod.export_argv(plan["source"], str(bacpac), src_cfg.password or ""), "sqlpackage-export.log")
        if not bacpac.exists():
            raise StepFailed("sqlpackage reported success but no BACPAC file was written")
        os.chmod(bacpac, 0o600)
        return f"{bacpac.name}, {bacpac.stat().st_size / 1_048_576:.1f} MB"

    def post_export(step: dict[str, Any]) -> str:
        with conn(src_cfg, src_db) as c:
            ctx["after"] = verify.snapshot(c)
        drift = verify.source_drift(ctx["before"], ctx["after"])
        ctx["drift"] = drift
        if drift:
            log["warnings"].append("The source changed while the export ran: " + "; ".join(drift[:10]) +
                                   ". The BACPAC may not match either count. Stop the writers and run the migration again for a clean result.")
            return f"source changed during export in {len(drift)} table(s)"
        return "source unchanged during export"

    def import_(step: dict[str, Any]) -> str:
        return run_cmd(plan_mod.import_argv(plan["target"], str(bacpac), tgt_cfg.password or ""), "sqlpackage-import.log") or "imported"

    def verify_(step: dict[str, Any]) -> str:
        with conn(tgt_cfg, tgt_db) as c:
            tgt = verify.snapshot(c)
        res = verify.compare(ctx["before"], tgt)
        res["source_drift"] = ctx.get("drift", [])
        log["verification"] = res
        if res["status"] != "pass":
            raise StepFailed(f"{res['tables_not_matching']} of {res['tables_compared']} table(s) differ, "
                             f"{len(res['object_count_differences'])} object type count(s) differ. See migration-log.json.")
        return (f"{res['tables_compared']} tables match, object counts match, "
                f"users missing in target: {len(res['users_missing_in_target'])}")

    handlers: dict[str, Callable[[dict[str, Any]], str]] = {
        "create-target-db": create_target_db, "baseline": baseline, "export": export,
        "post-export-check": post_export, "import": import_, "verify": verify_,
    }

    # ---- loop ---------------------------------------------------------------------------------------
    try:
        for step in plan["steps"]:
            say(f"[{step['id']}] {step['title']}")
            t0 = time.monotonic()
            rec: dict[str, Any] = {"id": step["id"], "title": step["title"], "kind": step["kind"]}
            try:
                rec["detail"] = handlers[step["id"]](step)
                rec["status"] = "ok"
            except StepFailed as exc:
                rec.update(status="failed", detail=scrub(str(exc), secrets))
                log["status"] = "failed"
                hint = _cleanup_hint(plan, ctx["created"])
                if hint:
                    log["cleanup_hint"] = hint
            except (DatabaseError, KeyError) as exc:
                rec.update(status="failed", detail=scrub(f"{type(exc).__name__}: {exc}", secrets))
                log["status"] = "failed"
                hint = _cleanup_hint(plan, ctx["created"])
                if hint:
                    log["cleanup_hint"] = hint
            rec["seconds"] = round(time.monotonic() - t0, 1)
            log["steps"].append(rec)
            say(f"    {rec['status']}: {rec['detail'][:200]}")
            _write_log(log_path, log)
            if rec["status"] == "failed":
                return log
        log["status"] = "completed"
        if not keep_bacpac and bacpac.exists():
            bacpac.unlink()
            log["bacpac"] = "deleted after a verified run (--keep-bacpac keeps it)"
        elif bacpac.exists():
            log["bacpac"] = str(bacpac)
        return log
    finally:
        log["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        _write_log(log_path, log)


def _write_log(path: Path, log: dict[str, Any]) -> None:
    path.write_text(json.dumps(log, indent=2, default=str), encoding="utf-8")
