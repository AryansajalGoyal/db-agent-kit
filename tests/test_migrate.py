"""migrate: plan, verify and runner, with no server and no real process."""
import copy
import json
import re
from pathlib import Path

import pytest

from db_agent.engines.sqlserver import db as db_mod
from db_agent.engines.sqlserver.db import ConnectionConfig
from db_agent.engines.sqlserver.migrate import plan as P, runner as R, verify as V

SRC = {"server": "10.0.0.5", "port": 1433, "database": "Sales", "user": "src_admin", "encrypt": True, "trust_server_certificate": True}
TGT = {"server": "tgt.database.windows.net", "port": 1433, "database": "SalesNew", "user": "tgt_admin", "encrypt": True, "trust_server_certificate": False}
CREATE = {"resource_group": "rg1", "free_limit": True, "service_objective": None}
SRC_PW, TGT_PW = "S3cret-src!", "S3cret-tgt!"


def inv(db="Sales"):
    return {"server": {"product_version": "13.0.7050.2", "edition": "Developer", "engine_edition": 3},
            "databases": [{"name": db, "compatibility_level": 110, "recovery_model_desc": "SIMPLE", "data_mb": 21, "log_mb": 8, "state_desc": "ONLINE"}],
            "objects": {db: {"tables": [{"rows": 10}, {"rows": 5}]}},
            "agent_jobs": [{"job_name": "Feed", "database_name": db}], "linked_servers": []}


def risk(id_, sev="medium", azure=False, db="Sales"):
    return {"id": id_, "severity": sev, "title": id_, "database": db, "object": "o", "detail": "d", "doc": "u", "azure_sql_database_only": azure}


def make_plan(risks=None, state=None, create=CREATE, **kw):
    return P.build_plan(inv=inv(), risks=risks or [], source=SRC, target=TGT, method="bacpac", create=create,
                        target_state=state or {"reachable": True, "exists": False}, tool_version="test", **kw)


# ---- plan -----------------------------------------------------------------------------------------
def test_plan_is_sealed_and_ready():
    plan = make_plan([risk("dep-x", "high")])
    assert plan["preflight"]["verdict"] == "ready"
    assert plan["preflight"]["agent_jobs_using_database"] == ["Feed"]
    assert [s["id"] for s in plan["steps"]] == ["create-target-db", "baseline", "export", "post-export-check", "import", "verify"]
    assert P.verify_seal(plan)


def test_azure_only_risk_blocks():
    plan = make_plan([risk("clr", azure=True)])
    assert plan["preflight"]["verdict"] == "blocked"
    assert plan["preflight"]["blockers"][0]["id"] == "clr"


def test_risks_of_other_databases_do_not_block():
    assert make_plan([risk("clr", azure=True, db="Other")])["preflight"]["verdict"] == "ready"


def test_editing_a_plan_breaks_the_seal():
    plan = make_plan()
    plan["steps"][0]["command"].append("--evil")
    assert not P.verify_seal(plan)


def test_no_password_anywhere_in_plan_or_markdown():
    plan = make_plan()
    text = json.dumps(plan) + P.render_markdown(plan)
    assert "/SourcePassword:***" in text and "/TargetPassword:***" in text
    assert not re.search(r"Password:(?!\*\*\*)", text)


@pytest.mark.parametrize("kwargs,msg", [
    (dict(state={"reachable": True, "exists": True}), "already exists"),
    (dict(create=None), "--create-target"),
])
def test_plan_refusals(kwargs, msg):
    with pytest.raises(P.PlanError, match=msg):
        make_plan(**kwargs)


def test_only_azure_sql_database_targets_and_bacpac():
    with pytest.raises(P.PlanError, match="Azure SQL Database only"):
        P.build_plan(inv=inv(), risks=[], source=SRC, target={**TGT, "server": "other-host"}, method="bacpac", create=CREATE,
                     target_state={"reachable": True, "exists": False}, tool_version="t")
    with pytest.raises(P.PlanError, match="not implemented"):
        P.build_plan(inv=inv(), risks=[], source=SRC, target=TGT, method="bak", create=CREATE,
                     target_state={"reachable": True, "exists": False}, tool_version="t")


def test_unknown_source_database():
    with pytest.raises(P.PlanError, match="not found"):
        P.build_plan(inv=inv("Other"), risks=[], source=SRC, target=TGT, method="bacpac", create=CREATE,
                     target_state={"reachable": True, "exists": False}, tool_version="t")


def test_billable_create_uses_the_given_objective_and_free_uses_the_free_flag():
    free = P.az_create_argv(TGT, CREATE)
    paid = P.az_create_argv(TGT, {"resource_group": "rg1", "free_limit": False, "service_objective": "GP_S_Gen5_1"})
    assert "--use-free-limit" in free and "--service-objective" not in free
    assert "--use-free-limit" not in paid and paid[paid.index("--service-objective") + 1] == "GP_S_Gen5_1"


# ---- verify ---------------------------------------------------------------------------------------
def snap(counts, objs=None, users=None, compat=110):
    return {"row_counts": counts, "object_counts": objs or {"U": len(counts)}, "users": users or [], "compatibility_level": compat, "collation": "c"}


def test_compare_pass_and_each_failure_kind():
    base = snap({"dbo.A": 3, "dbo.B": 4})
    assert V.compare(base, copy.deepcopy(base))["status"] == "pass"
    r = V.compare(base, snap({"dbo.A": 3, "dbo.B": 5}))
    assert r["status"] == "fail" and r["tables"][1]["status"] == "mismatch"
    assert V.compare(base, snap({"dbo.A": 3}))["tables"][1]["status"] == "missing_in_target"
    assert V.compare(base, snap({"dbo.A": 3, "dbo.B": 4, "dbo.C": 1}))["tables"][2]["status"] == "extra_in_target"
    assert V.compare(base, snap({"dbo.A": 3, "dbo.B": 4}, objs={"U": 2, "V": 1}))["object_count_differences"] == [{"type": "V", "source": 0, "target": 1}]
    assert V.compare(snap({}, users=["u (SQL_USER)"]), snap({}))["users_missing_in_target"] == ["u (SQL_USER)"]


def test_source_drift():
    assert V.source_drift(snap({"a": 1}), snap({"a": 1})) == []
    assert V.source_drift(snap({"a": 1}), snap({"a": 2})) == ["a: 1 -> 2"]


def test_table_names_are_bracket_quoted():
    assert V._q("we]ird") == "[we]]ird]"


# ---- runner ---------------------------------------------------------------------------------------
class FakeConn:
    exists = False

    def __init__(self, cfg, guard=None):
        self.cfg = cfg

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def query(self, sql, params=None):
        return [{"n": 1 if FakeConn.exists else 0}]


@pytest.fixture()
def world(monkeypatch, tmp_path):
    state = {"calls": [], "src_snaps": [snap({"dbo.A": 3}), snap({"dbo.A": 3})], "tgt": snap({"dbo.A": 3}), "fail_on": None}
    FakeConn.exists = False
    monkeypatch.setattr(R, "SafeConnection", FakeConn)

    def fake_snapshot(conn):
        return state["tgt"] if conn.cfg.database == "SalesNew" else state["src_snaps"].pop(0)

    monkeypatch.setattr(R.verify, "snapshot", fake_snapshot)

    def executor(argv, env, timeout):
        state["calls"].append(argv)
        action = next((a for a in argv if a.startswith("/Action:")), argv[0])
        if state["fail_on"] == action:
            return 1, f"boom, login failed for {SRC_PW} and {TGT_PW}"
        if action == "/Action:Export":
            Path(next(a for a in argv if a.startswith("/TargetFile:")).split(":", 1)[1]).write_bytes(b"BACPAC")
        return 0, f"Successfully did {action} with {SRC_PW}"

    state["executor"] = executor
    state["src"] = ConnectionConfig(server="10.0.0.5", database="Sales", user="src_admin", password=SRC_PW)
    state["tgt_cfg"] = ConnectionConfig(server="tgt.database.windows.net", database="SalesNew", user="tgt_admin", password=TGT_PW)
    state["out"] = tmp_path
    return state


def go(world, plan=None, **kw):
    return R.run_plan(plan or make_plan(), world["src"], world["tgt_cfg"], world["out"], executor=world["executor"], **kw)


def test_happy_path_runs_all_steps_deletes_bacpac_and_scrubs_passwords(world):
    log = go(world)
    assert log["status"] == "completed" and [s["status"] for s in log["steps"]] == ["ok"] * 6
    assert not (world["out"] / "artifacts" / "Sales.bacpac").exists()
    assert [c[0] for c in world["calls"]] == ["az", "sqlpackage", "sqlpackage"]
    assert world["calls"][1][1] == "/Action:Export" and world["calls"][2][1] == "/Action:Import"
    for f in world["out"].glob("*"):
        if f.is_file():
            assert SRC_PW not in f.read_text() and TGT_PW not in f.read_text(), f.name


def test_keep_bacpac_keeps_it_with_private_mode(world):
    go(world, keep_bacpac=True)
    f = world["out"] / "artifacts" / "Sales.bacpac"
    assert f.exists() and f.stat().st_mode & 0o777 == 0o600


def test_tampered_plan_is_refused_before_anything_runs(world):
    plan = make_plan()
    plan["target"]["database"] = "master"
    with pytest.raises(ValueError, match="fingerprint"):
        go(world, plan)
    assert world["calls"] == []


def test_existing_target_database_stops_before_az_is_called(world):
    FakeConn.exists = True
    log = go(world)
    assert log["status"] == "failed" and log["steps"][0]["status"] == "failed" and world["calls"] == []
    assert "cleanup_hint" not in log


def test_import_failure_stops_keeps_bacpac_and_says_how_to_clean_up(world):
    world["fail_on"] = "/Action:Import"
    log = go(world)
    assert log["status"] == "failed" and log["steps"][-1]["id"] == "import"
    assert (world["out"] / "artifacts" / "Sales.bacpac").exists()
    assert "az sql db delete" in log["cleanup_hint"] and "SalesNew" in log["cleanup_hint"]
    assert SRC_PW not in json.dumps(log) and TGT_PW not in json.dumps(log)


def test_source_drift_is_reported_and_verification_still_compares_to_the_baseline(world):
    world["src_snaps"] = [snap({"dbo.A": 3}), snap({"dbo.A": 4})]
    log = go(world)
    assert log["status"] == "completed" and "dbo.A: 3 -> 4" in log["warnings"][0]


def test_verification_failure_fails_the_run(world):
    world["tgt"] = snap({"dbo.A": 2})
    log = go(world)
    assert log["status"] == "failed" and log["steps"][-1]["id"] == "verify" and log["verification"]["tables_not_matching"] == 1


def test_existing_bacpac_is_never_overwritten(world):
    (world["out"] / "artifacts").mkdir()
    (world["out"] / "artifacts" / "Sales.bacpac").write_bytes(b"old")
    log = go(world)
    assert log["steps"][-1]["id"] == "export" and log["steps"][-1]["status"] == "failed"
    assert (world["out"] / "artifacts" / "Sales.bacpac").read_bytes() == b"old"


# ---- architecture ---------------------------------------------------------------------------------
PKG = Path(__file__).resolve().parents[1] / "src" / "db_agent" / "engines" / "sqlserver" / "migrate"


def test_only_runner_starts_processes_and_nothing_here_imports_a_driver():
    for p in PKG.glob("*.py"):
        text = p.read_text()
        assert not re.search(r"^\s*(import|from)\s+(pymssql|pyodbc)\b", text, re.MULTILINE), p.name
        if p.name != "runner.py":
            assert not re.search(r"^\s*(import|from)\s+(subprocess|os\s*$)|os\.system|Popen", text, re.MULTILINE), p.name


def test_runner_never_sends_sql_that_the_guard_would_refuse():
    text = (PKG / "runner.py").read_text() + (PKG / "verify.py").read_text()
    assert not re.search(r"\.conn\b|\._conn\b|\.cursor\(|\.execute\(", text)
    assert db_mod.SafeConnection  # every read goes through SafeConnection.query, which calls the guard first
