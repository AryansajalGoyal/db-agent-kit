# db-agent sqlserver migrate

Move one database from SQL Server (tested on 2016 SP3) to **Azure SQL Database**, in two commands. `plan` only
reads. `run` writes, and only the plan you approved.

```bash
export DBAGENT_SOURCE_PASSWORD=...  DBAGENT_TARGET_PASSWORD=...
db-agent sqlserver migrate plan \
  --source "server=sql2016.example.com,database=AdventureWorksLT2016,user=myadmin,trust_cert=yes" \
  --target "server=myserver.database.windows.net,database=AdventureWorksLT2016,user=myadmin" \
  --create-target --resource-group my-rg --free-limit

# read migration-plan.md, then approve by fingerprint:
db-agent sqlserver migrate run --plan db-agent-migrate-output/migration-plan.json --approve-plan <sha256>
```

Without `--approve-plan`, `run` prints the plan and asks you to type the first 8 characters of the fingerprint.

## What `plan` does (reads only)

Reads the source with the same guarded, read-only connection as `inventory`, applies the Azure SQL Database
rules from [risk-rules.md](risk-rules.md) to the one database, and checks the target server can be read and that
the new database name is free. It writes `migration-plan.json` and `migration-plan.md`. A plan with blockers
(CLR, Service Broker, FILESTREAM, cross-database or linked-server references) exits with code 2 and cannot be run.

It also lists the SQL Server Agent jobs that run against the database, because they are possible writers.

## What `run` does (writes)

| Step | Writes |
|---|---|
| `create-target-db` | `az sql db create` for the new database. With `--free-limit`: the free offer, AutoPause, the same sizing as an existing free database. Without it you must give `--service-objective`, so a billable database is never created by default. |
| `baseline` | Nothing. Counts rows in every source table. |
| `export` | One local BACPAC file, mode 600. It contains business data. The source is not changed. |
| `post-export-check` | Nothing. Counts again; warns if the source changed during the export. |
| `import` | `sqlpackage` loads schema and data into the new database. |
| `verify` | Nothing. Compares exact row counts per table, object counts by type, database users, compatibility level and collation. |

It stops at the first failure and never deletes anything on the target. If the target database was created, the log
says how to remove it. The BACPAC is deleted after a verified run unless you pass `--keep-bacpac`. The full
`sqlpackage` and `az` output (with passwords removed) is saved next to `migration-log.json`.

`run` refuses a plan that was edited after it was written (fingerprint mismatch), one older than 24 hours
(`--allow-stale`), and one with blockers.

## How it is kept safe

- Every SQL statement the tool sends (baseline, drift check, verification, target checks) goes through the existing query guard. The write path is `az` and `sqlpackage` subprocesses built from the plan, not T-SQL from this tool. A test checks that only `runner.py` starts a process.
- Passwords are never stored in a plan or a log and are scrubbed from tool output. **They are on the `sqlpackage` command line for the length of the run**, so other users on the same machine can see them in `ps`. `sqlpackage` has no password-file option. Run it on a machine you control.

## What a BACPAC does not carry

Server logins, SQL Server Agent jobs, linked servers, credentials, Database Mail, and anything outside the database.
A BACPAC is also not one transaction: stop writers before `run`. The run compares counts before and after the export
and reports a changed source, but it cannot stop the writers for you.

## Tested

| What | Result |
|---|---|
| 23 unit tests (`tests/test_migrate.py`), fake process executor and fake connections | pass |
| Live, 2026-11-24: SQL Server 2016 SP3 (Azure Windows VM) `AdventureWorksLT2016` (12 tables, 36,780 rows) to a new free-offer Azure SQL Database, canadacentral, from a Mac | 6 of 6 steps ok in about 2 minutes; 12 of 12 tables match row for row; object counts, users and collation match |

## Not tested, or not done

- Windows authentication, Entra ID and the odbc driver: `migrate` accepts SQL logins only.
- Targets other than Azure SQL Database (Managed Instance, SQL Server, Azure SQL VM), and methods other than BACPAC (`.bak` restore, log shipping).
- Databases larger than a few hundred MB. BACPAC time and memory grow with size, and the file passes through the machine running the tool.
- The full AdventureWorks2016 database, and any database with users mapped to server logins. `verify` lists the users that are missing on the target, but the behavior for login-mapped users was not exercised.
- Compatibility level is **not** changed: the target stayed at 110. Raising it is a separate decision that changes query behavior.
- Row counts and object counts are compared. Column values are not (no checksums).
- `sqlpackage` 170 needs .NET 10. On a machine that only has a newer major runtime it ran with `DOTNET_ROLL_FORWARD=Major`, which is not a supported configuration.
- A second free database on the same subscription was accepted by Azure in this run. The free offer has its own limits; Azure decides.
- `sqlpackage` printed `The object [log] exists in the target, but it will not be dropped` during import. The import and the comparison still passed. The cause was not investigated.
