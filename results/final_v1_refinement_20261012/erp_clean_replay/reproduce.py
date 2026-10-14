"""Reproduce the ERPNext regression in isolated Docker services.

Requires Docker, Git, Python 3 and public network access. Creates only the
specified fresh working directory and uniquely named Docker services. All
database passwords below are public test-fixture constants; no real account
credentials are used. No ports are exposed. No application source is patched.

Example:
  python3 reproduce.py --workdir /tmp/access-erp-repro --output /tmp/access-erp-evidence
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import time

PINS = {
    "frappe": "ab2ea34e2ca327b2a2c647abe0ac284be088a54f",
    "before": "c2d378a8fd7c8e4b1f5f05cf8cf0cd1c505557be",
    "after": "ff78778b7cde837bcd3128582280f34582522e5f",
    "bench_image": "frappe/bench@sha256:8c500a20cb1933d0427c1568dcf3c8c37021c0e07be1ac268539fd7fe14ef557",
    "database_image": "mariadb@sha256:6422478cb8e159f080fb1d8ccf65101e26fe51385787fde7d16c3b165a331f15",
    "redis_image": "redis@sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499",
}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--workdir", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--keep-containers", action="store_true")
    args = p.parse_args()
    work = args.workdir.resolve()
    output = args.output.resolve()
    if work.exists() or output.exists():
        raise SystemExit("Use fresh workdir and output paths; existing results are never overwritten.")
    work.mkdir(parents=True)
    output.mkdir(parents=True)
    (output / "logs").mkdir()
    shutil.copy2(Path(__file__).with_name("run_upstream_traced.py"), output)
    shutil.copy2(Path(__file__).with_name("summarize.py"), output)
    shutil.copy2(Path(__file__).with_name("python_requirements_lock.txt"), output)
    shutil.copy2(__file__, output)
    project = "access-erp-" + hashlib.sha256(str(work).encode()).hexdigest()[:12]
    app, db, redis = [project + "-" + suffix for suffix in ("app", "db", "redis")]
    commands = []

    def run(command, label, expected=0, cwd=None):
        started = time.time()
        with (output / "logs" / (label + ".log")).open("wb") as handle:
            result = subprocess.run(command, cwd=cwd, stdout=handle, stderr=subprocess.STDOUT)
        commands.append({"command": command, "label": label, "exit_code": result.returncode,
                         "expected_exit_code": expected, "elapsed_s": time.time() - started})
        (output / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        if result.returncode != expected:
            raise RuntimeError(f"{label}: exit {result.returncode}; see its log")

    def exec_app(command, label, expected=0, cwd="/workspace/bench"):
        run(["docker", "exec", "-w", cwd, app, "bash", "-lc", command], label, expected)

    for repo, sha in (("frappe", PINS["frappe"]), ("erpnext", PINS["after"])):
        folder = work / repo
        run(["git", "init", str(folder)], "git_init_" + repo)
        run(["git", "-C", str(folder), "remote", "add", "origin", f"https://github.com/frappe/{repo}.git"], "git_remote_" + repo)
        run(["git", "-C", str(folder), "fetch", "--depth", "2", "origin", sha], "git_fetch_" + repo)
        run(["git", "-C", str(folder), "checkout", "-b", "access-pinned", sha], "git_checkout_" + repo)
    for key in ("bench_image", "database_image", "redis_image"):
        run(["docker", "pull", PINS[key]], "pull_" + key)
    run(["docker", "network", "create", project], "network")
    try:
        run(["docker", "run", "-d", "--name", db, "--network", project, "--network-alias", "db",
             "--cpus", "2", "--memory", "4g", "-e", "MARIADB_ROOT_PASSWORD=access-local-test",
             "-e", "MARIADB_ROOT_HOST=%", PINS["database_image"],
             "--character-set-server=utf8mb4", "--collation-server=utf8mb4_unicode_ci",
             "--skip-character-set-client-handshake", "--innodb-flush-log-at-trx-commit=2", "--sync-binlog=0"], "database")
        run(["docker", "run", "-d", "--name", redis, "--network", project, "--network-alias", "redis",
             "--cpus", "1", "--memory", "1g", PINS["redis_image"]], "redis")
        run(["docker", "run", "-d", "--name", app, "--network", project,
             "--cpus", "3", "--memory", "12g", "-v", f"{work}:/workspace", "-v", f"{output}:/evidence",
             "-w", "/workspace", PINS["bench_image"], "sleep", "infinity"], "app")
        exec_app("bench init --frappe-path file:///workspace/frappe --frappe-branch access-pinned --skip-assets --skip-redis-config-generation --no-backups bench", "bench_init", cwd="/workspace")
        exec_app("bench set-config -g db_host db && bench set-config -g redis_cache redis://redis:6379/0 && bench set-config -g redis_queue redis://redis:6379/1 && bench set-config -g redis_socketio redis://redis:6379/2", "config")
        exec_app("bench get-app --skip-assets --branch access-pinned file:///workspace/erpnext && git -C apps/erpnext restore banking/yarn.lock && bench pip install '-e' 'apps/frappe[test]'", "install_apps")
        exec_app("bench pip install -r /evidence/python_requirements_lock.txt", "lock_runtime_dependencies")
        exec_app("bench new-site test_site --db-host db --db-root-username root --db-root-password access-local-test --admin-password access-local-admin --mariadb-user-host-login-scope=% --install-app erpnext && bench --site test_site set-config allow_tests true", "site_install")
        exec_app("env/bin/python -m pip freeze --all > /evidence/python_freeze.txt", "freeze")
        database_name = json.loads((work / "bench/sites/test_site/site_config.json").read_text())["db_name"]
        assert re.fullmatch(r"[A-Za-z0-9_]+", database_name)
        snapshot = work / "baseline.sql"
        with snapshot.open("wb") as handle:
            subprocess.run(["docker", "exec", db, "mariadb-dump", "-uroot", "-paccess-local-test", "--single-transaction", "--databases", database_name], stdout=handle, check=True)
        (output / "database_snapshot.json").write_text(json.dumps({"sha256": hashlib.sha256(snapshot.read_bytes()).hexdigest(), "purpose": "Same initialized test database restored before the second source-version run; dump kept only in external workdir."}, indent=2) + "\n")
        source_files = []
        for label, expected in (("before", 1), ("after", 0)):
            if label == "after":
                run(["docker", "exec", db, "mariadb", "-uroot", "-paccess-local-test", "-e", f"DROP DATABASE `{database_name}`"], "reset_test_database")
                with snapshot.open("rb") as handle:
                    subprocess.run(["docker", "exec", "-i", db, "mariadb", "-uroot", "-paccess-local-test"], stdin=handle, check=True)
                run(["docker", "exec", redis, "redis-cli", "FLUSHALL"], "flush_isolated_cache")
            sha = PINS[label]
            exec_app(f"git -C apps/erpnext fetch --depth 1 https://github.com/frappe/erpnext.git {sha} && git -C apps/erpnext checkout --detach {sha}", "checkout_" + label)
            repo = work / "bench/apps/erpnext"
            assert subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip() == sha
            assert not subprocess.check_output(["git", "-C", str(repo), "status", "--porcelain"], text=True).strip()
            for path in ("erpnext/controllers/buying_controller.py", "erpnext/stock/doctype/purchase_receipt/purchase_receipt.py", "erpnext/accounts/doctype/purchase_invoice/purchase_invoice.py", "erpnext/stock/doctype/purchase_receipt/test_purchase_receipt.py", "pyproject.toml", "license.txt", "erpnext/controllers/stock_controller.py"):
                data = (repo / path).read_bytes()
                source_files.append({"version": label, "commit": sha, "path": path, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "url": f"https://github.com/frappe/erpnext/blob/{sha}/{path}"})
            exec_app(f"/workspace/bench/env/bin/python /evidence/run_upstream_traced.py --label {label} --out /evidence", "test_" + label, expected, cwd="/workspace/bench/sites")
        tests = [row for row in source_files if row["path"].endswith("test_purchase_receipt.py")]
        assert tests[0]["sha256"] == tests[1]["sha256"]
        (output / "source_manifest.json").write_text(json.dumps({"erpnext_files": source_files, "upstream_regression_identical_between_versions": True}, indent=2) + "\n")
        (output / "pins.json").write_text(json.dumps(PINS, indent=2) + "\n")
        run(["python3", str(output / "summarize.py"), "--output", str(output)], "validate_results")
    finally:
        if not args.keep_containers:
            for name in (app, db, redis):
                subprocess.run(["docker", "rm", "-f", "-v", name], check=False)
            subprocess.run(["docker", "network", "rm", project], check=False)


if __name__ == "__main__":
    main()
