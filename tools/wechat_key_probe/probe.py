#!/usr/bin/env python3
"""Independent, explicit WeChat diagnostic CLI; never imports the bot service."""
from __future__ import annotations

import argparse
import json
import os
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from pathlib import Path

from core import (BUILD_ID, PREFIX, ProbeError, candidates, resolve, tracer_pid,
                  verify_sqlcipher_page_hmac)

HERE = Path(__file__).resolve().parent


def command(argv, **kwargs):
    return subprocess.check_output(argv, stderr=subprocess.DEVNULL, **kwargs)


def docker(*args, **kwargs):
    return command(["docker", *args], **kwargs)


def container_info(container):
    return json.loads(docker("inspect", container))[0]


def pids(container):
    return [int(line.split()[0]) for line in docker("top", container, "-eo", "pid").decode().splitlines()[1:]]


def db_fds(pid):
    result = set()
    for fd in Path(f"/proc/{pid}/fd").iterdir():
        try:
            name = os.readlink(fd)
            if name.endswith(".db") and "/db_storage/" in name:
                result.add(name)
        except OSError:
            pass
    return result


def target(container):
    matches = []
    for pid in pids(container):
        try:
            if os.readlink(f"/proc/{pid}/exe").endswith("/opt/wechat/wechat"):
                matches.append((len(db_fds(pid)), pid))
        except OSError:
            pass
    matches.sort(reverse=True)
    if not matches or (len(matches) > 1 and matches[0][0] == matches[1][0]):
        raise ProbeError("no unambiguous database-owning WeChat process")
    return matches[0][1]


def inventory(pid, root):
    result = []
    for index, name in enumerate(sorted(db_fds(pid))):
        path = root / name.lstrip("/")
        with path.open("rb") as f:
            page = f.read(4096)
        if len(page) == 4096 and not page.startswith(b"SQLite format 3\0"):
            result.append({"id": f"db-{index + 1:02d}", "name": Path(name).name,
                           "path": path, "container_path": name, "page": page,
                           "size": path.stat().st_size})
    return result


def run_gdb(config, consume, timeout, login_timeout=600):
    env = dict(os.environ, WECHAT_PROBE_CONFIG=json.dumps(config), PYTHONDONTWRITEBYTECODE="1")
    argv = ["gdb", "-q", "-nx", "--batch", "-iex", "set auto-load off",
            "-ex", "source " + str(HERE / "gdb_worker.py")]
    proc = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            start_new_session=True, bufsize=0)
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)
    pending = b""
    deadline = time.monotonic() + (login_timeout if config.get("startup") else timeout) + 20
    ready = False
    business_seen = False
    interrupt_at = None
    attached_pid = config.get("pid")
    events = Counter()

    def interrupt():
        if attached_pid and tracer_pid(attached_pid) == proc.pid:
            # A signal to the traced inferior reliably wakes GDB even while its
            # Python interpreter is blocked in execute('continue'). GDB consumes
            # SIGINT (nopass), so the application never receives it on detach.
            os.kill(attached_pid, signal.SIGINT)
        else:
            proc.send_signal(signal.SIGINT)

    try:
        while selector.get_map():
            now = time.monotonic()
            if now >= deadline and interrupt_at is None:
                interrupt()
                interrupt_at = now
            if interrupt_at is not None and now - interrupt_at > 10 and proc.poll() is None:
                # GDB handles SIGTERM by restoring breakpoints and detaching.
                proc.terminate()
                interrupt_at = now
            for key, _ in selector.select(0.2):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                pending += chunk
                while b"\n" in pending:
                    raw, pending = pending.split(b"\n", 1)
                    line = raw.decode("utf-8", "replace")
                    if not line.startswith(PREFIX):
                        continue  # GDB diagnostics may contain paths: never forward them.
                    event = json.loads(line[len(PREFIX):])
                    kind = event["kind"]
                    events[kind] += 1
                    if kind == "attached":
                        attached_pid = event["pid"]
                    if kind == "ready":
                        ready = True
                        print("PROBE_READY: trigger database reads in WeChat", flush=True)
                        deadline = time.monotonic() + (login_timeout if config.get("startup") else timeout)
                    matched = consume(event)
                    if config.get("startup") and matched and not business_seen:
                        business_seen = True
                        deadline = time.monotonic() + timeout
            if proc.poll() is not None and not selector.get_map():
                break
    except BaseException:
        if proc.poll() is None:
            interrupt()
        raise
    finally:
        selector.close()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.terminate()
            proc.wait(timeout=15)
        proc.stdout.close()
    tracer = tracer_pid(attached_pid) if attached_pid else None
    if tracer not in (0, None):
        raise ProbeError("debugger did not detach; manual recovery required")
    return {"events": dict(events), "ready": ready, "gdb_exit": proc.returncode,
            "tracer_pid_after": tracer, "target_pid": attached_pid}


def stable_snapshot(container, database, destination):
    """Stop only owners of writable DB/WAL FDs, with a 5-second resume watchdog."""
    names = {database["container_path"], database["container_path"] + "-wal"}
    stopped = []
    resumed = threading.Event()
    expired = threading.Event()

    def resume():
        for pid, handle in stopped:
            try:
                signal.pidfd_send_signal(handle, signal.SIGCONT)
            except ProcessLookupError:
                pass
        resumed.set()

    def watchdog():
        if not resumed.wait(5):
            expired.set()
            resume()

    try:
        owners = set()
        for pid in pids(container):
            try:
                for fd in Path(f"/proc/{pid}/fd").iterdir():
                    try:
                        if os.readlink(fd) in names:
                            info = Path(f"/proc/{pid}/fdinfo/{fd.name}").read_text()
                            flags = next(int(line.split()[1], 8) for line in info.splitlines() if line.startswith("flags:"))
                            if flags & 3:
                                owners.add(pid)
                    except (OSError, StopIteration):
                        continue
            except FileNotFoundError:
                continue
        for pid in owners:
            status = Path(f"/proc/{pid}/status").read_text()
            if tracer_pid(pid) != 0 or "State:\tT" in status or "State:\tt" in status:
                raise ProbeError("snapshot owner already stopped or traced")
            handle = os.pidfd_open(pid)
            stopped.append((pid, handle))
            signal.pidfd_send_signal(handle, signal.SIGSTOP)
        threading.Thread(target=watchdog, daemon=True).start()
        limit = time.monotonic() + 2
        for pid, _ in stopped:
            while True:
                states = [p.read_text() for p in Path(f"/proc/{pid}/task").glob("*/status")]
                if states and all("State:\tT" in s for s in states):
                    break
                if time.monotonic() >= limit:
                    raise ProbeError("snapshot owners did not stop")
                time.sleep(0.01)
        files = [database["path"]]
        wal = Path(str(database["path"]) + "-wal")
        if wal.exists():
            files.append(wal)
        before = [(f.stat().st_size, f.stat().st_mtime_ns) for f in files]
        for source in files:
            dest = destination / ("data.db-wal" if source == wal else "data.db")
            shutil.copyfile(source, dest)
            dest.chmod(0o600)
        after = [(f.stat().st_size, f.stat().st_mtime_ns) for f in files]
        if expired.is_set() or before != after:
            raise ProbeError("snapshot changed or exceeded pause budget")
    finally:
        resume()
        for _, handle in stopped:
            os.close(handle)


VERIFY_SCRIPT = (HERE / "verify_database.py").read_text()


def verify_copy(container, image, database, key, work):
    with tempfile.TemporaryDirectory(prefix="db-copy-", dir=work) as tmp:
        dest = Path(tmp)
        stable_snapshot(container, database, dest)
        with (dest / "data.db").open("rb") as f:
            page = f.read(4096)
        if not verify_sqlcipher_page_hmac(page, key):
            return {"opened": False, "error": "snapshot_page_hmac_failed"}
        argv = ["docker", "run", "--rm", "-i", "--network", "none", "--read-only", "--user", "0",
                        "--mount", f"type=bind,src={dest},dst=/probe",
                        "--entrypoint", "/opt/venv-bot/bin/python", image, "-c", VERIFY_SCRIPT]
        result = subprocess.run(argv, input=json.dumps({"key": key.hex() + page[:16].hex()}).encode(),
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=45)
        if result.returncode not in (0, 2):
            return {"opened": False, "stage": "verifier_process", "exit_code": result.returncode}
        try:
            return json.loads(result.stdout)
        except (ValueError, UnicodeError):
            return {"opened": False, "stage": "verifier_output", "error_type": "InvalidJSON"}


def startup(container, pid):
    """One graceful replacement. Returns new host PID and restoration callback."""
    info = container_info(container)
    env = dict(item.split("=", 1) for item in Path(f"/proc/{pid}/environ").read_bytes().decode().split("\0") if "=" in item)
    argv = Path(f"/proc/{pid}/cmdline").read_bytes().decode().rstrip("\0").split("\0")
    argv[0] = "/opt/wechat/wechat"
    cwd = os.readlink(f"/proc/{pid}/cwd")
    namespace = os.readlink(f"/proc/{pid}/ns/pid")
    uid = Path(f"/proc/{pid}/status").read_text().split("Uid:\t")[1].split()[0]
    service = "/run/service/svc-wechat-ai"
    service_up = docker("exec", container, "s6-svstat", "-o", "up", service).strip() == b"true"
    launched = None

    def restore():
        if service_up:
            docker("exec", container, "s6-svc", "-u", service)

    try:
        if service_up:
            docker("exec", container, "s6-svc", "-d", service)
            docker("exec", container, "s6-svwait", "-d", "-t", "10000", service)
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 20
        while Path(f"/proc/{pid}").exists():
            if time.monotonic() > deadline:
                raise ProbeError("WeChat did not exit gracefully; no forced kill")
            time.sleep(0.1)
        # No persistent launcher edits. The wrapper blocks before exec, so GDB
        # can install an exec catchpoint before any business DB is opened.
        wrapper = """import os,signal,sys,json
c=json.load(sys.stdin)
print(os.getpid(),flush=True)
fd=os.open('/dev/null',os.O_RDWR)
for n in (0,1,2): os.dup2(fd,n)
os.chdir(c['cwd'])
os.kill(os.getpid(),signal.SIGSTOP)
os.execve(c['argv'][0],c['argv'],c['env'])
"""
        launched = subprocess.Popen(["docker", "exec", "-i", "--user", uid, container,
                                     "/usr/bin/python3", "-c", wrapper],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        launched.stdin.write(json.dumps({"env": env, "argv": argv, "cwd": cwd}).encode())
        launched.stdin.close()
        ns_pid = int(launched.stdout.readline())
        launched.stdout.close()
        for new_pid in pids(container):
            status = Path(f"/proc/{new_pid}/status").read_text()
            nspid = next(line.split()[-1] for line in status.splitlines() if line.startswith("NSpid:"))
            if int(nspid) == ns_pid and os.readlink(f"/proc/{new_pid}/ns/pid") == namespace:
                return new_pid, restore
        raise ProbeError("startup wrapper PID not found")
    except BaseException:
        restore()
        raise


def run(args):
    info = container_info(args.container)
    pid = target(args.container)
    root = Path(f"/proc/{info['State']['Pid']}/root")
    if tracer_pid(pid) != 0:
        raise ProbeError("WeChat already has a debugger")
    base = resolve(pid)
    databases = inventory(pid, root)
    report = {"build_id": BUILD_ID, "mode": args.mode, "database_count": len(databases),
              "profile_validated": True, "databases": [], "events": [], "errors": []}
    if args.mode == "inspect":
        report["host_pid"] = pid
        report["load_bias"] = hex(base)
        report["databases"] = [{"id": d["id"], "name": d["name"]} for d in databases]
        return report
    if not databases:
        raise ProbeError("no encrypted business database pages available")
    found, seen = {}, set()
    contexts = {}
    matches_by_call = {}

    def consume(event):
        kind = event["kind"]
        if kind in {"cipher", "key", "kdf", "kdf_return", "capture_error", "kdf_unpaired"}:
            safe = {k: event[k] for k in ("kind", "call_id", "thread", "caller", "length", "mode",
                                         "algorithm", "iterations", "output_length", "success",
                                         "trusted_caller", "stage") if k in event}
            if "context" in event:
                pointer = event["context"]
                safe["context_id"] = contexts.setdefault(pointer, f"context-{len(contexts) + 1}")
            matched_ids = []
            for candidate in candidates(event):
                if candidate in seen:
                    continue
                seen.add(candidate)
                for db in databases:
                    if verify_sqlcipher_page_hmac(db["page"], candidate):
                        found[db["id"]] = candidate
                        matched_ids.append(db["id"])
            if kind == "kdf":
                salt = bytes.fromhex(event["salt"])
                safe["salt_matches"] = [d["id"] for d in databases if d["page"][:16] == salt]
                safe["hmac_salt_matches"] = [d["id"] for d in databases
                                             if bytes(x ^ 0x3a for x in d["page"][:16]) == salt]
                matches_by_call[event["call_id"]] = bool(safe["salt_matches"] or safe["hmac_salt_matches"])
            safe["hmac_matches"] = matched_ids
            report["events"].append(safe)
            return bool(matched_ids or matches_by_call.get(event.get("call_id")))
        return False

    restore = lambda: None
    try:
        if args.mode == "capture-startup":
            pid, restore = startup(args.container, pid)
            print("STARTUP: if WeChat requests QR/phone approval, complete login; capture waits up to 10 minutes", flush=True)
        report["debugger"] = run_gdb({"pid": pid, "startup": args.mode == "capture-startup",
                                      "max_hits": args.max_hits}, consume, args.timeout)
    finally:
        # A failed attach must not leave the pre-exec wrapper group-stopped.
        if args.mode == "capture-startup" and Path(f"/proc/{pid}").exists() and tracer_pid(pid) == 0:
            os.kill(pid, signal.SIGCONT)
        restore()
    report["unique_candidates"] = len(seen)
    verified = False
    for db in sorted(databases, key=lambda d: d["size"]):
        row = {"id": db["id"], "name": db["name"], "hmac_valid": db["id"] in found}
        if row["hmac_valid"] and not verified and db["size"] <= 64 * 1024 * 1024:
            try:
                row["copy_validation"] = verify_copy(args.container, info["Image"], db, found[db["id"]], args.work)
                verified = row["copy_validation"].get("quick_check_ok", False)
            except Exception:
                row["copy_validation"] = {"error": "snapshot_or_verifier_failed"}
        report["databases"].append(row)
    report["success"] = verified
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["inspect", "capture-live", "capture-startup"])
    parser.add_argument("--container", default="wechat-ai")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--max-hits", type=int, default=200)
    parser.add_argument("--work", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 600 or not 1 <= args.max_hits <= 2000:
        parser.error("timeout must be 1..600 and max-hits 1..2000")
    if os.geteuid() != 0:
        # Reuse host GDB without installing packages or changing the app image.
        # Root filesystem is read-only; only this private /tmp directory is writable.
        with tempfile.TemporaryDirectory(prefix="wechat-key-probe-") as work:
            image = container_info(args.container)["Image"]
            argv = ["docker", "run", "--rm", "--network", "none", "--read-only", "--user", "0",
                    "--pid", "host", "--cap-add", "SYS_PTRACE", "--security-opt", "seccomp=unconfined",
                    "--security-opt", "apparmor=unconfined",
                    "--mount", "type=bind,src=/,dst=/host,readonly",
                    "--mount", f"type=bind,src={work},dst=/host{work}",
                    "--entrypoint", "/usr/sbin/chroot", image, "/host", "/usr/bin/python3", "-B",
                    str(Path(__file__).resolve()), args.mode, "--container", args.container,
                    "--timeout", str(args.timeout), "--max-hits", str(args.max_hits), "--work", work]
            return subprocess.call(argv)
    with tempfile.TemporaryDirectory(prefix="probe-", dir=args.work or "/tmp") as work:
        args.work = work
        try:
            report = run(args)
        except Exception as exc:
            report = {"success": False, "error": str(exc) if isinstance(exc, ProbeError) else type(exc).__name__}
        print(json.dumps(report, indent=2), flush=True)
        return 0 if report.get("success", args.mode == "inspect" and "error" not in report) else 2


if __name__ == "__main__":
    raise SystemExit(main())
