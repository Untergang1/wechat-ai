"""Loaded only by GDB. Secret events go to the controller's private pipe."""
import json
import os
import sys
import gdb

sys.path.insert(0, os.path.dirname(__file__))
from core import PREFIX, PROFILE, CIPHER_RETURN, bounded_read, resolve

config = json.loads(os.environ["WECHAT_PROBE_CONFIG"])
count = 0
sequence = 0
base = 0
hooks = []


def emit(kind, **data):
    # Bypass GDB's to_string capture: events must reach the private pipe while
    # the inferior runs, rather than accumulating inside the continue command.
    os.write(1, (PREFIX + json.dumps({"kind": kind, **data}) + "\n").encode())


def reg(name):
    return int(gdb.parse_and_eval("$" + name)) & ((1 << 64) - 1)


def read(addr, size, maximum=4096):
    return bounded_read(gdb.selected_inferior().read_memory, addr, size, maximum)


def stack(offset):
    return int.from_bytes(read(reg("rsp") + offset, 8), "little")


class KdfReturn(gdb.FinishBreakpoint):
    def __init__(self, call_id, output, length):
        super().__init__(gdb.newest_frame(), internal=True)
        self.call_id, self.output, self.length = call_id, output, length
        self.silent = True

    def stop(self):
        try:
            success = reg("eax") == 0
            emit("kdf_return", call_id=self.call_id, success=success,
                 buffer=read(self.output, self.length).hex() if success else "")
        except Exception:
            emit("capture_error", stage="kdf_return")
        return False

    def out_of_scope(self):
        emit("kdf_unpaired", call_id=self.call_id)


class Hook(gdb.Breakpoint):
    def __init__(self, kind, location):
        super().__init__(location, internal=True)
        self.kind = kind
        self.silent = True

    def stop(self):
        global count, sequence
        count += 1
        sequence += 1
        try:
            thread = gdb.selected_thread().ptid[1]
            caller = stack(0) - base
            common = {"call_id": sequence, "thread": thread, "caller": hex(caller),
                      "context": reg("rdi")}
            if self.kind == "cipher":
                length = reg("ecx") & 0xffffffff
                trusted = config.get("fixture", False) or caller == CIPHER_RETURN
                emit("cipher", **common, trusted_caller=trusted, length=length,
                     mode=reg("esi") & 0xffffffff,
                     buffer=read(reg("rdx"), length, 64).hex() if trusted else "",
                     iv=read(reg("r8"), 16).hex() if trusted else "")
            elif self.kind == "key":
                length = reg("ecx") & 0xffffffff
                emit("key", **common, length=length,
                     buffer=read(reg("rdx"), length).hex())
            else:
                length = stack(16) & 0xffffffff
                if not 0 < length <= 64:
                    raise ValueError("output length")
                output = stack(24)
                read(output, length, 64)
                hooks.append(KdfReturn(sequence, output, length))
                emit("kdf", **common, algorithm=reg("esi") & 0xffffffff,
                     iterations=stack(8) & 0xffffffff, output_length=length,
                     buffer=read(reg("rdx"), reg("ecx") & 0xffffffff).hex(),
                     salt=read(reg("r8"), reg("r9d") & 0xffffffff, 64).hex())
        except Exception:
            emit("capture_error", stage=self.kind)
        return count >= config["max_hits"]


attached = False
try:
    for command in ("set pagination off", "set confirm off", "set debuginfod enabled off",
                    "set auto-solib-add off", "set print thread-events off",
                    "set breakpoint pending off", "handle SIGPIPE nostop noprint pass",
                    "handle SIGINT stop print nopass",
                    "handle SIGSTOP nostop noprint nopass"):
        gdb.execute(command, to_string=True)
    if config.get("fixture"):
        gdb.execute("file " + config["fixture"], to_string=True)
        gdb.execute("starti", to_string=True)
        attached = True
        pid = gdb.selected_inferior().pid
        emit("attached", pid=pid)
        for kind in config.get("fixture_hooks", ["cipher"]):
            hooks.append(Hook(kind, "*fixture_" + kind))
    else:
        pid = config["pid"]
        gdb.execute("attach " + str(pid), to_string=True)
        attached = True
        emit("attached", pid=pid)
        if config.get("startup"):
            gdb.execute("catch exec", to_string=True)
            catchpoints = list(gdb.breakpoints() or [])
            gdb.execute("continue", to_string=True)
            for bp in catchpoints:
                bp.delete()
        base = resolve(pid, gdb.selected_inferior().read_memory)
        for kind in (["cipher", "key", "kdf"] if config.get("startup") else ["cipher"]):
            hooks.append(Hook(kind, "*" + hex(base + PROFILE[kind][0])))
    emit("ready", pid=pid)
    gdb.execute("continue", to_string=True)
    emit("stopped", hits=count)
except KeyboardInterrupt:
    emit("interrupted", hits=count)
except Exception:
    emit("worker_error", hits=count)
finally:
    for bp in list(gdb.breakpoints() or []):
        try:
            if bp.is_valid():
                bp.delete()
        except Exception:
            emit("cleanup_error", stage="breakpoint")
    if attached and gdb.selected_inferior().pid:
        try:
            gdb.execute("detach", to_string=True)
            emit("detached")
        except Exception:
            emit("cleanup_error", stage="detach")
