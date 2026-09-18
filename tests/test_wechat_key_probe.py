"""Bounded probe tests; GDB integration runs against a disposable child only."""
import contextlib
import hashlib
import hmac
import io
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

PROBE = Path(__file__).resolve().parents[1] / "tools" / "wechat_key_probe"
sys.path.insert(0, str(PROBE))
from core import (ProbeError, bounded_read, candidates, elf_info, file_offset,
                  resolve, verify_sqlcipher_page_hmac)
from probe import run_gdb, verify_copy, VERIFY_SCRIPT
from verify_database import verify


class ProbeTests(unittest.TestCase):
    def test_raw_key_hmac_and_wrong_database(self):
        key = bytes(range(32))
        page = bytearray(os.urandom(4096))
        salt = bytes(x ^ 0x3a for x in page[:16])
        mac = hashlib.pbkdf2_hmac("sha512", key, salt, 2, dklen=32)
        page[-64:] = hmac.digest(mac, bytes(page[16:4032]) + struct.pack("<I", 1), "sha512")
        self.assertTrue(verify_sqlcipher_page_hmac(page, key))
        self.assertFalse(verify_sqlcipher_page_hmac(page, b"x" * 32))
        page[0] ^= 1
        self.assertFalse(verify_sqlcipher_page_hmac(page, key))

    def test_buffer_bounds(self):
        read = lambda a, n: b"x" * n
        for address, length in [(0, 32), (1, 0), (1, -1), (1, 4097)]:
            with self.assertRaises(ProbeError):
                bounded_read(read, address, length)
        self.assertEqual(bounded_read(read, 1, 32), b"x" * 32)
        with self.assertRaises(ProbeError):
            bounded_read(lambda a, n: b"", 1, 32)

    def test_no_guessing_key_api_input(self):
        value = {"kind": "key", "buffer": "ab" * 32}
        self.assertEqual(candidates(value), [])
        value.update(kind="cipher", trusted_caller=False)
        self.assertEqual(candidates(value), [])
        value["trusted_caller"] = True
        self.assertEqual(candidates(value), [bytes.fromhex("ab" * 32)])
        value.update(kind="kdf_return", success=False)
        self.assertEqual(candidates(value), [])

    def test_offsets_and_profile_rejection(self):
        self.assertEqual(file_offset(0x2012, [(1, 5, 0x1000, 0x2000, 100, 100)]), 0x1012)
        with self.assertRaises(ProbeError):
            file_offset(0x9999, [(1, 5, 0x1000, 0x2000, 100, 100)])
        with self.assertRaisesRegex(ProbeError, "Build ID"):
            resolve(os.getpid())

    def test_verifier_script_compiles(self):
        compile(VERIFY_SCRIPT, "verify", "exec")

    def test_verifier_reports_missing_input_without_echoing_values(self):
        for data in ("", "{}", '{"key":"private-marker"}'):
            result = verify(io.StringIO(data))
            self.assertEqual(result["stage"], "input")
            self.assertFalse(result["opened"])
            self.assertNotIn("private-marker", str(result))

    def test_verifier_transport_keeps_stdin_and_failure_stage(self):
        with tempfile.TemporaryDirectory() as work:
            def snapshot(container, database, dest):
                (dest / "data.db").write_bytes(b"x" * 4096)

            result = subprocess.CompletedProcess([], 2,
                b'{"opened":false,"stage":"schema","error_type":"DatabaseError"}')
            with patch("probe.stable_snapshot", side_effect=snapshot), \
                 patch("probe.verify_sqlcipher_page_hmac", return_value=True), \
                 patch("probe.subprocess.run", return_value=result) as run:
                actual = verify_copy("unused", "fixture-image", {}, b"a" * 32, work)
                self.assertEqual(actual["stage"], "schema")
                argv = run.call_args.args[0]
                self.assertIn("-i", argv)
                self.assertNotIn((b"a" * 32).hex(), " ".join(argv))
                self.assertIn(b'"key"', run.call_args.kwargs["input"])

    def test_verifier_rejects_missing_copy_without_creating_file(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "absent.db"
            result = verify(io.StringIO('{"key":"' + "aa" * 48 + '"}'), path)
            self.assertEqual(result["stage"], "copy_path")
            self.assertFalse(path.exists())


FIXTURE = r'''
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
__attribute__((noinline)) void fixture_cipher(void *ctx, int mode, const unsigned char *key,
    int keylen, const unsigned char *iv, void *in, int n, void *out) { asm volatile("" ::: "memory"); }
__attribute__((noinline)) int fixture_kdf(void *ctx,int alg,const unsigned char *pass,int passlen,
    const unsigned char *salt,int saltlen,int iters,int keylen,unsigned char *out) {
    usleep(2000); memcpy(out,pass,keylen); return 0;
}
void *worker(void *arg) {
    unsigned char key[32], iv[16]={0}, out[32]={0};
    memset(key,(intptr_t)arg,32);
    fixture_kdf(arg,2,key,32,iv,16,2,32,out);
    fixture_cipher(arg,0,out,32,iv,0,0,0);
    fixture_cipher(arg,0,0,0,iv,0,0,0);
    return 0;
}
int main(int argc,char **argv) {
    pthread_t a,b;
    pthread_create(&a,0,worker,(void *)17); pthread_create(&b,0,worker,(void *)34);
    pthread_join(a,0); pthread_join(b,0);
    usleep(200000); return 0;
}
'''


@unittest.skipUnless(os.environ.get("WECHAT_PROBE_GDB_TEST") == "1", "opt-in ptrace child test")
class GdbTests(unittest.TestCase):
    def test_multithread_capture_pairing_cleanup_and_redaction(self):
        with tempfile.TemporaryDirectory(prefix="probe-test-") as tmp:
            source = Path(tmp) / "fixture.c"
            exe = Path(tmp) / "fixture"
            source.write_text(FIXTURE)
            subprocess.run(["cc", "-g", "-O0", "-fno-omit-frame-pointer", "-pthread", str(source), "-o", str(exe)], check=True)
            events = []
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = run_gdb({"fixture": str(exe), "fixture_hooks": ["cipher", "kdf"], "max_hits": 200},
                                 lambda event: events.append(event), 5)
            self.assertTrue(result["ready"], result)
            self.assertIn(result["tracer_pid_after"], (0, None))
            returns = [e for e in events if e["kind"] == "kdf_return"]
            entries = {e["call_id"]: e for e in events if e["kind"] == "kdf"}
            self.assertEqual(len(returns), 2, result)
            for event in returns:
                self.assertEqual(event["buffer"], entries[event["call_id"]]["buffer"])
                self.assertTrue(event["success"])
            self.assertEqual(result["events"].get("capture_error"), 2)
            for marker in ("11" * 32, "22" * 32):
                self.assertNotIn(marker, stdout.getvalue())

    def test_timeout_detaches_running_child(self):
        with tempfile.TemporaryDirectory(prefix="probe-test-") as tmp:
            source, exe = Path(tmp) / "fixture.c", Path(tmp) / "fixture"
            source.write_text(FIXTURE.replace("usleep(200000)", "sleep(3)"))
            subprocess.run(["cc", "-g", "-O0", "-pthread", str(source), "-o", str(exe)], check=True)
            result = run_gdb({"fixture": str(exe), "max_hits": 200}, lambda e: False, 1)
            self.assertEqual(result["tracer_pid_after"], 0)
            self.assertEqual(result["events"].get("detached"), 1)


if __name__ == "__main__":
    unittest.main()
