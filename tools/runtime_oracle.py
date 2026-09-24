"""Runtime syscall false-negative oracle (Real-World Mining, §D2).

The thesis-critical, fully-automatable soundness check. Execute changed code in an
instrumented sandbox (here: strace), capture ACTUAL syscalls, map observed effects
to the taxonomy, and assert:

    every capability OBSERVED at runtime in a changed region was reported by
    Aether as INTRODUCES or UNPROVABLE — never NO_NEW_CAPABILITY.

Any violation is a CONFIRMED real-world false negative and halts the program. This
catches FNs that self-authored traps cannot.

LIMITATION (stated, per §D2/§H): the oracle observes only EXERCISED capabilities,
so it is a lower bound on the true capability set. It can CONFIRM false negatives;
it cannot certify their absence. It complements hand-labeling; it does not replace
it. Baseline subtraction (diff against an empty-interpreter run) removes most
import-time noise but is heuristic — treat fs/log signals as indicative and the
net/process signals as high-confidence.
"""
from __future__ import annotations
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Set

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.dirname(HERE))

_SYS_PREFIXES = ("/usr", "/lib", "/lib64", "/proc", "/sys", "/dev", "/etc/ld",
                 "/opt/python", "/tmp/aether", "site-packages", "__pycache__")


class OracleUnavailable(RuntimeError):
    """The oracle cannot observe anything on this machine."""


def available() -> bool:
    """Linux strace only. Git-for-Windows ships a Cygwin `strace` whose
    output none of the patterns below match: there the oracle observed
    nothing, reported `soundness_ok: True`, and so certified as sound a
    change whose effect it never saw (test_mining.py, unrun, was red on it)."""
    return sys.platform.startswith("linux") and shutil.which("strace") is not None


def _trace(script_path: str, argv: Optional[List[str]] = None) -> List[str]:
    if not available():
        raise OracleUnavailable("the runtime oracle needs Linux strace; observing "
                                "nothing is not observing no effects")
    with tempfile.NamedTemporaryFile("r", suffix=".strace", delete=False) as tf:
        trace_file = tf.name
    cmd = ["strace", "-f", "-qq", "-y",
           "-e", "trace=connect,sendto,sendmsg,socket,openat,open,execve,clone,fork,vfork,write",
           "-o", trace_file, sys.executable, script_path] + (argv or [])
    try:
        subprocess.run(cmd, capture_output=True, timeout=30,
                       env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    except subprocess.TimeoutExpired:
        pass
    try:
        with open(trace_file) as fh:
            return fh.readlines()
    finally:
        try:
            os.unlink(trace_file)
        except OSError:
            pass


_RE_CONNECT_INET = re.compile(r"connect\(.*sa_family=AF_INET")
_RE_SOCKET_INET = re.compile(r"socket\(AF_INET")
_RE_OPEN_WRITE = re.compile(r'openat?\([^)]*"(?P<path>[^"]+)"[^)]*(O_WRONLY|O_RDWR|O_CREAT|O_APPEND)')
_RE_EXECVE = re.compile(r'execve\("(?P<path>[^"]+)"')
_RE_CLONE = re.compile(r"\b(clone|fork|vfork)\(")
_RE_WRITE_STD = re.compile(r"write\((?P<fd>1|2)<")


def map_syscalls(lines: List[str], is_baseline_first_execve: bool = True) -> Set[str]:
    caps: Set[str] = set()
    seen_first_execve = False
    for ln in lines:
        if _RE_CONNECT_INET.search(ln) or _RE_SOCKET_INET.search(ln):
            caps.add("net")
        m = _RE_OPEN_WRITE.search(ln)
        if m:
            p = m.group("path")
            if not any(s in p for s in _SYS_PREFIXES) and not p.endswith(".pyc"):
                caps.add("fs")
        if _RE_EXECVE.search(ln):
            if seen_first_execve:           # the first execve is the interpreter itself
                caps.add("process")
            seen_first_execve = True
        if _RE_CLONE.search(ln):
            caps.add("process")
        if _RE_WRITE_STD.search(ln):
            caps.add("log")
    return caps


def observe_capabilities(script_src: str) -> Set[str]:
    """Run script_src under strace; subtract an empty-interpreter baseline."""
    with tempfile.NamedTemporaryFile("w", suffix="_target.py", delete=False) as tf:
        tf.write(script_src); target = tf.name
    with tempfile.NamedTemporaryFile("w", suffix="_base.py", delete=False) as bf:
        bf.write("pass\n"); base = bf.name
    try:
        target_caps = map_syscalls(_trace(target))
        base_caps = map_syscalls(_trace(base))
        # net/process are high-confidence; fs/log subtract interpreter baseline
        observed = set(target_caps)
        for noisy in ("fs", "log"):
            if noisy in base_caps:
                observed.discard(noisy)
        return observed
    finally:
        for p in (target, base):
            try:
                os.unlink(p)
            except OSError:
                pass


def check_against_aether(base_src: str, head_src: str,
                         entrypoint_src: Optional[str] = None) -> Dict[str, Any]:
    """Run the head (or a provided entrypoint exercising it) and assert Aether's
    delta verdict never says NO_NEW_CAPABILITY for an observed capability."""
    from tools.cap_delta import capability_delta
    observed = observe_capabilities(entrypoint_src or head_src)
    delta = capability_delta(base_src, head_src)
    named = set(delta.get("newly_introduces", []))
    verdict = delta.get("verdict")
    fns = []
    for cap in observed:
        if verdict == "NO_NEW_CAPABILITY":
            fns.append({"observed": cap, "verdict": verdict,
                        "reason": "runtime observed capability but Aether cleared the delta"})
    return {
        "observed_capabilities": sorted(observed),
        "aether_verdict": verdict,
        "aether_named": sorted(named),
        "confirmed_false_negatives": fns,
        "soundness_ok": not fns,
    }


if __name__ == "__main__":
    import json
    # DEMO: a head that opens a file, writes it, and attempts a network connect.
    base = "def handle(x):\n    return x\n"
    head = ("import socket\n"
            "def handle(x):\n"
            "    with open('/tmp/oracle_demo.out','w') as fh:\n"
            "        fh.write(str(x))\n"
            "    try:\n"
            "        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "        s.connect(('1.1.1.1',53))\n"
            "    except OSError:\n"
            "        pass\n"
            "    return x\n")
    entry = head + "\nhandle(42)\n"
    print(json.dumps(check_against_aether(base, head, entrypoint_src=entry), indent=2))
