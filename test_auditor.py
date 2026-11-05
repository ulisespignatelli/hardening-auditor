#!/usr/bin/env python3
"""Tests del auditor con un sistema simulado (FakeSystem). No toca el SO real.
Ejecutar: python3 test_auditor.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import haudit
from haudit.core import PASS, FAIL, WARN, NA


class FakeSystem:
    """Sistema simulado: se le pasan archivos, modos, sysctl y servicios."""
    def __init__(self, files=None, modes=None, owners=None, sysctls=None,
                 services=None, packages=None, bins=None, runs=None):
        self.files = files or {}
        self.modes = modes or {}
        self.owners = owners or {}
        self.sysctls = sysctls or {}
        self.services = services or {}
        self.packages = packages or {}
        self.bins = set(bins or [])
        self.runs = runs or {}

    def read_file(self, p): return self.files.get(p)
    def exists(self, p): return p in self.files or p in self.modes
    def mode(self, p): return self.modes.get(p)
    def owner(self, p): return self.owners.get(p)
    def which(self, n): return ("/usr/bin/" + n) if n in self.bins else None
    def run(self, cmd, timeout=8): return self.runs.get(tuple(cmd), (127, "", ""))
    def sysctl(self, k): return self.sysctls.get(k)
    def service_active(self, n): return self.services.get(n)
    def package_installed(self, n): return self.packages.get(n)
    def os_release(self): return {"PRETTY_NAME": "TestOS"}
    def hostname(self): return "testhost"
    def kernel(self): return "Linux test"


def result_map(system, profile_name="base"):
    profile = haudit.profiles.get(profile_name)
    return {r.check.id: r.status for r in haudit.run_all(system, profile)}


# ---- escenario 1: servidor BIEN endurecido ----
HARDENED = FakeSystem(
    files={
        "/etc/ssh/sshd_config": "PermitRootLogin no\nPermitEmptyPasswords no\nMaxAuthTries 3\nPasswordAuthentication no\n",
        "/etc/shadow": "root:$6$x:19000:0:99999:7:::\nuser:$6$y:19000:0:99999:7:::\n",
        "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\n",
        "/etc/login.defs": "PASS_MAX_DAYS 90\nUMASK 027\n",
    },
    modes={"/etc/ssh/sshd_config": 0o600, "/etc/shadow": 0o640, "/etc/gshadow": 0o640,
           "/etc/passwd": 0o644, "/etc/group": 0o644},
    owners={"/etc/ssh/sshd_config": (0, 0), "/etc/shadow": (0, 42), "/etc/gshadow": (0, 42),
            "/etc/passwd": (0, 0), "/etc/group": (0, 0)},
    sysctls={"net.ipv4.ip_forward": "0", "kernel.randomize_va_space": "2",
             "net.ipv4.conf.all.accept_redirects": "0"},
    services={"rsyslog": True, "auditd": True},
    packages={"telnetd": False, "unattended-upgrades": True},
    bins=["ufw"],
    runs={("ufw", "status"): (0, "Status: active\n", "")},
)

# ---- escenario 2: servidor MAL configurado ----
WEAK = FakeSystem(
    files={
        "/etc/ssh/sshd_config": "PermitRootLogin yes\nPermitEmptyPasswords yes\nMaxAuthTries 10\n",
        "/etc/shadow": "root:$6$x:19000:0:99999:7:::\nbackup::19000:0:99999:7:::\n",
        "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:0:0::/home/admin:/bin/bash\n",
        "/etc/login.defs": "PASS_MAX_DAYS 99999\n",
    },
    modes={"/etc/ssh/sshd_config": 0o666, "/etc/shadow": 0o644, "/etc/gshadow": 0o644,
           "/etc/passwd": 0o644, "/etc/group": 0o644},
    owners={"/etc/shadow": (0, 0), "/etc/passwd": (0, 0), "/etc/group": (0, 0),
            "/etc/gshadow": (0, 0), "/etc/ssh/sshd_config": (0, 0)},
    sysctls={"net.ipv4.ip_forward": "1", "kernel.randomize_va_space": "0",
             "net.ipv4.conf.all.accept_redirects": "1"},
    services={"rsyslog": False, "auditd": False},
    packages={"telnetd": True, "unattended-upgrades": False},
    bins=[],
)

EXPECT_HARDENED = {
    "SSH-01": PASS, "SSH-02": PASS, "SSH-03": PASS, "SSH-04": PASS, "SSH-05": PASS,
    "FILE-01": PASS, "FILE-02": PASS, "FILE-03": PASS, "FILE-04": PASS,
    "ACC-01": PASS, "ACC-02": PASS, "ACC-03": PASS, "ACC-04": PASS,
    "NET-01": PASS, "NET-02": PASS, "NET-03": PASS, "NET-04": PASS,
    "SVC-01": PASS, "SVC-02": PASS, "SVC-03": PASS, "SVC-04": PASS,
}
EXPECT_WEAK = {
    "SSH-01": FAIL, "SSH-02": FAIL, "SSH-03": FAIL, "SSH-04": FAIL, "SSH-05": WARN,
    "FILE-01": FAIL, "FILE-02": FAIL, "FILE-03": PASS, "FILE-04": PASS,
    "ACC-01": FAIL, "ACC-02": FAIL, "ACC-03": FAIL,
    "NET-01": FAIL, "NET-02": FAIL, "NET-03": FAIL, "NET-04": WARN,
    "SVC-01": FAIL, "SVC-02": FAIL, "SVC-03": WARN, "SVC-04": FAIL,
}


def main():
    ok = fail = 0
    for label, system, expected in [("endurecido", HARDENED, EXPECT_HARDENED),
                                    ("débil", WEAK, EXPECT_WEAK)]:
        got = result_map(system)
        for cid, exp in expected.items():
            g = got.get(cid)
            status = "ok " if g == exp else "FAIL"
            if g == exp:
                ok += 1
            else:
                fail += 1
                print(f"[{status}] ({label}) {cid}: esperado {exp}, obtuvo {g}")

    # puntajes coherentes
    from haudit.core import score
    p_h, _ = score(haudit.run_all(HARDENED, haudit.profiles.get("base")))
    p_w, _ = score(haudit.run_all(WEAK, haudit.profiles.get("base")))
    for cond, desc in [(p_h >= 95, f"endurecido >=95 (got {p_h})"),
                       (p_w <= 15, f"débil <=15 (got {p_w})"),
                       (len(haudit.REGISTRY) >= 20, f">=20 checks (got {len(haudit.REGISTRY)})")]:
        status = "ok " if cond else "FAIL"
        ok, fail = (ok + 1, fail) if cond else (ok, fail + 1)
        print(f"[{status}] {desc}")

    print(f"\n{ok} ok, {fail} fallos  ·  puntaje endurecido={p_h}  débil={p_w}  checks={len(haudit.REGISTRY)}")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
