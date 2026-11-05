"""Acceso al sistema operativo. Los checks solo usan esta capa, lo que permite
inyectar un sistema simulado (FakeSystem) en los tests."""
import os
import shutil
import subprocess


class System:
    """Lee el estado del sistema real (solo lectura)."""

    # ---- archivos ----
    def read_file(self, path):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return None

    def exists(self, path):
        return os.path.exists(path)

    def mode(self, path):
        """Bits de permiso (ej. 0o600) o None si no existe."""
        try:
            return os.stat(path).st_mode & 0o777
        except OSError:
            return None

    def owner(self, path):
        """(uid, gid) o None."""
        try:
            st = os.stat(path)
            return (st.st_uid, st.st_gid)
        except OSError:
            return None

    # ---- comandos ----
    def which(self, name):
        return shutil.which(name)

    def run(self, cmd, timeout=8):
        """Ejecuta un comando (lista). Devuelve (rc, stdout, stderr).
        rc=127 si el binario no existe."""
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout, check=False)
            return p.returncode, p.stdout, p.stderr
        except FileNotFoundError:
            return 127, "", "comando no encontrado"
        except subprocess.TimeoutExpired:
            return 124, "", "timeout"

    # ---- helpers de alto nivel ----
    def sysctl(self, key):
        """Valor de un parámetro del kernel (ej. 'net.ipv4.ip_forward')."""
        path = "/proc/sys/" + key.replace(".", "/")
        val = self.read_file(path)
        if val is not None:
            return val.strip().split()[0] if val.strip() else ""
        rc, out, _ = self.run(["sysctl", "-n", key])
        return out.strip() if rc == 0 else None

    def service_active(self, name):
        """True/False si el servicio corre; None si no se puede determinar."""
        if not self.which("systemctl"):
            return None
        rc, out, _ = self.run(["systemctl", "is-active", name])
        out = out.strip()
        if out in ("active", "inactive", "failed", "unknown"):
            return out == "active"
        return None

    def package_installed(self, name):
        """True/False/None según dpkg o rpm."""
        if self.which("dpkg-query"):
            rc, out, _ = self.run(["dpkg-query", "-W", "-f=${Status}", name])
            return rc == 0 and "install ok installed" in out
        if self.which("rpm"):
            rc, _, _ = self.run(["rpm", "-q", name])
            return rc == 0
        return None

    def os_release(self):
        data = {}
        txt = self.read_file("/etc/os-release") or ""
        for line in txt.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                data[k] = v.strip().strip('"')
        return data

    def hostname(self):
        return (self.read_file("/etc/hostname") or os.uname().nodename or "").strip()

    def kernel(self):
        u = os.uname()
        return f"{u.sysname} {u.release}"
