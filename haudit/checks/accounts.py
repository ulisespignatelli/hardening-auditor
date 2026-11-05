"""Checks de cuentas y política de contraseñas (CIS)."""
import re
from ..core import check, PASS, FAIL, WARN, NA


@check(id="ACC-01", title="Ninguna cuenta tiene contraseña vacía",
       category="Cuentas", severity="critica", tags=("base", "ot"),
       rationale="Una cuenta sin contraseña permite el acceso sin credenciales.",
       remediation="Bloqueá o asigná contraseña a las cuentas afectadas (passwd -l <usuario>).")
def no_empty_passwords(system):
    txt = system.read_file("/etc/shadow")
    if txt is None:
        return NA, "no se pudo leer /etc/shadow (requiere root)"
    empties = []
    for line in txt.splitlines():
        parts = line.split(":")
        if len(parts) >= 2 and parts[1] == "":
            empties.append(parts[0])
    if empties:
        return FAIL, "cuentas con contraseña vacía: " + ", ".join(empties)
    return PASS, "ninguna cuenta con contraseña vacía"


@check(id="ACC-02", title="Solo root tiene UID 0",
       category="Cuentas", severity="alta", tags=("base", "ot"),
       rationale="Más de una cuenta con UID 0 significa múltiples superusuarios ocultos.",
       remediation="Cambiá el UID de cualquier cuenta distinta de root que tenga UID 0.")
def only_root_uid0(system):
    txt = system.read_file("/etc/passwd")
    if txt is None:
        return NA, "no se pudo leer /etc/passwd"
    uid0 = []
    for line in txt.splitlines():
        parts = line.split(":")
        if len(parts) >= 3 and parts[2] == "0":
            uid0.append(parts[0])
    if uid0 == ["root"]:
        return PASS, "solo root tiene UID 0"
    return FAIL, "cuentas con UID 0: " + ", ".join(uid0)


@check(id="ACC-03", title="Caducidad máxima de contraseñas configurada",
       category="Cuentas", severity="baja", tags=("base",),
       rationale="Las contraseñas deberían caducar periódicamente (política CIS: <= 365 días).",
       remediation="En /etc/login.defs poné 'PASS_MAX_DAYS 365' (o menos).")
def pass_max_days(system):
    txt = system.read_file("/etc/login.defs")
    if txt is None:
        return NA, "login.defs no está presente"
    m = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", txt, re.M)
    if not m:
        return WARN, "PASS_MAX_DAYS no está definido"
    days = int(m.group(1))
    return (PASS, f"PASS_MAX_DAYS {days}") if days <= 365 else (FAIL, f"PASS_MAX_DAYS {days} (> 365)")


@check(id="ACC-04", title="umask por defecto restrictivo",
       category="Cuentas", severity="baja", tags=("base",),
       rationale="Un umask de 027 o más estricto evita archivos nuevos legibles por todos.",
       remediation="En /etc/login.defs poné 'UMASK 027'.")
def default_umask(system):
    txt = system.read_file("/etc/login.defs")
    if txt is None:
        return NA, "login.defs no está presente"
    m = re.search(r"^\s*UMASK\s+(\d+)", txt, re.M)
    if not m:
        return WARN, "UMASK no está definido"
    umask = m.group(1)
    return (PASS, f"UMASK {umask}") if umask in ("027", "077", "0027", "0077") else (WARN, f"UMASK {umask} (recomendado 027)")
