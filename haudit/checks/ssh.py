"""Checks de endurecimiento de SSH (CIS)."""
import re
from ..core import check, PASS, FAIL, WARN, NA

SSHD = "/etc/ssh/sshd_config"


def _directive(system, key):
    """Último valor efectivo de una directiva en sshd_config (o None)."""
    txt = system.read_file(SSHD)
    if txt is None:
        return None
    val = None
    rx = re.compile(r"^\s*" + re.escape(key) + r"\s+(.+?)\s*$", re.I)
    for line in txt.splitlines():
        if line.lstrip().startswith("#"):
            continue
        m = rx.match(line)
        if m:
            val = m.group(1).strip()
    return val


def _skip_if_no_sshd(system):
    return system.read_file(SSHD) is None


@check(id="SSH-01", title="SSH no permite el login directo de root",
       category="SSH", severity="alta", tags=("base", "ot"),
       rationale="El acceso directo como root impide la trazabilidad y amplía el riesgo.",
       remediation="En /etc/ssh/sshd_config poné 'PermitRootLogin no' y reiniciá sshd.")
def ssh_root_login(system):
    if _skip_if_no_sshd(system):
        return NA, "sshd_config no está presente"
    val = (_directive(system, "PermitRootLogin") or "prohibit-password").lower()
    if val == "no":
        return PASS, "PermitRootLogin no"
    return FAIL, f"PermitRootLogin = {val}"


@check(id="SSH-02", title="SSH no acepta contraseñas vacías",
       category="SSH", severity="critica", tags=("base", "ot"),
       rationale="Permitir contraseñas vacías habilita accesos triviales.",
       remediation="Poné 'PermitEmptyPasswords no' en sshd_config y reiniciá sshd.")
def ssh_empty_pw(system):
    if _skip_if_no_sshd(system):
        return NA, "sshd_config no está presente"
    val = (_directive(system, "PermitEmptyPasswords") or "no").lower()
    return (PASS, "PermitEmptyPasswords no") if val == "no" else (FAIL, f"PermitEmptyPasswords = {val}")


@check(id="SSH-03", title="SSH limita los intentos de autenticación",
       category="SSH", severity="media", tags=("base",),
       rationale="Un MaxAuthTries bajo frena ataques de fuerza bruta.",
       remediation="Poné 'MaxAuthTries 4' (o menos) en sshd_config.")
def ssh_maxauth(system):
    if _skip_if_no_sshd(system):
        return NA, "sshd_config no está presente"
    val = _directive(system, "MaxAuthTries")
    if val is None:
        return WARN, "MaxAuthTries no está definido (default 6)"
    try:
        n = int(val)
    except ValueError:
        return WARN, f"MaxAuthTries con valor no numérico: {val}"
    return (PASS, f"MaxAuthTries {n}") if n <= 4 else (FAIL, f"MaxAuthTries {n} (> 4)")


@check(id="SSH-04", title="Permisos de sshd_config restringidos",
       category="SSH", severity="media", tags=("base", "ot"),
       rationale="sshd_config no debe ser escribible por usuarios sin privilegios.",
       remediation="chmod 600 /etc/ssh/sshd_config && chown root:root /etc/ssh/sshd_config")
def ssh_config_perms(system):
    mode = system.mode(SSHD)
    if mode is None:
        return NA, "sshd_config no está presente"
    own = system.owner(SSHD)
    bad_world_group = mode & 0o077
    if bad_world_group == 0 and (own is None or own[0] == 0):
        return PASS, f"permisos {oct(mode)} root"
    return FAIL, f"permisos {oct(mode)} (deberían ser 600, root)"


@check(id="SSH-05", title="Se recomienda autenticación por clave, no por contraseña",
       category="SSH", severity="baja", tags=("base",),
       rationale="Las claves públicas resisten la fuerza bruta mejor que las contraseñas.",
       remediation="Configurá acceso por clave y poné 'PasswordAuthentication no'.")
def ssh_pubkey(system):
    if _skip_if_no_sshd(system):
        return NA, "sshd_config no está presente"
    val = (_directive(system, "PasswordAuthentication") or "yes").lower()
    return (PASS, "PasswordAuthentication no") if val == "no" else (WARN, "PasswordAuthentication yes (considerá usar claves)")
