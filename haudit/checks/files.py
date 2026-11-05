"""Checks de permisos de archivos críticos (CIS)."""
from ..core import check, PASS, FAIL, NA


def _perm_check(system, path, max_mode, owner_uid=0):
    """PASS si el archivo no excede max_mode y pertenece a owner_uid."""
    mode = system.mode(path)
    if mode is None:
        return NA, f"{path} no está presente"
    own = system.owner(path)
    too_open = mode & ~max_mode & 0o777
    owner_ok = own is None or own[0] == owner_uid
    if too_open == 0 and owner_ok:
        return PASS, f"permisos {oct(mode)}"
    return FAIL, f"permisos {oct(mode)} (máximo permitido {oct(max_mode)})"


@check(id="FILE-01", title="/etc/shadow con permisos restringidos",
       category="Archivos", severity="critica", tags=("base", "ot"),
       rationale="Contiene los hashes de contraseñas; no debe ser legible por otros.",
       remediation="chmod 0640 /etc/shadow && chown root:shadow /etc/shadow")
def shadow_perms(system):
    return _perm_check(system, "/etc/shadow", 0o640)


@check(id="FILE-02", title="/etc/gshadow con permisos restringidos",
       category="Archivos", severity="alta", tags=("base",),
       rationale="Contiene credenciales de grupos; no debe exponerse.",
       remediation="chmod 0640 /etc/gshadow && chown root:shadow /etc/gshadow")
def gshadow_perms(system):
    return _perm_check(system, "/etc/gshadow", 0o640)


@check(id="FILE-03", title="/etc/passwd con permisos correctos",
       category="Archivos", severity="media", tags=("base",),
       rationale="Debe ser legible pero no escribible por usuarios comunes.",
       remediation="chmod 0644 /etc/passwd && chown root:root /etc/passwd")
def passwd_perms(system):
    return _perm_check(system, "/etc/passwd", 0o644)


@check(id="FILE-04", title="/etc/group con permisos correctos",
       category="Archivos", severity="baja", tags=("base",),
       rationale="No debe ser escribible por usuarios comunes.",
       remediation="chmod 0644 /etc/group && chown root:root /etc/group")
def group_perms(system):
    return _perm_check(system, "/etc/group", 0o644)
