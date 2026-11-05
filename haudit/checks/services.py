"""Checks de servicios, logging y actualizaciones (CIS)."""
from ..core import check, PASS, FAIL, WARN, NA


@check(id="SVC-01", title="Sin servidor Telnet instalado",
       category="Servicios", severity="alta", tags=("base", "ot"),
       rationale="Telnet transmite credenciales en texto plano; no debe usarse.",
       remediation="Desinstalá el servidor telnet (apt purge telnetd) y usá SSH.")
def no_telnet(system):
    installed = system.package_installed("telnetd")
    if installed is None:
        # sin gestor de paquetes conocido: miramos el binario
        return (PASS, "no se encontró telnetd") if not system.which("telnetd") else (FAIL, "telnetd presente")
    return (FAIL, "telnetd instalado") if installed else (PASS, "telnetd no instalado")


@check(id="SVC-02", title="Servicio de logging activo",
       category="Servicios", severity="media", tags=("base", "ot"),
       rationale="Sin logs centralizados no hay trazabilidad ni detección de incidentes.",
       remediation="Habilitá rsyslog o journald: systemctl enable --now rsyslog")
def logging_active(system):
    for svc in ("rsyslog", "syslog-ng", "systemd-journald"):
        active = system.service_active(svc)
        if active:
            return PASS, f"{svc} activo"
    if system.service_active("rsyslog") is None:
        return NA, "no se pudo determinar (systemctl no disponible)"
    return FAIL, "no se detectó un servicio de logging activo"


@check(id="SVC-03", title="Actualizaciones de seguridad automáticas configuradas",
       category="Servicios", severity="media", tags=("base",),
       rationale="Aplicar parches a tiempo cierra vulnerabilidades conocidas.",
       remediation="Instalá y habilitá unattended-upgrades (Debian/Ubuntu) o dnf-automatic (RHEL).")
def auto_updates(system):
    definitive = False
    for pkg in ("unattended-upgrades", "dnf-automatic", "yum-cron"):
        inst = system.package_installed(pkg)
        if inst:
            return PASS, f"{pkg} instalado"
        if inst is False:
            definitive = True
    if not definitive:
        return NA, "no se pudo determinar (sin gestor de paquetes conocido)"
    return WARN, "sin actualizaciones automáticas configuradas"


@check(id="SVC-04", title="Auditoría del sistema (auditd) activa",
       category="Servicios", severity="media", tags=("base", "ot"),
       rationale="auditd registra eventos de seguridad clave para análisis forense.",
       remediation="Instalá y habilitá auditd: systemctl enable --now auditd")
def auditd_active(system):
    active = system.service_active("auditd")
    if active is None:
        inst = system.package_installed("auditd")
        if inst is None:
            return NA, "no se pudo determinar"
        return (WARN, "auditd instalado pero estado desconocido") if inst else (WARN, "auditd no instalado")
    return (PASS, "auditd activo") if active else (FAIL, "auditd inactivo")
