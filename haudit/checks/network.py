"""Checks de red y kernel (sysctl) y firewall (CIS)."""
from ..core import check, PASS, FAIL, WARN, NA


@check(id="NET-01", title="Reenvío de paquetes (IP forwarding) deshabilitado",
       category="Red/Kernel", severity="media", tags=("base", "ot"),
       rationale="Un host que no es router no debería reenviar tráfico entre redes.",
       remediation="sysctl -w net.ipv4.ip_forward=0 y persistilo en /etc/sysctl.conf. "
                   "Si el equipo es un router/gateway, documentá la excepción.")
def ip_forward(system):
    val = system.sysctl("net.ipv4.ip_forward")
    if val is None:
        return NA, "no se pudo leer net.ipv4.ip_forward"
    return (PASS, "ip_forward = 0") if val == "0" else (FAIL, f"ip_forward = {val}")


@check(id="NET-02", title="ASLR (aleatorización de memoria) activa",
       category="Red/Kernel", severity="alta", tags=("base", "ot"),
       rationale="ASLR dificulta la explotación de vulnerabilidades de memoria.",
       remediation="sysctl -w kernel.randomize_va_space=2 y persistilo en /etc/sysctl.conf.")
def aslr(system):
    val = system.sysctl("kernel.randomize_va_space")
    if val is None:
        return NA, "no se pudo leer kernel.randomize_va_space"
    return (PASS, "randomize_va_space = 2") if val == "2" else (FAIL, f"randomize_va_space = {val} (debería ser 2)")


@check(id="NET-03", title="No se aceptan redirecciones ICMP",
       category="Red/Kernel", severity="media", tags=("base",),
       rationale="Aceptar ICMP redirects permite a un atacante alterar la tabla de ruteo.",
       remediation="sysctl -w net.ipv4.conf.all.accept_redirects=0 y persistilo.")
def icmp_redirects(system):
    val = system.sysctl("net.ipv4.conf.all.accept_redirects")
    if val is None:
        return NA, "no se pudo leer accept_redirects"
    return (PASS, "accept_redirects = 0") if val == "0" else (FAIL, f"accept_redirects = {val}")


@check(id="NET-04", title="Hay un firewall activo",
       category="Red/Kernel", severity="alta", tags=("base", "ot"),
       rationale="Un firewall limita la superficie de red expuesta.",
       remediation="Activá ufw ('ufw enable') o configurá reglas en nftables/iptables.")
def firewall_active(system):
    # ufw
    if system.which("ufw"):
        rc, out, _ = system.run(["ufw", "status"])
        if rc == 0 and "status: active" in out.lower():
            return PASS, "ufw activo"
    # nftables
    if system.which("nft"):
        rc, out, _ = system.run(["nft", "list", "ruleset"])
        if rc == 0 and out.strip():
            return PASS, "nftables con reglas cargadas"
    # iptables
    if system.which("iptables"):
        rc, out, _ = system.run(["iptables", "-S"])
        if rc == 0:
            rules = [l for l in out.splitlines() if l and not l.startswith("-P")]
            policies_drop = any(l in ("-P INPUT DROP", "-P FORWARD DROP") for l in out.splitlines())
            if rules or policies_drop:
                return PASS, "iptables con reglas cargadas"
            return FAIL, "iptables sin reglas (todo en ACCEPT)"
    return WARN, "no se detectó un firewall gestionable (ufw/nft/iptables)"
