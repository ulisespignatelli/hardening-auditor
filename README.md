# Hardening Auditor 🧱🛡️

Auditor de **endurecimiento (hardening)** para servidores Linux. Revisa la configuración contra buenas prácticas de los **CIS Benchmarks** y reporta qué cumple, qué no y **cómo arreglarlo** — con reporte en terminal, HTML y JSON.

> **Es de solo lectura.** No modifica nada del sistema: audita y recomienda. Ese es el enfoque profesional (no se tocan a ciegas servidores en producción).

Por [Ulises Pignatelli](https://github.com/ulisespignatelli) — UP Security.

---

## ¿Por qué?

Un servidor recién instalado viene "blando": con opciones cómodas pero inseguras por defecto. El hardening reduce su superficie de ataque. Las empresas lo pagan, y en **infraestructura crítica (OT)** es un requisito explícito (NIST SP 800-82, IEC 62443). Esta herramienta mide, en minutos, qué tan endurecido está un equipo.

## Características

- **21 controles reales** agrupados en SSH, Archivos, Cuentas, Red/Kernel y Servicios.
- **Puntaje ponderado por severidad** (0-100) — no todos los hallazgos pesan igual.
- **Perfil OT**: resalta (⚡) los controles críticos para infraestructura y cita NIST SP 800-82 / IEC 62443.
- **Tres salidas**: terminal con color, **HTML** listo para entregar a un cliente, y JSON para integrar.
- **Degradación elegante**: si un componente no está (ej. sshd), el control se marca `N/A` en vez de fallar.
- **Sin dependencias**: solo la librería estándar de Python 3.8+.

## Uso

```bash
git clone https://github.com/ulisespignatelli/hardening-auditor
cd hardening-auditor

# Perfil base, salida en terminal (usá sudo para leer /etc/shadow, etc.)
sudo python3 auditor.py

# Perfil OT / infraestructura crítica
sudo python3 auditor.py --profile ot

# Generar reporte para un cliente
sudo python3 auditor.py --profile ot --html informe.html --json informe.json
```

### Códigos de salida
| Código | Significado |
|---|---|
| `0` | Sin fallas (puede haber avisos) |
| `1` | Hay al menos una **falla** |

## Controles incluidos

| Área | Ejemplos |
|---|---|
| **SSH** | root login deshabilitado, sin contraseñas vacías, `MaxAuthTries`, permisos de `sshd_config` |
| **Archivos** | permisos de `/etc/shadow`, `/etc/gshadow`, `/etc/passwd`, `/etc/group` |
| **Cuentas** | sin contraseñas vacías, solo root con UID 0, caducidad de contraseñas, umask |
| **Red/Kernel** | IP forwarding, ASLR, ICMP redirects, firewall activo |
| **Servicios** | sin Telnet, logging activo, actualizaciones automáticas, auditd |

## Arquitectura (modular y extensible)

```
hardening-auditor/
├── auditor.py              # CLI
└── haudit/
    ├── core.py             # registro de checks, severidades, puntaje
    ├── system.py           # acceso al SO (solo lectura) — inyectable en tests
    ├── profiles.py         # perfiles base y OT
    ├── report.py           # reportes terminal / HTML / JSON
    └── checks/
        ├── ssh.py  files.py  accounts.py  network.py  services.py
```

### Agregar un control nuevo

```python
from ..core import check, PASS, FAIL

@check(id="NET-05", title="…", category="Red/Kernel", severity="media",
       tags=("base", "ot"), remediation="cómo arreglarlo")
def mi_control(system):
    return PASS if system.sysctl("net.ipv4.tcp_syncookies") == "1" else FAIL
```

Aparece solo en el informe. Los checks usan la capa `system`, así que se testean con un sistema simulado sin tocar el SO real.

## Tests

```bash
python3 test_auditor.py   # 44 asserts con sistemas simulados (endurecido vs. débil)
```

## ⚠️ Aviso

Herramienta de referencia basada en CIS Benchmarks. No reemplaza una auditoría formal ni los CIS Benchmarks completos. Ejecutala solo en sistemas que administres o estés autorizado a auditar.

## Licencia

MIT — ver [LICENSE](LICENSE).
