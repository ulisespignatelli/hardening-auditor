#!/usr/bin/env python3
"""
auditor.py — Auditor de endurecimiento (hardening) para servidores Linux.

Revisa la configuración de un servidor contra buenas prácticas de los CIS
Benchmarks y reporta qué cumple, qué no, y cómo arreglarlo. Es de SOLO LECTURA:
no modifica nada del sistema.

Uso:
  sudo python3 auditor.py                    # perfil base, salida en terminal
  sudo python3 auditor.py --profile ot       # perfil OT / infraestructura crítica
  sudo python3 auditor.py --html informe.html
  sudo python3 auditor.py --json informe.json

Nota: corré con sudo para poder leer archivos como /etc/shadow; sin privilegios,
esos checks se marcan como N/A en lugar de fallar.

Códigos de salida:
  0  sin fallas (puede haber avisos)
  1  hay al menos una FALLA
  2  error de uso

Autor: Ulises Pignatelli — UP Security. Licencia: MIT.
"""
import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import haudit
from haudit import report
from haudit.core import FAIL


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Auditor de endurecimiento de servidores Linux (CIS). Solo lectura.")
    ap.add_argument("--profile", default="base", choices=list(haudit.profiles.PROFILES),
                    help="perfil de auditoría (base | ot)")
    ap.add_argument("--html", metavar="ARCHIVO", help="escribe el reporte en HTML")
    ap.add_argument("--json", metavar="ARCHIVO", help="escribe el reporte en JSON")
    ap.add_argument("--no-color", action="store_true", help="salida de terminal sin color")
    ap.add_argument("--quiet", action="store_true", help="no imprime el reporte en terminal")
    args = ap.parse_args(argv)

    profile = haudit.profiles.get(args.profile)
    system = haudit.System()
    results = haudit.run_all(system, profile)

    color = not args.no_color and sys.stdout.isatty()
    if not args.quiet:
        print(report.terminal(results, system, profile, color=color))

    if args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(report.to_html(results, system, profile))
        print(f"[+] Reporte HTML escrito en {args.html}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(report.to_json(results, system, profile))
        print(f"[+] Reporte JSON escrito en {args.json}")

    return 1 if any(r.status == FAIL for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
