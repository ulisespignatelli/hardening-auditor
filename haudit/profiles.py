"""Perfiles de auditoría: qué checks correr y con qué marco de referencia."""

PROFILES = {
    "base": {
        "name": "Base (Linux general)",
        "include_tags": {"base"},
        "framework": "CIS Benchmarks",
        "note": "Buenas prácticas generales de endurecimiento para servidores Linux.",
        "highlight_tags": set(),
    },
    "ot": {
        "name": "OT / Infraestructura crítica",
        "include_tags": {"base"},                 # corre todo lo base…
        "framework": "CIS Benchmarks · NIST SP 800-82 · IEC 62443",
        "note": ("Endurecimiento para sistemas en entornos OT. Los controles "
                 "marcados con ⚡ son especialmente críticos en infraestructura "
                 "donde la disponibilidad y la integridad del proceso son prioridad."),
        "highlight_tags": {"ot"},                 # …y resalta los relevantes para OT
    },
}


def get(name):
    return PROFILES.get(name)
