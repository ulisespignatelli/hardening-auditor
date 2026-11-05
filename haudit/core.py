"""Núcleo del auditor: resultados, registro de checks, severidades y puntaje."""

# --- Estados de un check ---
PASS = "PASS"        # cumple la buena práctica
FAIL = "FAIL"        # no cumple (hallazgo)
WARN = "WARN"        # cumple a medias o requiere revisión
NA = "NA"            # no aplica (el componente no está instalado)
ERROR = "ERROR"      # el check no se pudo ejecutar

# --- Severidades y su peso para el puntaje ---
SEVERITY_WEIGHT = {"critica": 10, "alta": 6, "media": 3, "baja": 1}

# Registro global de checks (se llena al importar haudit.checks.*)
REGISTRY = []


class Result:
    __slots__ = ("check", "status", "evidence")

    def __init__(self, check, status, evidence=""):
        self.check = check
        self.status = status
        self.evidence = evidence

    def to_dict(self):
        c = self.check
        return {
            "id": c.id, "titulo": c.title, "categoria": c.category,
            "severidad": c.severity, "tags": c.tags, "estado": self.status,
            "evidencia": self.evidence,
            "remediacion": c.remediation if self.status in (FAIL, WARN) else None,
        }


class Check:
    __slots__ = ("id", "title", "category", "severity", "tags",
                 "rationale", "remediation", "func")

    def __init__(self, func, id, title, category, severity,
                 remediation, rationale="", tags=("base",)):
        assert severity in SEVERITY_WEIGHT, f"severidad inválida: {severity}"
        self.func = func
        self.id = id
        self.title = title
        self.category = category
        self.severity = severity
        self.remediation = remediation
        self.rationale = rationale
        self.tags = list(tags)

    def run(self, system):
        """Ejecuta el check sobre un System y normaliza el retorno a Result."""
        try:
            out = self.func(system)
        except Exception as e:  # un check nunca debe tumbar la corrida completa
            return Result(self, ERROR, f"excepción: {e}")
        if isinstance(out, tuple):
            status, evidence = (out + ("",))[:2]
        else:
            status, evidence = out, ""
        return Result(self, status, evidence)


def check(**meta):
    """Decorador para registrar un check. Uso:

    @check(id="SSH-01", title="...", category="SSH", severity="alta",
           remediation="...", tags=("base","ot"))
    def _(system): -> PASS | FAIL | WARN | NA | (status, evidencia)
    """
    def deco(func):
        REGISTRY.append(Check(func, **meta))
        return func
    return deco


def select(profile):
    """Devuelve los checks que corresponden a un perfil (según sus tags)."""
    tags = set(profile.get("include_tags", {"base"}))
    chosen = [c for c in REGISTRY if tags.intersection(c.tags)]
    chosen.sort(key=lambda c: c.id)
    return chosen


def run_all(system, profile):
    return [c.run(system) for c in select(profile)]


def score(results):
    """Puntaje 0-100 ponderado por severidad. NA/ERROR no cuentan.
    WARN vale medio crédito."""
    got = 0.0
    total = 0.0
    counts = {PASS: 0, FAIL: 0, WARN: 0, NA: 0, ERROR: 0}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
        if r.status in (NA, ERROR):
            continue
        w = SEVERITY_WEIGHT[r.check.severity]
        total += w
        if r.status == PASS:
            got += w
        elif r.status == WARN:
            got += w * 0.5
    pct = round(100 * got / total) if total else 0
    return pct, counts
