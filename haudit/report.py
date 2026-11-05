"""Reportes: terminal (con color), HTML (para entregar) y JSON."""
import datetime as dt
import html as _html
import json
from .core import PASS, FAIL, WARN, NA, ERROR, score

STATUS_ORDER = {FAIL: 0, WARN: 1, ERROR: 2, PASS: 3, NA: 4}

_C = {
    PASS: "\033[1;32m", FAIL: "\033[1;31m", WARN: "\033[1;33m",
    NA: "\033[2;37m", ERROR: "\033[1;35m",
    "b": "\033[1m", "dim": "\033[2m", "x": "\033[0m",
}
_LABEL = {PASS: "PASS", FAIL: "FALLA", WARN: "AVISO", NA: "N/A", ERROR: "ERROR"}


def _meta(system, profile):
    osr = system.os_release()
    return {
        "host": system.hostname(),
        "os": osr.get("PRETTY_NAME", osr.get("NAME", "Linux")),
        "kernel": system.kernel(),
        "perfil": profile["name"],
        "framework": profile["framework"],
        "fecha": dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
    }


def _score_color(pct):
    return PASS if pct >= 80 else (WARN if pct >= 50 else FAIL)


# ----------------------------------------------------------------- TERMINAL
def terminal(results, system, profile, color=True):
    c = _C if color else {k: "" for k in _C}
    hl = profile.get("highlight_tags", set())
    m = _meta(system, profile)
    pct, counts = score(results)

    out = []
    out.append(f"\n{c['b']}Auditoría de endurecimiento — {m['host']}{c['x']}")
    out.append(f"{c['dim']}{m['os']} · {m['kernel']}{c['x']}")
    out.append(f"{c['dim']}Perfil: {m['perfil']} · Referencia: {m['framework']} · {m['fecha']}{c['x']}\n")

    # agrupar por categoría
    cats = {}
    for r in results:
        cats.setdefault(r.check.category, []).append(r)
    for cat in sorted(cats):
        out.append(f"{c['b']}{cat}{c['x']}")
        for r in sorted(cats[cat], key=lambda r: (STATUS_ORDER[r.status], r.check.id)):
            star = " ⚡" if hl.intersection(r.check.tags) else ""
            badge = f"{c[r.status]}{_LABEL[r.status]:<5}{c['x']}"
            out.append(f"  [{badge}] {c['dim']}{r.check.id}{c['x']} {r.check.title}{star}")
            if r.status in (FAIL, WARN):
                if r.evidence:
                    out.append(f"          {c['dim']}· {r.evidence}{c['x']}")
                out.append(f"          {c['dim']}→ {r.check.remediation}{c['x']}")
        out.append("")

    sc = c[_score_color(pct)]
    bar_len = 28
    filled = round(bar_len * pct / 100)
    bar = sc + "█" * filled + c['dim'] + "░" * (bar_len - filled) + c['x']
    out.append(f"{c['b']}Puntaje de endurecimiento: {sc}{pct}/100{c['x']}  {bar}")
    out.append(
        f"  {c[PASS]}{counts[PASS]} PASS{c['x']} · "
        f"{c[FAIL]}{counts[FAIL]} fallas{c['x']} · "
        f"{c[WARN]}{counts[WARN]} avisos{c['x']} · "
        f"{c['dim']}{counts[NA]} N/A{c['x']}")
    if profile.get("note"):
        out.append(f"\n{c['dim']}{profile['note']}{c['x']}")
    out.append("")
    return "\n".join(out)


# ----------------------------------------------------------------- JSON
def to_json(results, system, profile):
    pct, counts = score(results)
    return json.dumps({
        "meta": _meta(system, profile),
        "puntaje": pct,
        "resumen": {k: counts[k] for k in (PASS, FAIL, WARN, NA, ERROR)},
        "resultados": [r.to_dict() for r in
                       sorted(results, key=lambda r: (STATUS_ORDER[r.status], r.check.id))],
    }, ensure_ascii=False, indent=2)


# ----------------------------------------------------------------- HTML
_SEV_COLOR = {"critica": "#ff4d6d", "alta": "#ff8c42", "media": "#f2c94c", "baja": "#9aa6bb"}
_ST_COLOR = {PASS: "#00d4a4", FAIL: "#ff4d6d", WARN: "#f2c94c", NA: "#64718a", ERROR: "#9d4edd"}


def to_html(results, system, profile):
    m = _meta(system, profile)
    pct, counts = score(results)
    hl = profile.get("highlight_tags", set())
    ring = _ST_COLOR[_score_color(pct)]

    rows = []
    for r in sorted(results, key=lambda r: (STATUS_ORDER[r.status], r.check.id)):
        star = " ⚡" if hl.intersection(r.check.tags) else ""
        rem = ""
        if r.status in (FAIL, WARN) and r.check.remediation:
            rem = f'<div class="rem"><b>Remediación:</b> {_html.escape(r.check.remediation)}</div>'
        ev = f'<div class="ev">{_html.escape(r.evidence)}</div>' if r.evidence else ""
        rows.append(f"""<tr>
<td><span class="st" style="background:{_ST_COLOR[r.status]}1a;color:{_ST_COLOR[r.status]};border-color:{_ST_COLOR[r.status]}55">{_LABEL[r.status]}</span></td>
<td class="mono">{_html.escape(r.check.id)}</td>
<td><div class="ti">{_html.escape(r.check.title)}{star}</div><div class="cat">{_html.escape(r.check.category)}</div>{ev}{rem}</td>
<td><span class="sev" style="color:{_SEV_COLOR[r.check.severity]}">{r.check.severity}</span></td>
</tr>""")

    return f"""<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Auditoría de endurecimiento — {_html.escape(m['host'])}</title>
<style>
:root{{--bg:#0a0e17;--panel:#111827;--line:rgba(148,163,184,.14);--tx:#e7edf5;--mut:#93a0b4;--acc:#00d4a4}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Inter','Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--tx);padding:40px 20px;line-height:1.5}}
.wrap{{max-width:940px;margin:0 auto}}
.head{{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:20px;border-bottom:1px solid var(--line);padding-bottom:24px;margin-bottom:28px}}
h1{{font-size:24px;font-weight:800;letter-spacing:-.02em}}
.meta{{color:var(--mut);font-size:14px;margin-top:6px}}
.score{{text-align:center}}
.ring{{width:120px;height:120px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-direction:column;
 background:conic-gradient({ring} {pct*3.6}deg, rgba(148,163,184,.15) 0);position:relative}}
.ring::before{{content:"";position:absolute;inset:10px;border-radius:50%;background:var(--bg)}}
.ring b{{position:relative;font-size:34px;font-weight:900;color:{ring}}}
.ring span{{position:relative;font-size:12px;color:var(--mut)}}
.sum{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:26px}}
.pill{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 18px;font-size:14px;font-weight:600}}
.pill b{{font-size:20px;display:block}}
table{{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:14px;overflow:hidden}}
th{{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--mut);padding:12px 16px;border-bottom:1px solid var(--line)}}
td{{padding:14px 16px;border-bottom:1px solid var(--line);vertical-align:top;font-size:14px}}
tr:last-child td{{border-bottom:none}}
.st{{font-size:12px;font-weight:700;padding:4px 10px;border-radius:999px;border:1px solid;white-space:nowrap}}
.mono{{font-family:ui-monospace,Menlo,monospace;color:var(--mut);font-size:13px;white-space:nowrap}}
.ti{{font-weight:600}}.cat{{color:var(--mut);font-size:12.5px;margin-top:2px}}
.ev{{color:var(--mut);font-size:13px;margin-top:8px}}
.rem{{font-size:13px;margin-top:8px;color:#bdeede;background:rgba(0,212,164,.08);border:1px solid rgba(0,212,164,.3);border-radius:10px;padding:9px 12px}}
.sev{{font-weight:700;text-transform:capitalize;font-size:13px}}
.note{{color:var(--mut);font-size:13.5px;margin:22px 0 6px}}
.foot{{color:#64718a;font-size:12.5px;margin-top:26px;text-align:center}}
.foot b{{color:var(--acc)}}
</style></head><body><div class="wrap">
<div class="head">
 <div><h1>Auditoría de endurecimiento</h1>
 <div class="meta">{_html.escape(m['host'])} · {_html.escape(m['os'])}<br>{_html.escape(m['kernel'])}<br>
 Perfil: {_html.escape(m['perfil'])} · {_html.escape(m['framework'])} · {_html.escape(m['fecha'])}</div></div>
 <div class="score"><div class="ring"><b>{pct}</b><span>/ 100</span></div></div>
</div>
<div class="sum">
 <div class="pill" style="color:#00d4a4"><b>{counts[PASS]}</b>Cumple</div>
 <div class="pill" style="color:#ff4d6d"><b>{counts[FAIL]}</b>Fallas</div>
 <div class="pill" style="color:#f2c94c"><b>{counts[WARN]}</b>Avisos</div>
 <div class="pill" style="color:#64718a"><b>{counts[NA]}</b>No aplica</div>
</div>
<table><thead><tr><th>Estado</th><th>ID</th><th>Control</th><th>Sev.</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<div class="note">{_html.escape(profile.get('note',''))}</div>
<div class="foot">Generado con <b>hardening-auditor</b> · UP Security · Contenido de referencia, no reemplaza una auditoría formal.</div>
</div></body></html>"""
