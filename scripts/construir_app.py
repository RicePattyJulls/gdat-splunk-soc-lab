#!/usr/bin/env python3
"""Genera splunk_app/gdat_soc/default/savedsearches.conf a partir de detecciones/*.spl.

Es el equivalente de detections.bicep en GDAT: el SPL vive versionado en
detecciones/ y este script lo empaqueta como alertas programadas. Además añade
las búsquedas de correlación y de RBA ligero, que no salen de un .spl.

Uso: python3 scripts/construir_app.py
"""
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
DETECCIONES = RAIZ / "detecciones"
SALIDA = RAIZ / "splunk_app" / "gdat_soc" / "default" / "savedsearches.conf"

# Severidad de Splunk: 3 low, 4 medium, 5 high, 6 critical
SEVERIDAD = {"low": 3, "medium": 4, "high": 5, "critical": 6}


def leer_deteccion(ruta):
    meta, cuerpo = {}, []
    for linea in ruta.read_text(encoding="utf-8").splitlines():
        if linea.startswith("# ") and ":" in linea and not cuerpo:
            clave, valor = linea[2:].split(":", 1)
            meta[clave.strip()] = valor.strip()
        elif linea.strip():
            cuerpo.append(linea.rstrip())
    faltan = {"nombre", "mitre", "tactica", "severidad", "cron", "ventana", "descripcion"} - meta.keys()
    if faltan:
        raise SystemExit(f"{ruta.name}: faltan metadatos {sorted(faltan)}")
    return meta, cuerpo


def continuar(lineas):
    """Une las líneas de una búsqueda con la continuación de los .conf (' \\')."""
    return " \\\n".join(lineas)


def estrofa(nombre, ajustes):
    salida = [f"[{nombre}]"]
    for clave, valor in ajustes:
        salida.append(f"{clave} = {valor}")
    return "\n".join(salida)


def alerta_desde_spl(ruta):
    meta, cuerpo = leer_deteccion(ruta)
    inicio, fin = meta["ventana"].split()
    registro = (
        f"| `gdat_registrar_alerta({meta['nombre']}, {meta['severidad']}, "
        f"{meta['mitre']}, {meta['tactica']})`"
    )
    return estrofa(meta["nombre"], [
        ("description", f"{meta['descripcion']} MITRE {meta['mitre']}. Origen: {meta['kql']}"),
        ("search", continuar(cuerpo + [registro])),
        ("enableSched", "1"),
        ("cron_schedule", meta["cron"]),
        ("dispatch.earliest_time", inicio),
        ("dispatch.latest_time", fin),
        ("counttype", "number of events"),
        ("relation", "greater than"),
        ("quantity", "0"),
        ("alert.severity", str(SEVERIDAD[meta["severidad"]])),
        ("alert.track", "1"),
        ("alert.digest_mode", "1"),
        # Ventanas contiguas y sin solape: cada evento se evalúa una sola vez,
        # como en Sentinel con la supresión desactivada.
        ("alert.suppress", "0"),
        ("request.ui_dispatch_app", "gdat_soc"),
        ("request.ui_dispatch_view", "search"),
    ])


RBA_EVENTOS = [
    "index=gdat_alertas _index_earliest=-6m@m _index_latest=-1m@m",
    '| eval risk_score=case(severidad="high", 80, severidad="medium", 40, true(), 20)',
    '| eval HostEntidad=coalesce(HostCorto, HostOrigen, HostAfectado)',
    '| eval obj=mvappend('
    'if(isnotnull(CuentaNormalizada) AND CuentaNormalizada!="anonimo", "user|".CuentaNormalizada, null()), '
    'if(isnotnull(MiembroAnadido), "user|".MiembroAnadido, null()), '
    'if(isnotnull(IPOrigen) AND IPOrigen!="", "ip|".IPOrigen, null()), '
    'if(isnotnull(HostEntidad), "system|".HostEntidad, null()))',
    "| mvexpand obj",
    '| eval risk_object_type=mvindex(split(obj, "|"), 0), risk_object=mvindex(split(obj, "|"), 1), risk_message=regla',
    "| table _time risk_object risk_object_type risk_score risk_message regla mitre tactica",
    "| collect index=gdat_riesgo",
]

RBA_UMBRAL = [
    "index=gdat_riesgo",
    "| stats sum(risk_score) AS puntuacion dc(mitre) AS tecnicas values(mitre) AS mitre "
    "values(regla) AS reglas min(_time) AS inicio max(_time) AS fin by risk_object risk_object_type",
    "| where puntuacion>=100 AND tecnicas>=2",
    '| eval inicio=strftime(inicio, "%F %T"), fin=strftime(fin, "%F %T")',
    "| sort - puntuacion",
]

CORRELACION = [
    "index=gdat_alertas",
    "| eval HostEntidad=coalesce(HostCorto, HostOrigen, HostAfectado)",
    '| eval entidad=mvappend('
    'if(isnotnull(CuentaNormalizada) AND CuentaNormalizada!="anonimo", "Account:".CuentaNormalizada, null()), '
    'if(isnotnull(MiembroAnadido), "Account:".MiembroAnadido, null()), '
    'if(isnotnull(IPOrigen) AND IPOrigen!="", "IP:".IPOrigen, null()), '
    'if(isnotnull(HostEntidad), "Host:".HostEntidad, null()))',
    "| mvexpand entidad",
    "| stats dc(regla) AS NumReglas values(regla) AS Alertas min(_time) AS Inicio max(_time) AS Fin by entidad",
    "| where NumReglas > 1",
    '| eval Inicio=strftime(Inicio, "%F %T"), Fin=strftime(Fin, "%F %T")',
    "| sort entidad",
]

TIMELINE = [
    '(`gdat_win_security` EventCode IN (4624, 4662, 4688, 4728, 4769)) '
    'OR (index=gdat_cloud sourcetype=gdat:azure:storageblob OperationName=PutBlob) '
    'OR (index=gdat_web "candidate_injection_executed")',
    '| eval Fuente=case(index="gdat_win", "SecurityEvent", index="gdat_cloud", "StorageBlobLogs", index="gdat_web", "NovaShop")',
    '| eval Detalle=case(Fuente="SecurityEvent", EventCode." ".coalesce(TargetUserName, SubjectUserName)." ".coalesce(CommandLine, ServiceName, MemberName, IpAddress, ""), '
    'Fuente="StorageBlobLogs", OperationName." ".Uri." desde ".CallerIpAddress, '
    'true(), "SQLi ejecutada")',
    # El logging driver de Docker pone el hostname de la máquina; se muestra el nombre del servicio.
    '| eval host=if(Fuente="NovaShop", "novashop", host)',
    "| table _time Fuente host Detalle",
    "| sort 0 _time",
]


def main():
    bloques = [
        "# GENERADO por scripts/construir_app.py a partir de detecciones/*.spl.\n"
        "# No editar a mano: cambia el .spl y vuelve a ejecutar el script.",
    ]
    for ruta in sorted(DETECCIONES.glob("*.spl")):
        bloques.append(alerta_desde_spl(ruta))

    bloques.append(estrofa("GDAT RBA 00 - Eventos de riesgo", [
        ("description", "Convierte cada alerta nueva de gdat_alertas en eventos de riesgo por entidad (indice risk de Splunk ES). High 80, medium 40."),
        ("search", continuar(RBA_EVENTOS)),
        ("enableSched", "1"),
        ("cron_schedule", "*/5 * * * *"),
        ("dispatch.earliest_time", "-24h"),
        ("dispatch.latest_time", "now"),
        ("request.ui_dispatch_app", "gdat_soc"),
        ("request.ui_dispatch_view", "search"),
    ]))
    bloques.append(estrofa("GDAT RBA 01 - Umbral de riesgo", [
        ("description", "El incidente del lab: una entidad suma 100 puntos o mas con 2 o mas tecnicas MITRE en 24 h."),
        ("search", continuar(RBA_UMBRAL)),
        ("enableSched", "1"),
        ("cron_schedule", "*/5 * * * *"),
        ("dispatch.earliest_time", "-24h"),
        ("dispatch.latest_time", "now"),
        ("counttype", "number of events"),
        ("relation", "greater than"),
        ("quantity", "0"),
        ("alert.severity", "6"),
        ("alert.track", "1"),
        ("alert.digest_mode", "0"),
        ("alert.suppress", "1"),
        ("alert.suppress.fields", "risk_object"),
        ("alert.suppress.period", "24h"),
        ("request.ui_dispatch_app", "gdat_soc"),
        ("request.ui_dispatch_view", "search"),
    ]))
    bloques.append(estrofa("GDAT COR - Entidades compartidas", [
        ("description", "Informe: entidades (cuenta, IP, host) que aparecen en mas de una regla. Traduccion de la consulta de correlacion de la fase 10 de GDAT."),
        ("search", continuar(CORRELACION)),
        ("dispatch.earliest_time", "-24h"),
        ("dispatch.latest_time", "now"),
        ("request.ui_dispatch_app", "gdat_soc"),
        ("request.ui_dispatch_view", "search"),
    ]))
    bloques.append(estrofa("GDAT COR - Linea de tiempo", [
        ("description", "Informe: la cadena de ataque ordenada en el tiempo (union de la fase 10 de GDAT)."),
        ("search", continuar(TIMELINE)),
        ("dispatch.earliest_time", "-24h"),
        ("dispatch.latest_time", "now"),
        ("request.ui_dispatch_app", "gdat_soc"),
        ("request.ui_dispatch_view", "search"),
    ]))

    SALIDA.write_text("\n\n".join(bloques) + "\n", encoding="utf-8")
    print(f"Escrito {SALIDA.relative_to(RAIZ)} ({len(bloques) - 1} busquedas)")


if __name__ == "__main__":
    main()
