#!/usr/bin/env python3
"""Genera los dashboards (Dashboard Studio) y el menú de la app gdat_soc.

Dashboard Studio guarda cada dashboard como XML con la definición JSON dentro.
Generarlo desde aquí garantiza que el JSON es válido.

Ojo: en Dashboard Studio "$" abre un token; las búsquedas de aquí no lo usan.

Uso: python3 scripts/construir_dashboards.py
"""
import json
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
VISTAS = RAIZ / "splunk_app" / "gdat_soc" / "default" / "data" / "ui" / "views"
NAV = RAIZ / "splunk_app" / "gdat_soc" / "default" / "data" / "ui" / "nav"

RANGO = {
    "input_rango": {
        "type": "input.timerange",
        "title": "Rango de tiempo",
        "options": {"token": "rango", "defaultValue": "-24h@h,now"},
    }
}
DEFAULTS = {
    "dataSources": {
        "ds.search": {
            "options": {
                "queryParameters": {
                    "earliest": "$rango.earliest$",
                    "latest": "$rango.latest$",
                }
            }
        }
    }
}


def busqueda(spl):
    return {"type": "ds.search", "options": {"query": spl}}


def panel(tipo, ds, titulo, descripcion=None, opciones=None):
    viz = {"type": tipo, "title": titulo, "dataSources": {"primary": ds}}
    if descripcion:
        viz["description"] = descripcion
    if opciones:
        viz["options"] = opciones
    return viz


def dashboard(titulo, descripcion, fuentes, paneles, filas):
    estructura, y = [], 0
    for alto, elementos in filas:
        x = 0
        for nombre, ancho in elementos:
            estructura.append({"item": nombre, "type": "block",
                               "position": {"x": x, "y": y, "w": ancho, "h": alto}})
            x += ancho
        y += alto
    return {
        "title": titulo,
        "description": descripcion,
        "inputs": RANGO,
        "defaults": DEFAULTS,
        "dataSources": fuentes,
        "visualizations": paneles,
        "layout": {"type": "grid", "options": {}, "globalInputs": ["input_rango"],
                   "structure": estructura},
    }


def a_xml(etiqueta, definicion):
    return (
        '<dashboard version="2" theme="dark">\n'
        f"  <label>{etiqueta}</label>\n"
        f"  <description>{definicion['description']}</description>\n"
        "  <definition><![CDATA[\n"
        f"{json.dumps(definicion, ensure_ascii=False, indent=2)}\n"
        "  ]]></definition>\n"
        "</dashboard>\n"
    )


CORRELACION = (
    'index=gdat_alertas | eval HostEntidad=coalesce(HostCorto, HostOrigen, HostAfectado) '
    '| eval entidad=mvappend('
    'if(isnotnull(CuentaNormalizada) AND CuentaNormalizada!="anonimo", "Account:".CuentaNormalizada, null()), '
    'if(isnotnull(MiembroAnadido), "Account:".MiembroAnadido, null()), '
    'if(isnotnull(IPOrigen) AND IPOrigen!="", "IP:".IPOrigen, null()), '
    'if(isnotnull(HostEntidad), "Host:".HostEntidad, null())) '
    '| mvexpand entidad '
    '| stats dc(regla) AS NumReglas values(regla) AS Alertas by entidad '
    '| where NumReglas > 1 | sort - NumReglas'
)

TIMELINE = (
    '(`gdat_win_security` EventCode IN (4624, 4662, 4688, 4728, 4769)) '
    'OR (index=gdat_cloud sourcetype=gdat:azure:storageblob OperationName=PutBlob) '
    'OR (index=gdat_web "candidate_injection_executed") '
    '| eval Fuente=case(index="gdat_win", "SecurityEvent", index="gdat_cloud", "StorageBlobLogs", index="gdat_web", "NovaShop") '
    '| eval Detalle=case(Fuente="SecurityEvent", EventCode." ".coalesce(TargetUserName, SubjectUserName)." ".coalesce(CommandLine, ServiceName, MemberName, IpAddress, ""), '
    'Fuente="StorageBlobLogs", OperationName." ".Uri." desde ".CallerIpAddress, true(), "SQLi ejecutada") '
    '| eval host=if(Fuente="NovaShop", "novashop", host) '
    '| table _time Fuente host Detalle | sort 0 _time'
)

MITRE = (
    '| inputlookup gdat_mitre.csv '
    '| append [search index=gdat_alertas | stats count AS alertas by mitre | rename mitre AS tecnica] '
    '| stats values(orden) AS orden values(tactica) AS tactica values(nombre_tecnica) AS nombre_tecnica '
    'values(regla) AS regla sum(alertas) AS alertas by tecnica '
    '| where isnotnull(orden) | fillnull value=0 alertas '
    '| eval estado=if(alertas>0, "Detectada", "Sin alertas") '
    '| sort orden | table tactica tecnica nombre_tecnica regla alertas estado'
)


def cadena():
    fuentes = {
        "ds_alertas": busqueda("index=gdat_alertas | stats count"),
        "ds_reglas": busqueda("index=gdat_alertas | stats dc(regla) AS reglas"),
        "ds_incidentes": busqueda(
            "index=gdat_riesgo | stats sum(risk_score) AS puntuacion dc(mitre) AS tecnicas by risk_object "
            "| where puntuacion>=100 AND tecnicas>=2 | stats count"),
        "ds_por_regla": busqueda("index=gdat_alertas | stats count AS alertas by regla | sort regla"),
        "ds_riesgo": busqueda(
            "index=gdat_riesgo | stats sum(risk_score) AS puntuacion dc(mitre) AS tecnicas "
            "values(mitre) AS mitre by risk_object risk_object_type | sort - puntuacion"),
        "ds_entidades": busqueda(CORRELACION),
        "ds_timeline": busqueda(TIMELINE),
        "ds_mitre": busqueda(MITRE),
    }
    paneles = {
        "v_alertas": panel("splunk.singlevalue", "ds_alertas", "Alertas (gdat_alertas)"),
        "v_reglas": panel("splunk.singlevalue", "ds_reglas", "Reglas disparadas (de 8)"),
        "v_incidentes": panel("splunk.singlevalue", "ds_incidentes", "Entidades sobre el umbral RBA",
                              "100 puntos o mas y 2 o mas tecnicas"),
        "v_por_regla": panel("splunk.bar", "ds_por_regla", "Alertas por regla"),
        "v_riesgo": panel("splunk.table", "ds_riesgo", "Riesgo acumulado por entidad (RBA)"),
        "v_entidades": panel("splunk.table", "ds_entidades", "Entidades compartidas entre reglas",
                             "Lo que en Sentinel une las alertas en un incidente"),
        "v_mitre": panel("splunk.table", "ds_mitre", "Cobertura MITRE ATT&CK"),
        "v_timeline": panel("splunk.table", "ds_timeline", "Linea de tiempo del ataque"),
    }
    filas = [
        (130, [("v_alertas", 400), ("v_reglas", 400), ("v_incidentes", 400)]),
        (320, [("v_por_regla", 600), ("v_riesgo", 600)]),
        (300, [("v_entidades", 600), ("v_mitre", 600)]),
        (450, [("v_timeline", 1200)]),
    ]
    return dashboard("GDAT - Cadena de ataque",
                     "SQLi en NovaShop hasta DCSync: alertas, correlacion por entidad, RBA y MITRE.",
                     fuentes, paneles, filas)


def salud():
    fuentes = {
        "ds_ultimo": busqueda(
            "| tstats count latest(_time) AS ultimo WHERE index=gdat_* BY index sourcetype "
            '| eval minutos_desde_ultimo=round((now()-ultimo)/60, 1), ultimo=strftime(ultimo, "%F %T")'),
        "ds_volumen": busqueda(
            "| tstats count WHERE index=gdat_* BY _time index span=5m "
            "| timechart span=5m sum(count) AS eventos by index"),
        "ds_latencia": busqueda(
            "index=gdat_web OR index=gdat_win OR index=gdat_cloud "
            "| eval latencia_s=_indextime-_time "
            "| stats count avg(latencia_s) AS media_s perc95(latencia_s) AS p95_s max(latencia_s) AS max_s by sourcetype "
            "| eval media_s=round(media_s, 1), p95_s=round(p95_s, 1)"),
        "ds_programadas": busqueda(
            'index=_internal sourcetype=scheduler savedsearch_name="GDAT*" '
            "| stats count AS ejecuciones sum(result_count) AS resultados latest(status) AS ultimo_estado "
            "latest(_time) AS ultima by savedsearch_name "
            '| eval ultima=strftime(ultima, "%F %T") | sort savedsearch_name'),
    }
    paneles = {
        "v_ultimo": panel("splunk.table", "ds_ultimo", "Ultimo evento por fuente",
                          "Equivale a validate-soc.sh: que cada tabla reciba datos"),
        "v_volumen": panel("splunk.column", "ds_volumen", "Eventos por indice"),
        "v_latencia": panel("splunk.table", "ds_latencia", "Latencia de ingesta (_indextime - _time)",
                            "Con datos --historico la latencia es alta a proposito: son eventos con fecha pasada"),
        "v_programadas": panel("splunk.table", "ds_programadas", "Ejecuciones de las busquedas GDAT"),
    }
    filas = [
        (280, [("v_ultimo", 600), ("v_latencia", 600)]),
        (300, [("v_volumen", 1200)]),
        (320, [("v_programadas", 1200)]),
    ]
    return dashboard("GDAT - Salud de la ingesta",
                     "Que llega, cuanto tarda y si las busquedas programadas corren.",
                     fuentes, paneles, filas)


NAV_XML = """<nav search_view="search" color="#5E2CA5">
  <view name="gdat_cadena" default="true" />
  <view name="gdat_salud" />
  <view name="search" />
  <collection label="Detecciones">
    <saved source="unclassified" match="GDAT 0" />
  </collection>
  <collection label="Correlacion y RBA">
    <saved source="unclassified" match="GDAT RBA" />
    <saved source="unclassified" match="GDAT COR" />
  </collection>
  <view name="alerts" />
  <view name="reports" />
</nav>
"""


def main():
    VISTAS.mkdir(parents=True, exist_ok=True)
    NAV.mkdir(parents=True, exist_ok=True)
    (VISTAS / "gdat_cadena.xml").write_text(a_xml("GDAT - Cadena de ataque", cadena()), encoding="utf-8")
    (VISTAS / "gdat_salud.xml").write_text(a_xml("GDAT - Salud de la ingesta", salud()), encoding="utf-8")
    (NAV / "default.xml").write_text(NAV_XML, encoding="utf-8")
    print("Escritos gdat_cadena.xml, gdat_salud.xml y nav/default.xml")


if __name__ == "__main__":
    main()
