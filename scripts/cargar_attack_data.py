#!/usr/bin/env python3
"""Fase 8: carga datasets reales de splunk/attack_data (Apache-2.0) en gdat_win.

Los eventos se envían tal cual (XmlWinEventLog) al endpoint raw de HEC, para
que Splunk aplique el corte de eventos y la marca de tiempo de props.conf
([XmlWinEventLog] de la app gdat_soc). No se reescribe ni la fecha ni el
contenido: son los eventos originales del dataset.

Contra duplicados: cada dataset se apunta en generador/envios.jsonl con el
run_id "attack_data:<técnica>/<dataset>" y no se reenvía.

Uso:
  python3 -I scripts/cargar_attack_data.py            # descarga (si falta) y carga
  python3 -I scripts/cargar_attack_data.py --simular  # solo descarga y resume
"""
import argparse
import json
import re
import ssl
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
DESCARGAS = RAIZ / "datos_externos" / "attack_data"
REGISTRO = RAIZ / "generador" / "envios.jsonl"
LFS = "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques"

DATASETS = [
    # (técnica, dataset, fichero, regla GDAT que debería verlo)
    ("T1558.003", "kerberoasting_spn_request_with_rc4_encryption", "windows-xml.log", "02 Kerberoasting"),
    ("T1003.006", "mimikatz", "xml-windows-security.log", "07 DCSync"),
    ("T1003.006", "impacket", "windows-security-xml.log", "07 DCSync (cuenta de máquina del DC)"),
]


def leer_env(ruta):
    valores = dict(l.split("=", 1) for l in ruta.read_text().splitlines() if "=" in l and not l.startswith("#"))
    return valores["GDAT_HEC_TOKEN"].strip(), valores["GDAT_HEC_URL"].strip()


def descargar(tecnica, dataset, fichero):
    destino = DESCARGAS / tecnica / dataset / fichero
    if not destino.exists():
        destino.parent.mkdir(parents=True, exist_ok=True)
        url = f"{LFS}/{tecnica}/{dataset}/{fichero}"
        with urllib.request.urlopen(url, timeout=60) as r:
            destino.write_bytes(r.read())
    return destino


def resumen(texto):
    eventos = [e for e in re.split(r"(?=<Event xmlns)", texto) if e.strip()]
    ids = {}
    for e in eventos:
        m = re.search(r"<EventID[^>]*>(\d+)<", e)
        ids[m.group(1) if m else "?"] = ids.get(m.group(1) if m else "?", 0) + 1
    return len(eventos), ids


def enviar_raw(texto, source, token, url):
    params = urllib.parse.urlencode({"index": "gdat_win", "sourcetype": "XmlWinEventLog", "source": source})
    peticion = urllib.request.Request(
        f"{url.rstrip('/')}/services/collector/raw?{params}",
        data=texto.encode("utf-8"),
        headers={"Authorization": "Splunk " + token},
    )
    # HEC local con certificado autofirmado
    with urllib.request.urlopen(peticion, context=ssl._create_unverified_context(), timeout=30) as r:
        datos = json.loads(r.read())
    if datos.get("code") != 0:
        raise SystemExit(f"HEC rechazó {source}: {datos}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--env", default=str(RAIZ / ".env.local"))
    p.add_argument("--simular", action="store_true")
    args = p.parse_args()

    enviados = set()
    if REGISTRO.exists():
        enviados = {json.loads(l)["run_id"] for l in REGISTRO.read_text().splitlines() if l.strip()}

    token = url = None
    if not args.simular:
        token, url = leer_env(Path(args.env))

    for tecnica, dataset, fichero, regla in DATASETS:
        run_id = f"attack_data:{tecnica}/{dataset}"
        texto = descargar(tecnica, dataset, fichero).read_text(encoding="utf-8", errors="replace")
        n, ids = resumen(texto)
        print(f"{run_id}: {n} eventos {ids} → regla {regla}")
        if args.simular:
            continue
        if run_id in enviados:
            print("  ya cargado (generador/envios.jsonl): no se reenvía")
            continue
        enviar_raw(texto, run_id, token, url)
        with REGISTRO.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"run_id": run_id, "modo": "attack_data",
                                "fecha": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                "eventos": ids}) + "\n")
        print("  cargado")


if __name__ == "__main__":
    sys.exit(main())
