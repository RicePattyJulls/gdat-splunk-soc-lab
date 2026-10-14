#!/usr/bin/env python3
"""Generador sintético de la cadena GDAT para Splunk (HEC).

Simula la telemetría que en GDAT venía de Windows (SecurityEvent), de Storage
(StorageBlobLogs) y de Azure Activity. La SQLi NO se simula: la produce
NovaShop de verdad (scripts/novashop.sh).

Los eventos usan los nombres de campo nativos de Windows (EventCode,
TargetUserName, IpAddress...), así que el SPL de detecciones/ sirve también
para XmlWinEventLog real con Splunk_TA_windows.

Modos:
  --modo ahora      Campaña en vivo: cada paso se envía con la hora actual y
                    espera --ritmo segundos. Es el modo que hace saltar las
                    alertas programadas.
  --modo historico  Toda la cadena de golpe, con fechas pasadas y su ritmo
                    real (unos 35 min). Sirve para la línea de tiempo; las
                    alertas programadas no la ven porque ya pasó su ventana.
  --simular         No envía nada: enseña el resumen y un evento de ejemplo.

Contra duplicados: cada ejecución tiene un run_id que va en todos los eventos
y se apunta en generador/envios.jsonl. Un run_id repetido no se reenvía.

Solo biblioteca estándar. El token se lee de .env.local y nunca se imprime.
"""
import argparse
import json
import ssl
import sys
import time
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
REGISTRO = Path(__file__).resolve().parent / "envios.jsonl"

# Entidades del laboratorio. IPs de documentación (RFC 5737).
ATACANTE = "203.0.113.50"
IP_ADMIN = "198.51.100.10"
MEMBER_PUBLICA = "192.0.2.15"
MEMBER_PRIVADA = "10.0.1.5"
DC_PRIVADA = "10.0.1.4"
OTRO_PRIVADO = "10.0.1.20"
IP_CLOUD_INTRUSO = "203.0.113.77"
DOMINIO = "novashop.local"
NETBIOS = "NOVASHOP"
SID_DOMINIO = "S-1-5-21-1004336348-1177238915-682003330"
DC = f"DC01.{DOMINIO}"
MEMBER = f"MEMBER01.{DOMINIO}"
STORAGE = "gdatstorage"
SUSCRIPCION = "00000000-0000-0000-0000-000000000000"

REPLICACION = "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"
CLASE_DOMINIO = "{19195a5b-6da0-11d0-afd3-00c04fd930c9}"


def leer_env(ruta):
    valores = {}
    for linea in ruta.read_text(encoding="utf-8").splitlines():
        if "=" in linea and not linea.lstrip().startswith("#"):
            clave, valor = linea.split("=", 1)
            valores[clave.strip()] = valor.strip()
    for clave in ("GDAT_HEC_TOKEN", "GDAT_HEC_URL"):
        if not valores.get(clave):
            raise SystemExit(f"Falta {clave} en {ruta}")
    return valores


class Constructor:
    """Crea eventos HEC con run_id; la hora la pone quien envía."""

    def __init__(self, run_id):
        self.run_id = run_id

    def _hec(self, index, sourcetype, source, host, campos):
        return {"index": index, "sourcetype": sourcetype, "source": source,
                "host": host, "event": {**campos, "run_id": self.run_id}}

    def win(self, equipo, codigo, **campos):
        base = {"EventCode": codigo, "Computer": equipo, "Channel": "Security",
                "Keywords": "Audit Success", "TaskCategory": TAREAS.get(codigo, "")}
        # El source NO puede empezar por "WinEventLog": system/default/props.conf trae
        # [source::WinEventLog...] con KV_MODE = none, y las estrofas source:: ganan a
        # las de sourcetype, así que anularía el KV_MODE = json y no habría campos.
        return self._hec("gdat_win", "gdat:win:security", "gdat:SecurityEvent",
                         equipo.split(".")[0], {**base, **campos})

    def blob(self, ip_puerto, autenticacion, estado, fichero, tamano, usuario_agente):
        return self._hec("gdat_cloud", "gdat:azure:storageblob", "StorageBlobLogs", STORAGE, {
            "OperationName": "PutBlob", "Category": "StorageWrite", "AccountName": STORAGE,
            "AuthenticationType": autenticacion, "StatusCode": estado,
            "StatusText": "Success" if estado == 201 else "AuthorizationFailure",
            "CallerIpAddress": ip_puerto,
            "Uri": f"https://{STORAGE}.blob.core.windows.net/exfil/{fichero}",
            "RequestBodySize": tamano, "UserAgentHeader": usuario_agente,
        })

    def actividad(self, llamante, ip, operacion, recurso, estado="Success"):
        partes = operacion.split("/")
        proveedor, tipo = partes[0], "/".join(partes[1:-1])
        return self._hec("gdat_cloud", "gdat:azure:activity", "AzureActivity", "azure", {
            "Caller": llamante, "CallerIpAddress": ip, "CategoryValue": "Administrative",
            "OperationNameValue": operacion.upper(), "ActivityStatusValue": estado,
            "ResourceGroup": "rg-temp",
            "ResourceId": f"/subscriptions/{SUSCRIPCION}/resourceGroups/rg-temp/providers/"
                          f"{proveedor}/{tipo}/{recurso}",
            "SubscriptionId": SUSCRIPCION, "Level": "Informational",
        })


TAREAS = {4624: "Logon", 4662: "Directory Service Access", 4688: "Process Creation",
          4728: "Security Group Management", 4769: "Kerberos Service Ticket Operations"}


def escenario(c):
    """Devuelve [(segundos desde el inicio, nombre del paso, [eventos])]."""
    pasos = []

    # --- Ruido de fondo: actividad normal que ninguna regla debe marcar ---
    pasos.append((0, "Ruido de fondo (negativos esperados)", [
        c.win(MEMBER, 4624, TargetUserName="alice.finance", TargetDomainName=NETBIOS,
              LogonType=3, IpAddress=OTRO_PRIVADO, IpPort="50112", LogonProcessName="NtLmSsp",
              AuthenticationPackageName="NTLM", WorkstationName="WS-ALICE"),
        c.win(MEMBER, 4624, TargetUserName="bob.hr", TargetDomainName=NETBIOS,
              LogonType=10, IpAddress=DC_PRIVADA, IpPort="50200", LogonProcessName="User32",
              AuthenticationPackageName="Negotiate", WorkstationName="DC01"),
        c.win(MEMBER, 4624, TargetUserName="gdatadmin", TargetDomainName=NETBIOS,
              LogonType=10, IpAddress=IP_ADMIN, IpPort="51022", LogonProcessName="User32",
              AuthenticationPackageName="Negotiate", WorkstationName="ADMIN-PC"),
        c.win(MEMBER, 4624, TargetUserName="charlie.dev", TargetDomainName=NETBIOS,
              LogonType=3, IpAddress=ATACANTE, IpPort="40110", LogonProcessName="NtLmSsp",
              AuthenticationPackageName="NTLM", WorkstationName="WS-ATK"),
        c.win(DC, 4769, TargetUserName=f"alice.finance@{DOMINIO.upper()}", TargetDomainName=DOMINIO.upper(),
              ServiceName="svc-web", TicketEncryptionType="0x12", TicketOptions="0x40810000",
              IpAddress=f"::ffff:{OTRO_PRIVADO}", IpPort="50300", Status="0x0"),
        c.win(DC, 4769, TargetUserName=f"bob.hr@{DOMINIO.upper()}", TargetDomainName=DOMINIO.upper(),
              ServiceName="krbtgt", TicketEncryptionType="0x17", TicketOptions="0x60810010",
              IpAddress=f"::ffff:{OTRO_PRIVADO}", IpPort="50301", Status="0x0"),
        c.win(DC, 4769, TargetUserName=f"MEMBER01$@{DOMINIO.upper()}", TargetDomainName=DOMINIO.upper(),
              ServiceName="DC01$", TicketEncryptionType="0x17", TicketOptions="0x40810000",
              IpAddress=f"::ffff:{MEMBER_PRIVADA}", IpPort="50302", Status="0x0"),
        c.win(DC, 4662, SubjectUserName="DC01$", SubjectDomainName=NETBIOS, ObjectServer="DS",
              ObjectType=f"%{CLASE_DOMINIO}", OperationType="Object Access", AccessMask="0x100",
              Properties=f"%%7688 {REPLICACION} {CLASE_DOMINIO}"),
        c.win(DC, 4624, TargetUserName="DC01$", TargetDomainName=NETBIOS, TargetLogonId="0x3e7a1",
              LogonType=3, IpAddress=DC_PRIVADA, IpPort="49702", LogonProcessName="Kerberos",
              AuthenticationPackageName="Kerberos", WorkstationName="-"),
        c.win(DC, 4662, SubjectUserName="DC01$", SubjectDomainName=NETBIOS, SubjectLogonId="0x3e7a1",
              ObjectServer="DS", ObjectType=f"%{CLASE_DOMINIO}", OperationType="Object Access",
              AccessMask="0x100", Properties=f"%%7688 {REPLICACION} {CLASE_DOMINIO}"),
        c.win(DC, 4662, SubjectUserName="charlie.dev", SubjectDomainName=NETBIOS, ObjectServer="DS",
              ObjectType="%{bf967aba-0de6-11d0-a285-00aa003049e2}", OperationType="Object Access",
              AccessMask="0x10", Properties="%%7684 {bf967aba-0de6-11d0-a285-00aa003049e2}"),
        c.win(DC, 4728, SubjectUserName="gdatadmin", SubjectDomainName=NETBIOS,
              MemberName="CN=alice.finance,CN=Users,DC=novashop,DC=local",
              MemberSid=f"{SID_DOMINIO}-1105", TargetUserName="Marketing",
              TargetDomainName=NETBIOS, TargetSid=f"{SID_DOMINIO}-1120"),
        c.blob(f"{IP_ADMIN}:52011", "AccountKey", 201, "backup/inventario.csv", 18_432, "AzCopy/10.26.0"),
        c.blob(f"{MEMBER_PUBLICA}:52012", "OAuth", 201, "backup/nominas.csv", 22_016, "azsdk-python-storage-blob/12.19.0"),
        c.blob(f"{MEMBER_PUBLICA}:52013", "AccountKey", 403, "Datos_Financieros_prueba.zip", 512, "azsdk-python-storage-blob/12.19.0"),
        *[c.actividad(f"gdatadmin@{DOMINIO}", IP_ADMIN, op, nombre) for op, nombre in [
            ("Microsoft.Web/sites/write", "novashop-app"),
            ("Microsoft.Storage/storageAccounts/write", STORAGE),
            ("Microsoft.Insights/diagnosticSettings/write", "diag-novashop"),
        ]],
        c.actividad(f"ops.temp@{DOMINIO}", IP_CLOUD_INTRUSO,
                    "Microsoft.Compute/virtualMachines/write", "vm-fallida", estado="Failed"),
    ]))

    # --- La cadena (mismas entidades que GDAT) ---
    pasos.append((300, "RDP de charlie.dev a MEMBER01 desde la IP del atacante", [
        c.win(MEMBER, 4624, TargetUserName="charlie.dev", TargetDomainName=NETBIOS,
              TargetUserSid=f"{SID_DOMINIO}-1104", LogonType=10, IpAddress=ATACANTE,
              IpPort="40222", LogonProcessName="User32", AuthenticationPackageName="Negotiate",
              WorkstationName="WS-ATK"),
    ]))
    pasos.append((420, "Reconocimiento en MEMBER01 (4688)", [
        c.win(MEMBER, 4688, SubjectUserName="charlie.dev", SubjectDomainName=NETBIOS,
              NewProcessName=f"C:\\Windows\\System32\\{exe}", CommandLine=linea,
              ParentProcessName="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
        for exe, linea in [
            ("whoami.exe", "whoami /groups"),
            ("net.exe", "net user /domain"),
            ("net.exe", 'net group "Domain Admins" /domain'),
            ("setspn.exe", "setspn -Q */*"),
        ]
    ]))
    pasos.append((540, "Kerberoasting de svc-sql (4769 RC4)", [
        c.win(DC, 4769, TargetUserName=f"charlie.dev@{DOMINIO.upper()}", TargetDomainName=DOMINIO.upper(),
              ServiceName="svc-sql", ServiceSid=f"{SID_DOMINIO}-1110", TicketEncryptionType="0x17",
              TicketOptions="0x40810000", IpAddress=f"::ffff:{MEMBER_PRIVADA}", IpPort="50410",
              Status="0x0"),
    ]))
    pasos.append((900, "svc-sql anade a charlie.dev a Domain Admins (4728)", [
        c.win(DC, 4728, SubjectUserName="svc-sql", SubjectDomainName=NETBIOS,
              MemberName="CN=charlie.dev,CN=Users,DC=novashop,DC=local",
              MemberSid=f"{SID_DOMINIO}-1104", TargetUserName="Domain Admins",
              TargetDomainName=NETBIOS, TargetSid=f"{SID_DOMINIO}-512"),
    ]))
    pasos.append((1200, "Exfiltracion de Datos_Financieros a Storage con AccountKey", [
        c.blob(f"{MEMBER_PUBLICA}:{50500 + i}", "AccountKey", 201,
               f"Datos_Financieros_parte{i}.zip", tamano, "azsdk-python-storage-blob/12.19.0")
        for i, tamano in enumerate([4_194_304, 4_194_304, 1_572_864], start=1)
    ]))
    pasos.append((1500, "DCSync de charlie.dev (4662 con derechos de replicacion)", [
        c.win(DC, 4662, SubjectUserName="charlie.dev", SubjectDomainName=NETBIOS,
              SubjectUserSid=f"{SID_DOMINIO}-1104", ObjectServer="DS",
              ObjectType=f"%{CLASE_DOMINIO}", ObjectName="%{8f2a6c1e-3b7d-4e19-9c55-2d1a7e6b4f03}",
              OperationType="Object Access", AccessMask="0x100",
              Properties=f"%%7688 {guid} {CLASE_DOMINIO}")
        for guid in ("{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}", "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}")
    ]))

    pasos.append((1650, "DCSync con el hash de DC01$ desde MEMBER01 (regla 07b)", [
        c.win(DC, 4624, TargetUserName="DC01$", TargetDomainName=NETBIOS, TargetLogonId="0x5a3f21",
              LogonType=3, IpAddress=MEMBER_PRIVADA, IpPort="51877", LogonProcessName="NtLmSsp",
              AuthenticationPackageName="NTLM", WorkstationName="-"),
        *[c.win(DC, 4662, SubjectUserName="DC01$", SubjectDomainName=NETBIOS, SubjectLogonId="0x5a3f21",
                ObjectServer="DS", ObjectType=f"%{CLASE_DOMINIO}", OperationType="Object Access",
                AccessMask="0x100", Properties=f"%%7688 {guid} {CLASE_DOMINIO}")
          for guid in ("{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}", "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}")],
    ]))

    # --- Escenario independiente de la regla 05 (como en la fase 10 de GDAT) ---
    pasos.append((1800, "Rafaga de creacion de recursos por ops.temp (6 recursos)", [
        c.actividad(f"ops.temp@{DOMINIO}", IP_CLOUD_INTRUSO, op, nombre) for op, nombre in [
            ("Microsoft.Network/virtualNetworks/write", "vnet-temp"),
            ("Microsoft.Network/networkSecurityGroups/write", "nsg-temp"),
            ("Microsoft.Network/publicIPAddresses/write", "pip-mineria01"),
            ("Microsoft.Network/networkInterfaces/write", "nic-mineria01"),
            ("Microsoft.Compute/disks/write", "disk-mineria01"),
            ("Microsoft.Compute/virtualMachines/write", "vm-mineria01"),
        ]
    ]))
    return pasos


def enviar(eventos, env):
    cuerpo = "".join(json.dumps(e, ensure_ascii=False) for e in eventos).encode("utf-8")
    peticion = urllib.request.Request(
        env["GDAT_HEC_URL"].rstrip("/") + "/services/collector/event",
        data=cuerpo,
        headers={"Authorization": "Splunk " + env["GDAT_HEC_TOKEN"],
                 "Content-Type": "application/json"},
    )
    # HEC local con certificado autofirmado: solo se desactiva la verificación aquí.
    contexto = ssl._create_unverified_context()
    with urllib.request.urlopen(peticion, context=contexto, timeout=15) as respuesta:
        datos = json.loads(respuesta.read())
    if datos.get("code") != 0:
        raise SystemExit(f"HEC rechazó el envío: {datos}")


def run_ids_enviados():
    if not REGISTRO.exists():
        return set()
    return {json.loads(l)["run_id"] for l in REGISTRO.read_text().splitlines() if l.strip()}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--modo", choices=["ahora", "historico"], default="ahora")
    p.add_argument("--ritmo", type=float, default=20.0,
                   help="segundos entre pasos en modo ahora (por defecto 20)")
    p.add_argument("--inicio", help="modo historico: inicio en UTC, p. ej. 2026-10-09T10:00 (por defecto, hace 2 h)")
    p.add_argument("--run-id", help="identificador de la ejecución (por defecto, modo + fecha)")
    p.add_argument("--env", default=str(RAIZ / ".env.local"), help="fichero con GDAT_HEC_TOKEN y GDAT_HEC_URL")
    p.add_argument("--simular", action="store_true", help="no envía nada")
    args = p.parse_args()

    ahora = datetime.now(timezone.utc)
    run_id = args.run_id or f"{args.modo}-{ahora:%Y%m%dT%H%M%SZ}"
    if run_id in run_ids_enviados():
        raise SystemExit(f"run_id {run_id} ya se envió (generador/envios.jsonl). No se reenvía.")

    pasos = escenario(Constructor(run_id))
    total = Counter()
    for _, _, eventos in pasos:
        total.update(e["sourcetype"] for e in eventos)

    if args.simular:
        print(f"run_id: {run_id} · modo: {args.modo}")
        for segundos, nombre, eventos in pasos:
            print(f"  +{segundos:>5}s  {len(eventos):>2} ev  {nombre}")
        print("Totales:", dict(total))
        print("Ejemplo:", json.dumps(pasos[1][2][0], ensure_ascii=False))
        return

    env = leer_env(Path(args.env))
    if args.modo == "historico":
        inicio = (datetime.fromisoformat(args.inicio).replace(tzinfo=timezone.utc)
                  if args.inicio else ahora - timedelta(hours=2))
        lote = []
        for segundos, _, eventos in pasos:
            for desfase, e in enumerate(eventos):
                e["time"] = round((inicio + timedelta(seconds=segundos + desfase)).timestamp(), 3)
                lote.append(e)
        enviar(lote, env)
        print(f"Enviados {len(lote)} eventos con fechas desde {inicio:%Y-%m-%d %H:%M} UTC")
    else:
        for numero, (_, nombre, eventos) in enumerate(pasos, start=1):
            marca = time.time()
            for e in eventos:
                e["time"] = round(marca, 3)
            enviar(eventos, env)
            print(f"[{datetime.now():%H:%M:%S}] {numero}/{len(pasos)} {nombre} ({len(eventos)} ev)", flush=True)
            if numero < len(pasos):
                time.sleep(args.ritmo)

    with REGISTRO.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"run_id": run_id, "modo": args.modo,
                            "fecha": ahora.isoformat(timespec="seconds"),
                            "eventos": dict(total)}) + "\n")
    print(f"run_id {run_id} registrado. Comprobación en Splunk:")
    print(f'  index=gdat_* run_id="{run_id}" | stats count by index sourcetype')


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("Interrumpido: el run_id NO se registró; revisa en Splunk qué llegó antes de repetir.")
