# Resultados de las pruebas (fase 4 y 5)

Rellenar tras cada campaña. Horas en UTC. Lo esperado sale de `generador/gdat_generar.py`
(cadena + ruido) y de la SQLi real de NovaShop.

| Regla | Positivo esperado | Negativos que NO deben salir | Resultado | run_id / hora |
|---|---|---|---|---|
| 01 SQLi | `' OR 1=1 -- ` desde 203.0.113.50, `candidate_injection_executed` | Búsquedas normales (`signature_match=false`) | ✅ PASS (real, NovaShop) | 17:25 UTC, SQLi manual |
| 02 Kerberoasting | charlie.dev → svc-sql, RC4 `0x17` | AES `0x12` (svc-web), `krbtgt`, servicio `DC01$` | ✅ PASS | ahora 2ª campaña (~17:55 UTC) |
| 03 Grupo privilegiado | svc-sql añade charlie.dev a Domain Admins (-512) | gdatadmin añade alice.finance a Marketing (-1120) | ✅ PASS | ahora 2ª campaña |
| 04 Exfiltración | 3 PutBlob AccountKey desde 192.0.2.15 → host member01 | IP de admin 198.51.100.10, OAuth, estado 403 | ✅ PASS (1 alerta por campaña) | ahora-20261009T172311Z y 2ª campaña |
| 05 Recursos | ops.temp crea 6 recursos desde 203.0.113.77 | gdatadmin (3 recursos), escritura `Failed` | ✅ PASS | evaluación horaria |
| 06 RDP | charlie.dev tipo 10 desde 203.0.113.50 en MEMBER01 | bob.hr desde IP privada, gdatadmin (excluida), charlie.dev tipo 3 | ✅ PASS | ahora 2ª campaña |
| 07 DCSync | charlie.dev con los GUID de replicación en DC01 | `DC01$`, charlie.dev leyendo otro objeto | ✅ PASS | ahora 2ª campaña |

## Correlación esperada (fase 6)

| Entidad | Reglas que la comparten |
|---|---|
| IP:203.0.113.50 | 01 SQLi, 06 RDP |
| Account:charlie.dev | 02, 03 (miembro añadido), 06, 07 |
| Host:member01 | 04 (por el mapa IP → host), 06 |
| Host:dc01 | 02, 03, 07 |

RBA: charlie.dev, dc01, member01 y 203.0.113.50 deben superar 100 puntos con ≥ 2 técnicas.
svc-sql (solo regla 03) no debe superar el umbral de técnicas.

## Resultado de la campaña del 2026-10-09

- 7/7 reglas disparadas; cada regla generó una sola alerta por campaña, así que el ruido no disparó nada.
- Entidades compartidas: exactamente las cuatro esperadas.
- RBA: 4 entidades sobre el umbral (charlie.dev 280 puntos y 4 técnicas, dc01 240 y 3, member01 200 y 2,
  y 203.0.113.50). member01 suma 200 porque la exfiltración salió en las dos campañas.
- Incidencia: en la 1ª campaña (`ahora-20261009T172311Z`) las reglas de Windows no saltaron porque el source
  `WinEventLog:Security` activaba `[source::WinEventLog...]` (`KV_MODE = none`). Corregido en el generador.
- Evidencia: capturas del dashboard *GDAT - Cadena de ataque*.

## Re-test en modo remediado (fase 2)

Misma SQLi (`' OR 1=1 -- `) desde 203.0.113.50 contra NovaShop:

| Hora (UTC) | Modo | outcome | matched_products |
|---|---|---|---|
| 17:22:56 | vulnerable (`lab_mode=true`) | `candidate_injection_executed` | 6 (catálogo completo) |
| 18:38:38 | remediado (`lab_mode=false`) | `candidate_injection_parameterized` | 0 |

✅ PASS. La consulta parametrizada neutraliza la inyección. La regla 01 sigue registrando el intento,
porque filtra por la firma y no por el resultado (decisión de diseño).

## Fase 8: validación con datos reales (splunk/attack_data, Apache-2.0)

Datasets cargados con `scripts/cargar_attack_data.py` en `gdat_win` (`sourcetype=XmlWinEventLog`), sin
modificar ni el contenido ni las fechas (2024). El parseo es el equivalente mínimo de `Splunk_TA_windows`
incluido en la app. Las reglas son exactamente las mismas que con los datos sintéticos.

| Dataset | Eventos | Regla | Resultado |
|---|---|---|---|
| `T1558.003/kerberoasting_spn_request_with_rc4_encryption` | 1 × 4769 | 02 | ✅ PASS: administrator → KerberoastableUser, `0x17`, 10.0.1.15 |
| `T1003.006/mimikatz` | 10 × 4662, 1 × 4624 | 07 | ✅ PASS: Administrator, 3 replicaciones |
| `T1003.006/impacket` | 6 × 4662, 1 × 4624 | 07 | ⚠️ **FALSO NEGATIVO**: `AR-WIN-DC$` replica desde 10.0.1.30 y la regla lo descarta por terminar en `$` |

**Hallazgo.** Excluir todas las cuentas que terminan en `$` (criterio de la regla 07) evita el
ruido de la replicación legítima entre DCs. Pero también deja pasar un DCSync hecho con la cuenta de
máquina de un DC desde otro equipo. Cruzando el 4662 con el 4624 de su sesión (`SubjectLogonId` =
`TargetLogonId`) se obtiene la IP de origen: 10.0.1.30 no es el DC. Propuesta: regla 07b, que excluya las
cuentas `$` solo cuando la sesión venga de un DC conocido.

## Regla 07b: DCSync con cuenta de máquina (nueva, a partir del hallazgo de la fase 8)

| Datos | Caso | Esperado | Resultado |
|---|---|---|---|
| attack_data `T1003.006/impacket` | `AR-WIN-DC$` replica desde 10.0.1.30 (LogonId 0x335045) | Sale | ✅ PASS (búsqueda manual, All time) |
| attack_data `T1003.006/mimikatz` | `Administrator` (no es cuenta `$`) | No sale (lo cubre la 07) | ✅ PASS |
| Generador | `DC01$` con sesión desde MEMBER01 (10.0.1.5) | Sale | ✅ PASS (alerta en la 3ª campaña, ~19:35 UTC) |
| Generador | `DC01$` con sesión desde el propio DC (10.0.1.4, en `gdat_dcs.csv`) | No sale | ✅ PASS (solo 1 resultado) |
| Generador | `DC01$` sin 4624 (ruido antiguo) | No sale | ✅ PASS |

## Estado final (2026-10-09, ~19:50 UTC)

- **8/8 reglas disparadas** (7 de GDAT + 07b). 15 alertas, todas explicadas (ver README).
- **RBA:** 5 entidades sobre el umbral: charlie.dev, dc01, member01, 203.0.113.50 y 10.0.1.5 (Kerberoasting + 07b).
- **Salud de la ingesta:** todas las fuentes reciben datos y todas las búsquedas terminan en `success`. Latencia de NovaShop
  ~2,6 s de media; la de los sintéticos es ≈0 (±1 s, por la resolución de `_indextime`).

## 4ª campaña (capturas, 19:54 UTC, run_id ahora-20261009T195426Z)

- NovaShop vulnerable + SQLi + generador. ✅ **Cada una de las 8 reglas dio exactamente 1 resultado**, la 05 en su pasada de las 20:00 UTC
  (comprobado en scheduler.log). Ruido: 0 alertas. RBA 00 generó 20 eventos de riesgo. Total acumulado de las 4 campañas: 24 alertas.
