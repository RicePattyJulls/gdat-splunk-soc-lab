# Equivalencias Sentinel / KQL ↔ Splunk / SPL

Chuleta de equivalencias entre Microsoft Sentinel (KQL) y Splunk (SPL). Cada fila se ha usado al escribir
las reglas de [`detecciones/`](../detecciones/).

## Conceptos

| Sentinel / KQL | Splunk / SPL |
|---|---|
| Workspace de Log Analytics | Instancia de Splunk |
| Tabla (`SecurityEvent`) | `index` + `sourcetype` |
| DCR / AMA / conector | HEC, Universal Forwarder, `props.conf` / `transforms.conf` |
| Transformación en la DCR | `props.conf` (`TRANSFORMS`, `SEDCMD`) o `INGEST_EVAL` |
| Regla Scheduled (frecuencia/periodo) | Alerta programada (`cron_schedule` + `dispatch.earliest_time`/`latest_time`) |
| Regla NRT | Alerta cada minuto con ventana desfasada, o búsqueda en tiempo real (`rt-1m`) |
| Entity mapping | Campos con nombre común (`CuentaNormalizada`, `IPOrigen`, `Host*`); en CIM, `user`/`src`/`dest` |
| Agrupación de alertas en incidente | Correlation search / notable (ES); aquí, índice `gdat_alertas` + búsqueda por entidad |
| Supresión | `alert.suppress` (throttling por campos) |
| Automation rule | Acción de alerta (`logevent`, `webhook`, email); en ES, estado del notable |
| `let x = dynamic([...])` / watchlist | Lookup CSV o macro |
| Función KQL guardada | Macro (`macros.conf`) |
| Workbook | Dashboard (Dashboard Studio) |
| Summary rule | Summary index / `collect` / datamodel acelerado + `tstats` |
| `SecurityAlert` | `index=gdat_alertas` (o `index=notable` en ES) |
| Bicep (`detections.bicep`) | App `gdat_soc` (`savedsearches.conf`, `macros.conf`…) |

### Operadores

| KQL | SPL |
|---|---|
| `T \| where TimeGenerated > ago(1h)` | `index=… earliest=-1h` |
| `where a == "x"` | `search a="x"` o `where a="x"` (con `search` los nombres de campo no distinguen mayúsculas; con `where`, sí) |
| `where a in ("x","y")` | `a IN ("x","y")` |
| `!endswith "$"` | `where NOT like(a, "%$")` |
| `!in~ (...)` | `lookup … \| where isnull(…)` o `NOT a IN (...)` |
| `has` / `has_any` | Término o frase en la búsqueda base: `"texto"`, `("a" OR "b")` |
| `extend` | `eval` |
| `project` | `table` (o `fields`) |
| `summarize count() by x` | `stats count by x` |
| `dcount(x)` / `make_set(x, 10)` | `dc(x)` / `values(x)` + `mvindex(…, 0, 9)` |
| `min()`, `max()`, `sum()` | `min()`, `max()`, `sum()` |
| `parse_json(s)` | `spath input=s` |
| `extract(@"re(…)", 1, s)` | `rex field=s "re(?<campo>…)"` |
| `split(s, ".")[0]` | `mvindex(split(s, "."), 0)` |
| `tolower()` | `lower()` |
| `iff(c, a, b)` | `if(c, a, b)` |
| `replace_string(s, "a", "b")` | `replace(s, "a", "b")` (es una regex: hay que escapar) |
| `ipv4_is_private(ip)` | `cidrmatch("10.0.0.0/8", ip) OR …` (macro `gdat_ip_privada`) |
| `isnotempty(x)` | `isnotnull(x) AND x!=""` |
| `union A, B` | `(index=a …) OR (index=b …)` o `append`/`multisearch` |
| `mv-expand` | `mvexpand` |

### Matices encontrados al escribir las reglas

| KQL | SPL | Matiz |
|---|---|---|
| `endswith "/write"` | `like(lower(x), "%/write")` | `endswith` no distingue mayúsculas; `like()` sí |
| `join ... on $left.SubjectLogonId == $right.TargetLogonId` | `eval LogonId=... \| stats ... by LogonId` | En SPL se prefiere `stats` a `join` (regla 07b) |
| Esquema fijo de la tabla (*schema on write*) | Campos al buscar (*schema on read*) | En `props.conf`, `source::` gana a `sourcetype`: una estrofa de serie `[source::WinEventLog...]` con `KV_MODE = none` anulaba la extracción JSON |
| Función KQL con parámetros | Macro con argumentos | Dentro de la definición, `$` está reservado para los argumentos |
