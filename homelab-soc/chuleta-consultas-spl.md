# Chuleta de Consultas SPL para Análisis SOC

Consultas organizadas por categoría, cada una explicada — no solo copiada. Basado en el trabajo propio de este homelab más patrones documentados por analistas SOC y repositorios de threat hunting de la comunidad (Splunk ThreatHunting App, Splunk Security Essentials, y compilaciones de queries usadas en investigaciones reales).

---

## 1. Búsqueda y filtrado básico

```spl
index=endpoint sourcetype="WinEventLog:Security"
```
Punto de partida de casi cualquier búsqueda: acota por índice y, si hace falta, por `sourcetype` para no mezclar logs de distinto origen (Security, Sysmon, firewall, etc.).

```spl
index=endpoint EventCode=4625 OR EventCode=4624
```
Combina múltiples códigos de evento en una sola búsqueda con `OR`. Útil para comparar fallos (`4625`) contra éxitos (`4624`) de inicio de sesión en la misma consulta.

```spl
index=endpoint NOT user=SYSTEM
```
`NOT` excluye resultados — en este caso, filtra el ruido de actividad generada por la propia cuenta de sistema, muy común al analizar procesos.

```spl
index=endpoint earliest=-24h@h latest=now
```
Controla la ventana de tiempo directamente en la query en vez del selector visual — útil quando guardas la búsqueda como alerta programada. `@h` redondea a la hora exacta más cercana (evita minutos sueltos que compliquen la lectura).

---

## 2. Estadísticas y agregación (`stats`)

```spl
index=endpoint EventCode=4625
| stats count by src_ip
| sort -count
```
`stats count by <campo>` es probablemente el comando más usado en un SOC: cuenta ocurrencias agrupadas por un campo. `sort -count` ordena de mayor a menor (el `-` invierte el orden).

```spl
index=endpoint EventCode=4625
| stats count by user, src_ip
| where count > 5
```
Agrupar por **dos campos** a la vez (usuario + IP origen) es el patrón clásico de detección de fuerza bruta — permite ver exactamente qué cuenta fue atacada desde qué origen, no solo un conteo global.

```spl
index=endpoint
| stats dc(dest_ip) as ips_distintas by src_ip
```
`dc()` (distinct count) cuenta valores **únicos**, no el total de eventos. Muy usado para detectar escaneo de red: una IP origen tocando muchas IPs destino distintas en poco tiempo es señal de reconocimiento activo.

```spl
index=endpoint
| stats earliest(_time) as primera_vez, latest(_time) as ultima_vez by user
```
`earliest()` y `latest()` dentro de `stats` (no confundir con los modificadores de tiempo de búsqueda) devuelven el primer y último timestamp de cada grupo — útil para ver cuánto duró una sesión o una campaña de actividad sospechosa.

---

## 3. Extracción de campos con expresiones regulares (`rex`)

```spl
index=endpoint CommandLine="*-enc*"
| rex field=CommandLine "-enc(odedCommand)?\s+(?<b64>[A-Za-z0-9+/=]+)"
```
`rex` extrae texto de un campo usando una expresión regular y lo guarda en un campo nuevo (aquí, `b64`). Es la herramienta principal cuando el dato que buscas está "escondido" dentro de un campo más largo, como un argumento dentro de una línea de comandos completa.

```spl
index=endpoint sourcetype=pan:traffic
| rex field=_raw "src=(?<src_ip>\d+\.\d+\.\d+\.\d+)"
```
Ejemplo típico contra logs de firewall (formato `campo=valor` sin parsear): extrae la IP origen directamente del texto crudo (`_raw`) cuando el campo no viene ya separado por Splunk.

---

## 4. Series de tiempo y tendencias

```spl
index=endpoint EventCode=4625
| timechart span=1h count by src_ip
```
`timechart` convierte los resultados en una serie temporal — imprescindible para ver **cuándo** ocurrió la actividad, no solo cuánta hubo. `span=1h` agrupa en buckets de una hora.

```spl
index=endpoint
| bucket _time span=10m
| stats count by _time, user
```
Alternativa a `timechart` cuando necesitas más control sobre cómo se agrupan los resultados después — `bucket` redondea el timestamp a intervalos fijos antes de aplicar `stats`.

---

## 5. `eval` — crear y transformar campos

```spl
index=endpoint EventCode=4625
| eval hora_local=strftime(_time, "%Y-%m-%d %H:%M:%S")
```
`eval` crea un campo nuevo calculado. `strftime()` convierte el timestamp interno de Splunk (epoch) a un formato de fecha legible.

```spl
index=endpoint
| eval riesgo=case(
    count > 20, "Alto",
    count > 5, "Medio",
    1=1, "Bajo")
```
`case()` dentro de `eval` funciona como un if/elif/else — muy usado para clasificar resultados en categorías (severidad, prioridad) directamente en la query, antes de mandarlos a una alerta o dashboard.

---

## 6. `transaction` — agrupar eventos relacionados

```spl
index=endpoint user=*
| transaction user maxspan=5m
```
Agrupa eventos separados que pertenecen a la misma "sesión" lógica (mismo usuario, dentro de una ventana de 5 minutos) en un solo resultado. Útil para reconstruir una secuencia de acciones de un mismo actor, aunque hay que usarlo con cuidado — es un comando costoso en instancias grandes.

---

## 7. Subsearches — cruzar datos entre índices o listas

```spl
index=firewall action=blocked
[search index=threatintel | fields ip | rename ip as dest_ip]
```
Una subsearch (entre corchetes) ejecuta una búsqueda interna primero y usa su resultado como filtro de la búsqueda externa — aquí, cruza logs de firewall contra una lista de IPs maliciosas conocidas. Es potente pero puede ser lento si la subsearch devuelve muchos resultados; en producción se prefiere `lookup` para listas grandes.

---

## 8. `tstats` — búsquedas aceleradas sobre datos indexados

```spl
| tstats count where index=endpoint by _time span=1h, EventCode
```
`tstats` es mucho más rápido que una búsqueda normal porque opera directamente sobre los metadatos indexados (útil en instancias grandes con Data Models acelerados). En un homelab pequeño la diferencia no se nota, pero es importante conocerlo porque en un entorno empresarial real es el estándar para dashboards de alto volumen.

---

## 9. Consultas de referencia por caso de uso común

| Objetivo | Query base |
|---|---|
| Fuerza bruta (fallos repetidos) | `EventCode=4625 \| stats count by user, src_ip \| where count > 5` |
| Login exitoso tras fuerza bruta | `(EventCode=4625 OR EventCode=4624) \| transaction user maxspan=10m \| where eventcount > 1` |
| Proceso hijo sospechoso de Office | `ParentImage="*winword.exe" OR ParentImage="*excel.exe" \| search Image="*powershell.exe" OR Image="*cmd.exe"` |
| PowerShell codificado | `CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*"` |
| Creación de tareas programadas | `Image="*schtasks.exe" OR CommandLine="*Register-ScheduledTask*"` |
| Acceso a memoria de LSASS | `EventCode=10 TargetImage="*lsass.exe"` |
| Conexión saliente a puerto inusual | `sourcetype=pan:traffic \| stats count by dest_port \| sort -count` |
| Nueva cuenta creada | `EventCode=4720` |
| Cuenta agregada a grupo privilegiado | `EventCode=4728 OR EventCode=4732` |
| Borrado de logs de eventos (anti-forense) | `EventCode=1102` |

---

## 10. Buenas prácticas (de guías de threat hunting de la comunidad)

- **Empieza amplio, luego reduce**: primero confirma que el índice y sourcetype tienen datos (`index=endpoint \| head 10`), después añade filtros — buscar demasiado específico desde el inicio puede ocultar que el problema real es que los logs no están llegando.
- **`fields` antes que `table` en instancias grandes**: `| fields campo1, campo2` reduce la cantidad de datos que Splunk mueve internamente antes de mostrarlos; `table` solo cambia la presentación final.
- **Cuidado con `transaction`**: es intuitivo pero costoso en rendimiento — para instancias con mucho volumen, `stats` con `earliest()`/`latest()` suele lograr lo mismo de forma más eficiente.
- **Prioriza `tstats` sobre Data Models acelerados** cuando trabajes con datasets grandes en un entorno real — la diferencia de velocidad es considerable frente a una búsqueda normal.

## Fuentes consultadas

- Splunk ThreatHunting App y Splunk Security Essentials (apps oficiales de Splunk para threat hunting)
- Compilaciones de queries de la comunidad de SOC analysts (repositorios públicos de SPL para detección basada en MITRE ATT&CK)
- Documentación oficial de Splunk SPL (comandos `stats`, `eval`, `rex`, `tstats`, `transaction`)
