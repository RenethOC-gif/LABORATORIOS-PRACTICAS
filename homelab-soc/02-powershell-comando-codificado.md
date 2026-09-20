# Detección de comandos PowerShell codificados (MITRE ATT&CK T1059.001)

## Objetivo

Simular el uso del flag `-EncodedCommand` de PowerShell — una técnica de evasión común para ocultar comandos de reglas de detección basadas en texto plano — y construir tanto la detección como la decodificación del comando original directamente desde Splunk.

## Arquitectura

Mismo lab de los proyectos anteriores: Splunk (SIEM) + Windows con Sysmon + Universal Forwarder, índice `endpoint`. Ver [detección de fuerza bruta RDP](../01-deteccion-fuerza-bruta-rdp/) para el detalle de la infraestructura.

## Contexto técnico

PowerShell no codifica el texto directamente a Base64. Primero lo convierte a **UTF-16LE** (cada carácter ocupa 2 bytes) y luego aplica Base64 sobre esos bytes. Este detalle es clave más adelante, al intentar leer el comando original.

## Intento inicial (fallido)

El primer atomic probado (`Invoke-AtomicTest T1059.001 -TestNumbers 1`) intentaba ejecutar Mimikatz vía un payload externo (`Invoke-Mimikatz.ps1`), pero falló: Atomic Red Team no descarga automáticamente los payloads externos de cada test, requieren un paso adicional (`-GetPrereqs`) no cumplido en este caso. No fue un problema del lab, sino un prerrequisito faltante del test específico.

## Ejecución

Para tener control total sobre lo que se estaba probando, se generó y ejecutó el comando codificado manualmente en vez de depender de un payload externo:

```powershell
$comando = 'Get-Process | Select-Object -First 5'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($comando)
$codificado = [Convert]::ToBase64String($bytes)
powershell.exe -EncodedCommand $codificado
```

Esto lanza un proceso `powershell.exe` hijo con el flag real `-EncodedCommand` en su línea de comandos, capturado por Sysmon como **Event ID 1**.

## Detección

```spl
index=endpoint EventCode=1 CommandLine="*-EncodedCommand*"
| table _time, ComputerName, User, CommandLine
```

**Qué hace cada línea:**
- `index=endpoint` — restringe la búsqueda al índice donde llegan los logs de este endpoint
- `EventCode=1` — filtra por eventos de creación de proceso (Sysmon)
- `CommandLine="*-EncodedCommand*"` — busca el flag literal en cualquier parte de la línea de comandos; los `*` son comodines
- `| table` — muestra solo las columnas relevantes en vez del evento crudo completo

## Decodificación del comando capturado

Primero, extraer el string Base64 desde el propio evento:

```spl
index=endpoint EventCode=1 CommandLine="*-EncodedCommand*"
| rex field=CommandLine "-EncodedCommand\s+(?<b64>[A-Za-z0-9+/=]+)"
| table _time, ComputerName, b64
```

**Qué hace cada línea:**
- `rex field=CommandLine "..."` — aplica una expresión regular sobre el campo `CommandLine` para extraer solo una parte de él
- `-EncodedCommand\s+` — busca el texto literal `-EncodedCommand` seguido de uno o más espacios
- `(?<b64>[A-Za-z0-9+/=]+)` — captura todo lo que sigue (el alfabeto propio de Base64) en un campo nuevo llamado `b64`

**Problema encontrado:** la función `base64decode()` de `eval` no está disponible en esta instancia de Splunk (*"function is unsupported or undefined"*). Se decodificó el valor externamente en PowerShell en su lugar:

```powershell
[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))
```

Se usó específicamente `Unicode` (UTF-16LE) y no UTF-8 — consistente con cómo PowerShell codifica internamente sus comandos.

## Conclusión

El flag `-EncodedCommand` deja un rastro simple de detectar (un `CommandLine` con ese texto literal). El verdadero reto de esta técnica no es detectarla, sino **leer qué se ejecutó realmente** — y entender que el contenido va codificado en UTF-16LE es lo que marca la diferencia entre solo confirmar "hubo un comando ofuscado" y poder decir exactamente qué hizo.
