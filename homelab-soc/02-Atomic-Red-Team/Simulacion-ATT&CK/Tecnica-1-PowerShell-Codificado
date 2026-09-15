## Técnica 1: PowerShell con comando codificado (T1059.001)

### Qué es y por qué importa

Los atacantes codifican sus comandos de PowerShell en Base64 para evadir reglas de detección simples basadas en texto plano, y para evitar que caracteres especiales (comillas, pipes) rompan la sintaxis al pasar el comando por varias capas (ej. dentro de un script, un macro de Office, etc.). El flag real que usa PowerShell para esto es `-EncodedCommand` (o su forma corta `-enc`).

Es importante notar que PowerShell no convierte el texto a Base64 directamente: primero lo codifica en **UTF-16LE** (cada carácter ocupa 2 bytes) y *después* aplica Base64. Esto se confirma más adelante al intentar decodificar el string capturado.

### Primer intento (fallido) — Test 1: Mimikatz

El primer test de la técnica (`Invoke-AtomicTest T1059.001 -TestNumbers 1`) intentaba ejecutar Mimikatz a través de un payload externo (`Invoke-Mimikatz.ps1`). Falló porque Atomic Red Team no descarga automáticamente los payloads externos de cada test — requieren un paso adicional (`-GetPrereqs`) para obtenerlos. No fue un error de configuración del lab, sino un prerrequisito no cumplido.

### Ejecución — comando codificado real

En vez de depender de un payload externo, se generó y ejecutó un comando codificado manualmente para tener control total sobre lo que se estaba probando:

```powershell
$comando = 'Get-Process | Select-Object -First 5'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($comando)
$codificado = [Convert]::ToBase64String($bytes)
powershell.exe -EncodedCommand $codificado
```

Esto genera un proceso `powershell.exe` hijo con el flag `-EncodedCommand` real en su línea de comandos — capturado por Sysmon como **Event ID 1** (creación de proceso).

### Detección en Splunk

```spl
index=endpoint EventCode=1 CommandLine="*-EncodedCommand*"
| table _time, ComputerName, User, CommandLine
```

**Explicación de la query:**
- `index=endpoint` — busca solo en el índice donde llegan los logs de este endpoint
- `EventCode=1` — filtra por eventos de creación de proceso de Sysmon
- `CommandLine="*-EncodedCommand*"` — busca el flag exacto en cualquier parte de la línea de comandos (los asteriscos son comodines)
- `| table` — muestra solo las columnas relevantes en vez de todo el evento crudo

### Decodificación del comando capturado

Se extrajo el string Base64 directamente desde Splunk:

```spl
index=endpoint EventCode=1 CommandLine="*-EncodedCommand*"
| rex field=CommandLine "-EncodedCommand\s+(?<b64>[A-Za-z0-9+/=]+)"
| table _time, ComputerName, b64
```

**Explicación:**
- `rex field=CommandLine "..."` — aplica una expresión regular sobre el campo `CommandLine` para extraer una parte específica
- `-EncodedCommand\s+` — busca literalmente el texto `-EncodedCommand` seguido de uno o más espacios (`\s+`)
- `(?<b64>[A-Za-z0-9+/=]+)` — captura todo lo que sigue (letras, números, y los símbolos `+ / =` propios de Base64) en un campo nuevo llamado `b64`

**Problema encontrado:** la función `base64decode()` de `eval` no está disponible en esta instancia de Splunk (error *"function is unsupported or undefined"*). En vez de depender de esa función, se decodificó el valor extraído externamente en PowerShell:

```powershell
[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))
```

Se confirmó que el decode debe hacerse con `Unicode` (UTF-16LE) y no UTF-8 — consistente con cómo PowerShell codifica internamente sus comandos, tal como se explicó arriba.

### Conclusión de la técnica

El flag `-EncodedCommand` deja un rastro claro y fácil de detectar en Sysmon. El reto real no está en detectarlo (la query es simple), sino en poder **leer qué se ejecutó realmente** — y ahí es donde entender la codificación UTF-16LE marca la diferencia entre un analista que solo ve "hubo un comando codificado" y uno que puede decir exactamente qué comando fue.

---
