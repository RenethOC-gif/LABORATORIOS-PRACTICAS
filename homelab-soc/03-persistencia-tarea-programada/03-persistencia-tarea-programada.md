# Detección de persistencia vía tarea programada (MITRE ATT&CK T1053.005)

## Objetivo

Simular la creación de tareas programadas maliciosas — una técnica de persistencia común, precisamente porque las tareas programadas legítimas (backups, actualizaciones) son parte normal de cualquier sistema Windows — y detectarla usando la cadena de procesos padre-hijo como principal indicador de sospecha.

## Arquitectura

Mismo lab de los proyectos anteriores. Ver [detección de fuerza bruta RDP](../01-deteccion-fuerza-bruta-rdp/) para el detalle de la infraestructura.

## Test ejecutado

`Invoke-AtomicTest T1053.005 -TestNumbers 1` ("Scheduled Task Startup Script"):

```
schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"
schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"
```

**Desglose de parámetros:**

| Parámetro | Significado |
|---|---|
| `/tn` | Task Name — nombre con el que queda registrada la tarea |
| `/sc onlogon` | Dispara la tarea cada vez que alguien inicia sesión |
| `/sc onstart` | Dispara al arrancar el sistema, antes de que exista cualquier sesión |
| `/ru system` | La tarea corre con privilegios de `SYSTEM`, el nivel más alto de Windows |
| `/tr` | Task to Run — el comando real que ejecuta la tarea (aquí, `calc.exe` como sustituto inofensivo de lo que en un ataque real sería un payload malicioso) |

La segunda tarea es la más peligrosa: al correr como `SYSTEM` y dispararse antes de cualquier inicio de sesión, sobrevive a un reinicio completo del sistema sin depender de que nadie se autentique.

## Detección

```spl
index=endpoint EventCode=1 (Image="*schtasks.exe" OR CommandLine="*schtasks*" OR CommandLine="*Register-ScheduledTask*")
| table _time, ComputerName, User, CommandLine, ParentImage
```

**Qué hace cada línea:**
- `Image="*schtasks.exe"` — filtra por el ejecutable exacto que se lanzó
- `CommandLine="*schtasks*"` — cubre casos donde `schtasks` aparece como parte de un comando más largo (ej. dentro de un script)
- `CommandLine="*Register-ScheduledTask*"` — cubre la alternativa vía cmdlet de PowerShell, por si un atacante usa ese método en vez del binario clásico
- `ParentImage` se incluye deliberadamente en la tabla — es el campo que revela quién lanzó el comando, y es el dato clave del análisis (ver abajo)

## Hallazgo: la cadena de procesos

Los resultados mostraron 3 eventos encadenados:

1. `powershell.exe` → lanzó `cmd.exe` (ejecutando ambos comandos `schtasks` encadenados con `&`)
2. `cmd.exe` → `schtasks.exe` (tarea OnLogon)
3. `cmd.exe` → `schtasks.exe` (tarea OnStartup)

La cadena completa fue **`powershell.exe → cmd.exe → schtasks.exe`**. Una tarea programada creada por un administrador normalmente se origina desde `explorer.exe` (interfaz gráfica) o una consola abierta manualmente — no desde un script de PowerShell encadenando comandos automáticamente. Esa cadena de tres niveles es la señal de sospecha más fuerte del hallazgo, y es el patrón típico de creación automatizada por malware o por un atacante con acceso a consola.

## Limpieza

```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup
```

## Conclusión

Detectar por nombre de proceso (`schtasks.exe`) es sencillo, pero insuficiente por sí solo — genera falsos positivos constantes en cualquier entorno real. El valor del análisis está en el campo `ParentImage`: permite diferenciar una tarea programada legítima (creada manualmente) de una creada de forma automatizada, que es el patrón que realmente indica actividad maliciosa.
