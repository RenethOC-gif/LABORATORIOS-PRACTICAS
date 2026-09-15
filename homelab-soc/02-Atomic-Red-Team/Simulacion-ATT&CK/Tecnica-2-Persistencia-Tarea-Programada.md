## Técnica 2: Persistencia vía tarea programada (T1053.005)

### Qué es y por qué importa

Una vez que un atacante logra acceso a un sistema, necesita asegurarse de no perderlo si la máquina se reinicia. Crear una tarea programada que se dispare automáticamente (al iniciar sesión, al arrancar el sistema) es una de las formas más comunes de lograr esa persistencia, precisamente porque las tareas programadas legítimas (backups, actualizaciones) son parte normal de cualquier sistema Windows — lo que hace más difícil distinguir una maliciosa de una legítima a simple vista.

### Test ejecutado

`Invoke-AtomicTest T1053.005 -TestNumbers 1` ("Scheduled Task Startup Script"), que ejecuta:

```
schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"
schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"
```

- La primera tarea se dispara **cada vez que alguien inicia sesión**
- La segunda se dispara **al arrancar el sistema**, corriendo como `SYSTEM` (el privilegio más alto de Windows) — esto significa que sobrevive a un reinicio completo y no depende de que nadie inicie sesión
- `calc.exe` se usa como sustituto inofensivo de lo que en un ataque real sería un script malicioso o un payload

### Detección en Splunk

```spl
index=endpoint EventCode=1 (Image="*schtasks.exe" OR CommandLine="*schtasks*" OR CommandLine="*Register-ScheduledTask*")
| table _time, ComputerName, User, CommandLine, ParentImage
```

**Explicación:**
- `Image="*schtasks.exe"` — filtra por el ejecutable exacto que se lanzó
- `CommandLine="*schtasks*"` — cubre casos donde `schtasks` aparece como parte de un comando más largo (ej. dentro de un script)
- `CommandLine="*Register-ScheduledTask*"` — cubre la alternativa vía cmdlet de PowerShell, en caso de que un atacante use ese método en vez del binario clásico
- `ParentImage` — se incluye deliberadamente en la tabla porque es el campo que revela **quién lanzó** el comando

### Hallazgo: la cadena de procesos

Los resultados mostraron 3 eventos encadenados:

1. `powershell.exe` → lanzó `cmd.exe` (ejecutando ambos comandos `schtasks` encadenados con `&`)
2. `cmd.exe` → `schtasks.exe` (tarea OnLogon)
3. `cmd.exe` → `schtasks.exe` (tarea OnStartup)

Es decir, la cadena completa fue **`powershell.exe → cmd.exe → schtasks.exe`**. Esto es la señal de sospecha más fuerte del hallazgo: una tarea programada creada por un administrador normalmente se origina desde `explorer.exe` (interfaz gráfica) o una consola abierta manualmente — no desde un script de PowerShell encadenando comandos automáticamente. Esa cadena de tres niveles es un patrón típico de creación automatizada, ya sea por malware o por un atacante con acceso a consola.

### Limpieza

```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup
```

### Conclusión de la técnica

La detección por nombre de proceso (`schtasks.exe`) es sencilla, pero el valor real del análisis está en el campo `ParentImage`: permite diferenciar una tarea programada legítima de una creada de forma automatizada, que es el patrón que realmente indica actividad maliciosa.

---
