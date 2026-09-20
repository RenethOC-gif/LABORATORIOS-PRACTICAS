# Detección de acceso a memoria de LSASS vía comsvcs.dll (MITRE ATT&CK T1003.001)

## Objetivo

Simular el volcado de memoria de `lsass.exe` (el proceso que retiene credenciales de sesión activas en Windows) usando una DLL nativa del sistema, y evaluar la visibilidad real que ofrece una configuración de Sysmon estándar de la industria frente a esta técnica.

## Arquitectura

Mismo lab de los proyectos anteriores. Ver [detección de fuerza bruta RDP](../01-deteccion-fuerza-bruta-rdp/) para el detalle de la infraestructura.

## Contexto técnico

`lsass.exe` mantiene en memoria, mientras una sesión está activa, credenciales como hashes de contraseñas y tickets Kerberos, para que el usuario no tenga que reautenticarse constantemente. Si un atacante logra leer esa memoria, puede extraer esas credenciales — es la técnica detrás de herramientas como Mimikatz.

## Test elegido

De las 14 variantes disponibles en Atomic Red Team para esta técnica, se eligió **`T1003.001-2` (comsvcs.dll)** por dos razones: no requiere descargar ninguna herramienta externa (la DLL ya viene incluida en Windows), y es la técnica más documentada en la industria para este tipo de laboratorio.

```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id $env:TEMP\lsass-comsvcs.dmp full
```

**Desglose:**

| Parte | Qué es |
|---|---|
| `rundll32.exe` | Utilidad nativa de Windows que ejecuta una función específica exportada por una DLL |
| `comsvcs.dll` | DLL usada normalmente por COM+ Services para generar volcados de diagnóstico cuando un proceso de ese tipo crashea |
| `MiniDump` | Función exportada que vuelca la memoria de cualquier proceso dado su PID — no valida que ese proceso pertenezca a COM+, lo cual habilita el abuso |
| `(Get-Process lsass).id` | PowerShell obteniendo dinámicamente el PID de `lsass.exe` en el momento de la ejecución |
| `full` | Tipo de volcado: memoria completa del proceso |

El archivo generado (`lsass-comsvcs.dmp`) contendría material de credenciales reales si se procesara con una herramienta como Mimikatz — por eso el comando de limpieza del propio atomic lo elimina automáticamente después de la prueba, y en ningún momento se subió ni se procesó ese archivo.

## Primer hallazgo: blind spot en la configuración de Sysmon

Al buscar el evento esperado de acceso a memoria (Event ID 10), la búsqueda no devolvía resultados:

```spl
index=endpoint EventCode=10 TargetImage="*lsass.exe"
```

Revisando el archivo `sysmonconfig-export.xml` (basado en la config de SwiftOnSecurity), se encontró la causa exacta:

```xml
<!--SYSMON EVENT ID 10 : INTER-PROCESS ACCESS [ProcessAccess]-->
<!--COMMENT: Can cause high system load, disabled by default.-->
<RuleGroup name="" groupRelation="or">
    <ProcessAccess onmatch="include">
        <!--NOTE: Using "include" with no rules means nothing in this section will be logged-->
    </ProcessAccess>
</RuleGroup>
```

La sección `ProcessAccess` estaba completamente vacía. Con `onmatch="include"` y ninguna regla dentro, Sysmon no genera Event ID 10 para **ningún** proceso — no es un problema específico de `rundll32.exe`, es que esta config deshabilita por completo la visibilidad sobre accesos entre procesos, según el propio comentario del autor, para evitar sobrecargar el sistema.

**Esto significa que, con esta configuración de Sysmon sin ajustar, cualquier técnica de volcado de memoria de LSASS (Mimikatz, ProcDump, comsvcs.dll) pasa completamente invisible para el SIEM.**

## Habilitando la visibilidad

Se agregó una regla específica y acotada (solo para `lsass.exe`, no para todo el sistema) dentro del bloque vacío:

```xml
<ProcessAccess onmatch="include">
    <TargetImage condition="end with">lsass.exe</TargetImage>
</ProcessAccess>
```

Y se reaplicó la configuración en caliente:

```powershell
Sysmon.exe -c "C:\ruta\sysmonconfig-export.xml"
```

## Segundo hallazgo: ruido legítimo del sistema

Al activar la regla y volver a consultar, aparecieron 135 eventos — pero casi todos correspondían a `VBoxService.exe` (el servicio de integración de VirtualBox Guest Additions) accediendo a `lsass.exe` de forma rutinaria, con `GrantedAccess=0x1400` en cada caso. Esto confirma en la práctica la advertencia original del autor de la config: habilitar `ProcessAccess` sin acotar bien genera ruido legítimo constante, no solo actividad maliciosa.

## Aislando el evento real

```spl
index=endpoint EventCode=10 TargetImage="*lsass.exe" SourceImage="*rundll32.exe"
```

Este filtro adicional (`SourceImage="*rundll32.exe"`) separa el evento del ataque simulado del ruido de `VBoxService.exe`.

**Diferencia clave encontrada:**

| Campo | Ruido (VBoxService) | Ataque simulado |
|---|---|---|
| `SourceImage` | `VBoxService.exe` | `rundll32.exe` |
| `GrantedAccess` | `0x1400` | `0x1410` |

`0x1410` combina `PROCESS_QUERY_INFORMATION` (0x0400) con `PROCESS_VM_READ` (0x0010) — este segundo permiso es el que habilita leer directamente la memoria del proceso, no solo consultar su estado. Este valor es lo suficientemente característico de esta técnica que aparece citado en reglas de detección reales (Sigma, Elastic) para volcados de LSASS vía `comsvcs.dll`/ProcDump.

El evento también incluyó el campo `CallTrace`, que muestra la pila de llamadas involucradas:
```
...C:\Windows\System32\comsvcs.dll+2267f...
```
Esto confirma directamente, a nivel de evidencia técnica (no solo inferencia), que el acceso a memoria pasó por esa DLL específica.

## Conclusión

Este fue el hallazgo más completo de los tres proyectos, con dos capas de análisis: primero, identificar un blind spot real en una configuración de Sysmon ampliamente usada en la industria (Event ID 10 deshabilitado por defecto); segundo, tras habilitarlo, aprender a diferenciar tráfico legítimo del sistema de actividad maliciosa usando el valor exacto de `GrantedAccess` y el campo `CallTrace` como evidencia. Detectar la técnica en sí fue relativamente simple una vez visible — lo valioso fue entender por qué no era visible al principio, y qué trade-off de configuración explica esa ausencia.
