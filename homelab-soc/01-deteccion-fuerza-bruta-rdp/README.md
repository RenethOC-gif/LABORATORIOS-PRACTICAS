# Detección de fuerza bruta RDP con Splunk (MITRE ATT&CK T1110)

## Objetivo

Montar un mini-SOC en casa (Splunk + Windows + Kali) para simular un ataque de fuerza bruta contra RDP y construir la detección desde cero: ingesta de logs, búsqueda SPL y una alerta programada.

## Arquitectura del lab

- **Splunk Enterprise 10.4.3** sobre Ubuntu Server — `192.168.54.10` (SIEM)
- **Windows 10/11** ("DESKTOP-22BGPUF") — `192.168.54.20` (endpoint víctima)
- **Kali Linux** — `192.168.54.30` (atacante)
- Índice dedicado en Splunk: `endpoint`
- Red host-only aislada entre las 3 VMs

## Ataque

Desde Kali, fuerza bruta contra el servicio RDP con Hydra:

```bash
hydra -l wim--victim -P passwords.txt rdp://192.168.54.20 -V -t 1 -W 1
```

`-t 1 -W 1` para ir despacio y no saturar el servicio ni perder intentos por timing.

## Problemas que me encontré (y cómo los resolví)

Nada salió a la primera. Esta parte es la que más me sirvió aprender:

**1. Hydra no lograba conectar con el RDP.**
El Firewall de Windows estaba bloqueando ICMP y el tráfico entrante desde la red del lab. Tuve que abrir las reglas correspondientes en el Firewall con Seguridad Avanzada para permitir el eco ICMPv4 y el tráfico hacia el servicio RDP expuesto.

**2. Los eventos no aparecían en Splunk (0 resultados) aun con el ataque corriendo.**
El problema no era la ingesta, era la hora. Windows y Ubuntu tenían la hora desincronizada, así que Splunk indexaba los eventos con timestamps fuera del rango de búsqueda por defecto. Sincronicé la hora en ambas VMs (NTP/`w32tm` en Windows, `timedatectl` en Ubuntu) y en cuanto cuadró la hora, los 47 eventos aparecieron.

**3. La query SPL devolvía "No results found" a pesar de tener 47 eventos indexados.**
Los campos no venían con los nombres estándar en inglés (`Account_Name`, `src_ip`) sino extraídos en español por Splunk (`Nombre_de_cuenta`, `Dirección_de_red_de_origen`). Tuve que revisar los "Interesting Fields" del evento y reescribir la query con los nombres reales entre comillas:

```spl
index=endpoint EventCode=4625
| stats Count by "Nombre_de_cuenta", "Dirección de red de origen"
| where Count > 5
```

**4. Error de sintaxis al programar la alerta con cron.**
Puse `0 5 * * * *` (6 campos) cuando Splunk usa el estándar de 5 campos de Linux. Lo corregí a `*/5 * * * *` para que corra cada 5 minutos sobre los últimos 5 minutos de datos (`-5m`).

**5. Aviso de licencia Trial.**
Splunk avisó que la búsqueda programada dejaría de correr al expirar el trial — es comportamiento esperado, la alerta queda guardada y funcional igual al pasar a la versión Free (500 MB/día de ingesta).

## Detección

Con la hora sincronizada y los campos correctos, la búsqueda queda validada:

```spl
index=endpoint EventCode=4625
| stats Count by "Nombre_de_cuenta", "Dirección de red de origen"
| where Count > 5
```

**Resultado:** 47 eventos capturados, con 42 fallos de inicio de sesión (`EventCode 4625`) originados desde `192.168.54.30` (Kali) contra la cuenta `wim--victim` — el patrón de fuerza bruta queda claramente aislado del resto del ruido del log de Seguridad.

## Alerta configurada

| Campo | Valor |
|---|---|
| Nombre | Alerta - Intento de Fuerza Bruta (EventCode 4625) |
| Programación | Cron `*/5 * * * *` |
| Rango temporal | Últimos 5 minutos (`-5m`) |
| Condición de disparo | Number of Results > 0 |
| Acciones | Registro en Triggered Alerts + notificación por correo + snapshot de dashboard |

La alerta se disparó correctamente en las pruebas posteriores, confirmando que quedó operativa para triaje.

## Conclusión

Lo que más me llevo de este lab no es la query en sí (`4625` agrupado por cuenta e IP de origen es de las detecciones más básicas que existen), sino el proceso de resolver por qué "no funcionaba" en cada etapa: firewall, sincronización horaria, localización de campos, sintaxis de cron. En un entorno real esos son exactamente los mismos tipos de problemas que retrasan una detección — no la falta de conocimiento de SPL, sino la infraestructura alrededor.

**Próximo paso:** ampliar esta misma base con Atomic Red Team para simular y detectar otras técnicas (PowerShell ofuscado, movimiento lateral con PsExec, persistencia vía tareas programadas).
