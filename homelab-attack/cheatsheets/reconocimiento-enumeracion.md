# Cheatsheet — Reconocimiento y Enumeración

Notas de reconocimiento que uso en mis laboratorios. Referencia rápida, no un tutorial — para eso ya tengo los writeups completos ([Alfred](../writeups/alfred.md), [Steel Mountain](../writeups/steel-mountain.md), [Mr. Robot](../writeups/mr-robot.md), [Vulnuversity](../writeups/vulnuversity.md), [Pivot](../writeups/pivot.md)).

## 1. Escaneo de puertos con Nmap

Descubrimiento rápido, todos los puertos:

```bash
nmap -n -Pn -sS -T4 --open -p- --min-rate 3000 <IP>
```

- `-n` sin resolución DNS
- `-Pn` no hace ping antes (asume host activo)
- `-sS` SYN scan
- `--open` solo puertos abiertos
- `-p-` rango completo 1-65535
- `--min-rate` fuerza velocidad mínima de paquetes/segundo

En THM/HTB subo el min-rate a 3000-4000 sin problema. En un pentest real contra producción esto se coordina con el cliente antes — un escaneo muy agresivo puede saturar el enlace o disparar el IDS de forma innecesaria.

Escaneo de versiones, ya con los puertos identificados:

```bash
nmap -n -Pn -sV -sC -vv --min-rate 3000 -p<puertos> <IP>
```

Vulnerabilidades conocidas vía scripts NSE:

```bash
nmap -n -Pn --min-rate 3000 -vv --script vuln -p<puertos> <IP>
```

Esto es un primer filtro, no reemplaza buscar manualmente en Searchsploit.

## 2. Enumeración web

```bash
gobuster dir -u http://<IP>[:puerto] -w /usr/share/dirb/wordlists/common.txt \
  -x txt,php,zip -s 200,204,301,302,307,401,403 -t 200 -k
```

Ajustar wordlist y extensiones según lo que ya sé del sitio (no tiene caso buscar `.aspx` en un sitio PHP).

Cosas que reviso siempre:

- `robots.txt` — en Mr. Robot tenía directamente una flag y un diccionario.
- Código fuente (Ctrl+U) — comentarios, credenciales hardcodeadas, nombres de usuario. Así encontré el nombre del "empleado del mes" en Alfred y Steel Mountain, que terminó siendo el usuario válido.
- Archivos de versión del CMS (`CHANGELOG.txt` en Drupal — así saqué la versión exacta en Pivot).
- Formularios de carga de archivos: probar extensiones alternativas si hay validación (`.phtml`, `.pht`, `.phar`).

## 3. Enumeración por servicio

| Servicio | Comando | Qué busco |
|---|---|---|
| SMB | `smbclient -L //<IP>/ -N` | Shares anónimos |
| FTP | `ftp <IP>` | Login anónimo |
| SSH | Hydra + wordlist | Credenciales débiles/reutilizadas |
| WordPress | Login con usuario de prueba | Mensajes de error que confirman usuarios válidos |

## 4. Fuerza bruta con Hydra

```bash
hydra -L <usuarios> -P <contraseñas> -t 64 -f <IP> <protocolo>
```

SSH (Pivot):

```bash
hydra -l flag4 -P /usr/share/wordlists/metasploit/unix_passwords.txt -t 50 -f ssh://<IP>
```

Formulario web (Mr. Robot):

```bash
hydra -L wordlist.txt -p test -t 64 -f <IP> http-post-form \
  "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In: Invalid username" -V
```

En un pentest real esto es de lo más ruidoso que hay, y con riesgo de lockout de cuentas. Solo con autorización explícita en el alcance y controlando el rate.

## Antes de pasar a explotación

- Versión exacta de cada servicio relevante
- Código fuente revisado en cada página web
- Fuzzing hecho en cada puerto HTTP
- Búsqueda en Searchsploit / CVE Details por servicio + versión
- Archivos de configuración revisados por credenciales expuestas
