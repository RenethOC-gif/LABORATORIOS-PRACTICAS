# Portafolio de Ciberseguridad — René Ochoa

En formación hacia la ciberseguridad. Este repositorio contiene writeups documentados de máquinas resueltas en TryHackMe y en laboratorios de la certificación PMJ (Hacker Mentor), cubriendo reconocimiento, explotación, escalada de privilegios y post-explotación — además de un homelab propio de detección (Blue Team/SOC).

## Habilidades técnicas

- **Reconocimiento:** Nmap, Gobuster, enumeración de servicios (SMB, FTP, HTTP, RPC)
- **Explotación web:** Drupalgeddon2, File Upload, RCE vía Jenkins Script Console, HFS RCE (CVE-2014-6287)
- **Post-explotación:** Metasploit / Meterpreter, pivoting (autoroute), token impersonation (incognito)
- **Escalada de privilegios (Linux):** binarios SUID (GTFOBins), LinPEAS
- **Escalada de privilegios (Windows):** unquoted service paths, WinPEAS, PowerUp.ps1
- **Cracking de credenciales:** Hydra, John the Ripper, CrackStation
- **Persistencia:** SSH authorized_keys
- **Blue Team / SOC:** Splunk (SIEM), Sysmon, análisis de logs de Windows Event Log, creación de alertas y detecciones basadas en MITRE ATT&CK

## Writeups

| Máquina | Plataforma | SO | Técnica principal |
|---|---|---|---|
| [Alfred](./homelab-attack/writeups/alfred.md) | TryHackMe | Windows | Jenkins RCE + Token Impersonation |
| [Steel Mountain](./homelab-attack/writeups/steel-mountain.md) | TryHackMe | Windows | Rejetto HFS RCE (CVE-2014-6287) + Service Hijacking |
| [Mr. Robot](./homelab-attack/writeups/mr-robot.md) | TryHackMe | Linux | WordPress Bruteforce + SUID (nmap) |
| [Vulnuversity](./homelab-attack/writeups/vulnuversity.md) | TryHackMe | Linux | File Upload + SUID (systemctl) |
| [Pivot](./homelab-attack/writeups/pivot.md) | Academia (Hacker Mentor) | Linux | Drupalgeddon2 + Pivoting |

Cheatsheets de referencia: [reconocimiento y enumeración](./homelab-attack/cheatsheets/reconocimiento-enumeracion.md) · [escalada de privilegios](./homelab-attack/cheatsheets/escalada-privilegios.md) · [metodología](./homelab-attack/cheatsheets/metodologia.md)

## Homelab / Blue Team

Proyectos de infraestructura propia orientados a detección y monitorización — a diferencia de los writeups de arriba (máquinas resueltas), aquí construyo el entorno completo y documento hallazgos generados por mí mismo.

| Proyecto | Stack | Técnica principal |
|---|---|---|
| [Detección Fuerza Bruta RDP](./homelab-soc/01-deteccion-fuerza-bruta-rdp/) | Splunk + Sysmon + Windows/Kali | MITRE ATT&CK T1110 |
| [Detección PowerShell Codificado](./homelab-soc/02-powershell-comando-codificado/) | Splunk + Sysmon + Atomic Red Team | MITRE ATT&CK T1059.001 |
| [Detección Persistencia — Tarea Programada](./homelab-soc/03-persistencia-tarea-programada/) | Splunk + Sysmon + Atomic Red Team | MITRE ATT&CK T1053.005 |
| [Detección Acceso a LSASS (comsvcs.dll)](./homelab-soc/04-acceso-lsass-comsvcs/) | Splunk + Sysmon + Atomic Red Team | MITRE ATT&CK T1003.001 |

## Aviso

Todo el contenido de este repositorio es exclusivamente para fines educativos, realizado en entornos de laboratorio controlados y autorizados (TryHackMe, laboratorios de academia). No se incluye información sensible real ni se promueve el uso de estas técnicas contra sistemas sin autorización.

