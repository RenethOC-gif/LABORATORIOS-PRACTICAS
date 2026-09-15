# Simulación ATT&CK con Atomic Red Team

## Objetivo

Usar Atomic Red Team para ejecutar técnicas reales de MITRE ATT&CK en un endpoint Windows monitoreado con Sysmon, y construir la detección de cada una en Splunk — profundizando además en el mecanismo interno de cada técnica, no solo en la query que la detecta.

## Arquitectura

Se reutiliza el mismo lab del Proyecto 1 (Splunk + Sysmon + Universal Forwarder sobre `192.168.54.20`, índice `endpoint`). Ver [writeup de detección de fuerza bruta RDP](../01-deteccion-fuerza-bruta-rdp/) para el detalle de la infraestructura.

---
