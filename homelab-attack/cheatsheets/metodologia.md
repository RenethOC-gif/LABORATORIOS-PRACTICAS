# Mi Metodología de Pentesting

Cómo abordo un laboratorio o compromiso de principio a fin. No es una traducción de PTES u OSSTMM — es cómo aplico esos principios en la práctica, basado en lo documentado en este portafolio.

## Fase 0 — Alcance y reglas

En un pentest real, antes de tocar nada: confirmar el alcance exacto (qué IPs/dominios están autorizados y cuáles no), la ventana de tiempo, restricciones (nada de DoS, no tocar producción en horario laboral, avisar antes de fuerza bruta), y tener la autorización por escrito.

En los laboratorios de este portafolio el alcance ya lo define la plataforma, pero mantengo la misma disciplina de pensarlo así.

## Fase 1 — Reconocimiento

Puertos completos (los 65535, no solo el top 1000 — más de una vez la vulnerabilidad estuvo en un puerto que un escaneo rápido no habría mostrado), luego versiones, luego enumeración específica por servicio (ver [cheatsheet de reconocimiento](../cheatsheets/reconocimiento-enumeracion.md)).

Documento en el momento, no de memoria después. Cada comando y resultado relevante, con captura si aplica.

Ya no lanzo fuerza bruta o exploits antes de terminar de enumerar. Es tentador ir directo al primer indicio, pero la ruta más fácil suele estar en un servicio que todavía no revisé.

## Fase 2 — Análisis de vulnerabilidades

Cruzar versión de cada servicio contra Searchsploit / CVE Details / Exploit-DB. Distingo entre vulnerabilidad técnica (CVE-2014-6287 en HFS) y debilidad de configuración (credenciales por defecto en Jenkins) — el enfoque no es el mismo para ambas. Priorizo por probabilidad de éxito e impacto, no por lo que suena más interesante.

## Fase 3 — Explotación

Prefiero exploits manuales primero cuando el CVE lo permite — entender qué hace el exploit, no solo correrlo. Así lo hice en Steel Mountain antes de usar Metasploit como alternativa. Cuando uso una herramienta automatizada, es después de entender manualmente por qué funciona, no como primer recurso.

Confirmo el acceso con algo simple (`whoami`, `id`) antes de asumir que la shell es estable.

## Fase 4 — Post-explotación y escalada

Enumeración automatizada (LinPEAS/winPEAS) + verificación manual de lo más prometedor (ver [cheatsheet de escalada](../cheatsheets/escalada-privilegios.md)). Si LinPEAS marca diez cosas en rojo, reviso cuáles son realmente explotables — hay bastante falso positivo.

Documento la cadena completa: usuario inicial → técnica → privilegio final.

## Fase 5 — Documentación

Escribo el writeup en paralelo, no al terminar. Se me olvidan detalles si lo dejo para después, y explicar el "por qué" mientras aún lo tengo fresco mejora el resultado final.

Estructura que uso en todos mis writeups: Reconocimiento → Análisis de vulnerabilidades → Explotación → Escalada de privilegios → Banderas/evidencia → Herramientas → Conclusiones y recomendaciones.

La sección de conclusiones no es relleno — es la parte que más le importa a un cliente real, porque conecta el hallazgo técnico con una acción concreta.

## Lo que se repite de máquina en máquina

En 4 de mis 5 writeups el vector inicial fue configuración débil o información expuesta (credenciales por defecto, contraseñas en archivos de config, fuerza bruta contra passwords débiles), no una vulnerabilidad de día cero. GTFOBins y LOLBAS los reviso siempre antes de asumir que un binario con permisos elevados sirve. Y cuando algo no funciona, vuelvo a la enumeración en vez de cambiar de exploit al azar — casi siempre el problema es que me faltó información.
