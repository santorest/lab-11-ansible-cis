---
title: "Endurecimiento CIS con Ansible para Ubuntu 24.04"
id: "lab-11-ansible-cis"
category: "Scripting y automatización"
type: "Laboratorio"
status: "en curso"
date: "2026-10-05"
time_to_reproduce: "Unos 30 minutos: una ejecución de CI (fork, habilitar Actions, ejecutar CI)"
skills: [Ansible, OpenSCAP, SCAP Security Guide, CIS Benchmarks, Molecule, ansible-lint, Python, Ubuntu, GitHub Actions]
frameworks: [CIS Ubuntu Linux 24.04 LTS Benchmark (nivel 1 – servidor), CIS Controls v8 (4.1, 4.2, 4.6, 4.7, 4.8, 5.2, 8.2), MITRE ATT&CK (T1021.004, T1548.003, T1562.001)]
repo: "https://github.com/santorest/lab-11-ansible-cis"
bundle: "Publicado en el sitio del portafolio con su suma SHA-256"
---

# Endurecimiento CIS con Ansible para Ubuntu 24.04

> **Resumen:** Siete roles de Ansible, uno por grupo de secciones de CIS, endurecen un servidor Ubuntu 24.04 por
> defecto al nivel 1 de CIS para servidores. OpenSCAP escanea la máquina antes y después con el perfil de
> ComplianceAsCode, el playbook se ejecuta una segunda vez para probar que no cambia nada, y una pequeña herramienta
> en Python compara los escaneos y hace fallar CI ante un puntaje bajo, un control declarado que sigue fallando, una
> regresión o una segunda ejecución que cambia algo. Cada control se puede rastrear desde su id de CIS hasta el rol
> que lo aplica y las reglas del escáner que lo verifican. Todo se ejecuta en GitHub Actions sobre un runner
> desechable. **Las ejecuciones de CI son reales; el equipo es un runner de CI desechable.**

| | |
|---|---|
| **Rol desempeñado** | Ingeniero de sistemas / seguridad responsable de la línea base de endurecimiento de una flota de servidores Ubuntu |
| **Entorno** | Repositorio público en GitHub, VM de runners `ubuntu-24.04` alojados por GitHub, contenedores Docker para probar los roles |
| **Herramientas** | Ansible (ansible-core 2.21), OpenSCAP, SCAP Security Guide v0.1.82, Molecule, ansible-lint, yamllint, Python 3.12, pytest, ruff, mypy, shellcheck, gitleaks |
| **Entregable** | Siete roles de endurecimiento, mapa de controles con excepciones documentadas, herramienta de escaneo-comparación-compuerta (`cisreport`), CI con pruebas de roles y el ciclo real, ruleset de rama, PR de demostración |

---

## 1. Problema

Una línea base de endurecimiento suele vivir en dos lugares que se separan con el tiempo: un script o playbook que
alguien escribió una vez y un documento de benchmark que leen los auditores. Nadie puede decir qué control de CIS
implementa una tarea, si el servidor sigue cumpliendo después del último cambio, ni qué controles se omitieron a
propósito y por qué. Y un playbook que reporta cambios en cada ejecución esconde la deriva real entre el ruido.

## 2. Diseño

- **Roles propios por sección.** Siete roles siguen las secciones del benchmark (configuración inicial, servicios,
  red, firewall, acceso, registros, mantenimiento). Cada tarea lleva en su nombre y en su etiqueta el id de CIS, de
  modo que un control se puede encontrar, ejecutar u omitir por separado.
- **Un escáner independiente.** Los roles no se califican a sí mismos. OpenSCAP con el perfil de ComplianceAsCode
  `cis_level1_server`, de una versión fijada de SCAP Security Guide (verificada por SHA-512), escanea antes y después.
  Si la versión cambia o desaparece, la ejecución se detiene; el escáner nunca se reemplaza en silencio.
- **Lo que se declara sale de la línea base real.** `policy/controls.yml` asocia cada id de CIS con su rol y con las
  reglas del escáner que lo verifican. Se construyó a partir del primer escaneo de un runner por defecto: cada regla
  que falló y que un rol corrige — 84 controles, 112 reglas. Si alguna sigue fallando después del endurecimiento, CI
  falla.
- **Excepciones como datos.** Un control omitido es una entrada con el id de CIS, sus reglas, un motivo y un rol
  responsable. Las tareas lo omiten, el informe lo lista y muestra el puntaje con y sin él, y una excepción para una
  regla que los roles también declaran, sin motivo o para una regla que el perfil no tiene es un error de
  configuración.
- **Salvaguardas del runner.** El objetivo es el propio runner, así que el endurecimiento no puede cortar el trabajo:
  el tráfico saliente sigue abierto en los puertos que el trabajo necesita (DNS, HTTP, HTTPS, NTP) y la cuenta
  `runner` conserva su sudo.

## 3. El ciclo

1. Descargar SCAP Security Guide v0.1.82 y verificar su SHA-512.
2. Escaneo previo: `oscap xccdf eval --profile …cis_level1_server` (ARF y HTML).
3. `ansible-playbook playbooks/harden.yml` contra `localhost` con `become`.
4. El mismo playbook otra vez: el resumen debe mostrar `changed=0` y `failed=0`.
5. Escaneo posterior con el mismo contenido.
6. `cisreport report` compara los escaneos y escribe HTML, Markdown y JSON; `cisreport gate` decide.

## 4. Medición y compuerta

- **Puntaje** = pass / (pass + fail) sobre las reglas seleccionadas por el perfil, antes y después, con todas las
  reglas y excluyendo las de las excepciones. `notapplicable` y `notchecked` no cuentan en ningún sentido.
- **Corregidas, regresiones, declaradas que fallan, abiertas**: reglas que pasaron de fallar a cumplir; reglas que
  pasaron de cumplir a fallar; reglas declaradas que siguen fallando; reglas que fallan y no están ni declaradas ni
  exceptuadas.
- **Compuerta** (código 1): el puntaje sin excepciones por debajo del 90 %, cualquier regla declarada que falle,
  cualquier regresión (aunque el puntaje total haya subido) o una segunda ejecución con `changed > 0` o `failed > 0`.
- **Errores, no puntajes** (código 2): un escaneo ausente, vacío o truncado, un perfil que no seleccionó reglas,
  resultados que son todos `error` o `notchecked`, o un resumen de Ansible ausente. Un escaneo que no ocurrió nunca
  debe leerse como 100 % ni como 0 %.

## 5. Roles

| Rol | Secciones CIS | Qué hace |
|---|---|---|
| `cis_initial_setup` | 1.1, 1.3–1.6 | módulos de sistemas de archivos no usados, opciones de `/dev/shm`, AppArmor (utilidades, cargador de arranque, perfiles no confinados a modo complain), contraseña del cargador de arranque, ASLR, ptrace y volcados de memoria, avisos de inicio de sesión |
| `cis_services` | 2.1–2.4 | servidores y clientes innecesarios eliminados, sincronización de hora solo con `systemd-timesyncd`, permisos de cron |
| `cis_network` | 3.2–3.3 | protocolos de red poco comunes no disponibles, parámetros de red del kernel |
| `cis_firewall` | 4.2 | ufw: reglas de loopback, reglas salientes explícitas, una regla entrante por cada puerto en escucha, denegar por defecto entrada, salida y enrutado |
| `cis_access` | 5.1–5.4 | archivo adicional de SSH, sudo (`use_pty`, archivo de registro, tiempo de espera, `secure_path`), restricción de `su`, calidad de contraseñas en PAM, faillock e historial, vencimiento, cuentas de sistema, tiempo de espera y umask del shell |
| `cis_logging` | 6.1 | journald reenvía a rsyslog, permisos y propietarios en `/var/log` |
| `cis_maintenance` | 7.1–7.2 | permisos de archivos de cuentas, archivos escribibles por todos, archivos sin propietario, archivos ocultos de usuario, contraseñas vacías |

**Excepciones** (en `group_vars/all.yml`):

| CIS | Reglas | Motivo |
|---|---|---|
| 1.1.2.1.1 | `partition_for_tmp` | un runner de CI ya arrancado no se puede reparticionar |
| 4.3 | la variante nftables y `package_ufw_removed` | CIS pide una sola herramienta de firewall y este laboratorio usa ufw; las reglas de nftables no pueden cumplirse mientras ufw administra el firewall |
| 6.3.1 | `package_aide_installed`, `aide_build_database` | construir la base de datos de AIDE de una imagen de runner grande y efímera no terminó en 15 minutos; la supervisión de integridad de archivos corresponde a servidores de larga vida |

## 6. Pipeline

| Trabajo | Qué prueba |
|---|---|
| `lint` | yamllint, ansible-lint (perfil production), ruff, mypy (estricto), shellcheck |
| `unit` | `cisreport` sobre datos de prueba: análisis, escaneos vacíos o que no coinciden, excepciones, regresiones, reglas declaradas que fallan, análisis del resumen de Ansible, límites del umbral, escape en el informe; cobertura mínima 90 % |
| `molecule` | cada rol en un contenedor Ubuntu 24.04: converge, idempotencia, verificación (las tareas de kernel, cargador de arranque y firewall se etiquetan para ejecutarse solo en la VM) |
| `harden` | el ciclo completo en la VM del runner; artefactos: escaneos, informe, registros del playbook; un resumen en Markdown del trabajo |
| `secrets` | gitleaks sobre todo el historial |

Se ejecuta en cada pull request, en cada push a `main`, semanalmente y a demanda.

## 7. Resultados

Los resultados se agregan a partir de las primeras ejecuciones de CI.

## 8. Lecciones

- **Lo que significa "cumplir" lo decide el perfil, no el recuerdo del benchmark.** El perfil fijado espera
  `systemd-timesyncd` (no chrony) para la hora, `LogLevel INFO` en SSH, rsyslog como vía de registros, y no
  selecciona auditd en el nivel 1. Los roles se escribieron a partir de la lista de reglas que de verdad fallaron en
  el escaneo de línea base (408 reglas seleccionadas: 222 cumplen, 122 fallan, 64 no aplican), no a partir de una
  lectura del benchmark.
- **Los detalles pequeños de un archivo rompen los cambios con privilegios.** La prueba de viabilidad escribió su
  archivo de sudoers con `tee`, que lo dejó en `0644`, y `visudo -c` lo rechazó; el rol escribe `0440` y valida su
  propio archivo antes de instalarlo. En el runner, dos perfiles de AppArmor reclaman el mismo binario del navegador,
  así que `aa-complain` se niega a ejecutarse; el rol edita directamente la marca de no confinado en cada perfil y
  recarga solo los perfiles que cambió.
- **Un servicio que nunca se ejecutó no deja su directorio de ejecución.** En el runner, SSH se activa por socket,
  así que `/run/sshd` no existe y `sshd -t` se niega a validar una configuración; el rol crea primero el directorio.
- **Algunos controles no encajan en una máquina efímera.** Instalar AIDE arrastró un servidor de correo, y construir
  su base de datos no terminó en 15 minutos sobre la imagen grande del runner; se convirtió en una excepción
  documentada en lugar de una tarea omitida en silencio.
- **Las herramientas leen la configuración desde donde se ejecutan.** Molecule se ejecuta desde el directorio del
  rol, donde no se lee el `ansible.cfg` del repositorio (ni su ruta de colecciones); CI pasa esa ruta de forma
  explícita.

## 9. Límites

- El objetivo es un runner alojado por GitHub, no un servidor de producción; tres controles son excepciones porque el
  runner ya está arrancado y es efímero.
- El puntaje viene del perfil de ComplianceAsCode, que sigue a CIS pero no es CIS-CAT ni una certificación.
- Los ajustes que requieren reiniciar (AppArmor en la línea de comandos del kernel, la contraseña del cargador de
  arranque) se escriben y el escáner los verifica, pero no se arranca con ellos.
- No cubre: nivel 2, Windows Server, CIS-CAT Pro, administración de flotas.

## 10. Reproducirlo

Haga un fork del repositorio y habilite Actions: cada push ejecuta el ciclo en un runner nuevo. En una VM Ubuntu
24.04 **desechable**, `bash scripts/run-hardening.sh` endurece esa VM y escribe `out/report.html` y
`out/results.json`. Los roles se pueden probar en contenedores con `molecule test` desde el directorio de cada rol.

## 11. Mapeo

| Marco | Elementos |
|---|---|
| CIS Controls v8 | 4.1 establecer y mantener un proceso de configuración segura, 4.2 … para la infraestructura de red, 4.6 administrar de forma segura activos y software, 4.7 administrar las cuentas por defecto, 4.8 desinstalar o deshabilitar servicios innecesarios, 5.2 usar contraseñas únicas, 8.2 recolectar registros de auditoría |
| MITRE ATT&CK | T1021.004 Remote Services: SSH, T1548.003 Sudo and Sudo Caching, T1562.001 Impair Defenses: Disable or Modify Tools — lo que los ajustes endurecidos dificultan |
