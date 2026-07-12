# AD Attack Detection

> Laboratorio propio de Active Directory donde reproduzco ataques reales (Kerberoasting, DCSync, Golden Ticket...) paso a paso y construyo, para cada uno, su detección en PowerShell basada en Event IDs reales de Windows.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)
![Ataques documentados](https://img.shields.io/badge/Ataques%20documentados-9%2F13-brightgreen)
![Enfoque](https://img.shields.io/badge/Enfoque-Blue%20Team%20%2B%20Red%20Team-blue)

---

> [!WARNING]
> **Disclaimer:** Este repositorio tiene fines **exclusivamente educativos y de investigación en ciberseguridad defensiva**. Todo el contenido (ataques, scripts y capturas) fue realizado en un laboratorio propio y aislado (`adlab.local`), sin conexión a sistemas de producción ni de terceros.
>
> El autor no se hace responsable del mal uso que se le pueda dar a la información o scripts aquí publicados. No utilices estas técnicas contra redes, sistemas o cuentas sobre las que no tengas autorización explícita y por escrito. El uso no autorizado de estas técnicas puede constituir un delito.

---

## Qué demuestra este proyecto

Este repo no es una recopilación de teoría: es el registro de un laboratorio de AD montado, atacado y defendido de principio a fin por mí. Concretamente, cada módulo demuestra:

- **Entendimiento real de Kerberos/NTLM y sus abusos** — AS-REP Roasting, Kerberoasting, DCSync y Golden Ticket no descritos de oídas, sino ejecutados contra un DC propio con Mimikatz, Rubeus, Impacket y Crackmapexec.
- **Detection engineering aplicado**, no solo teoría de IoCs: cada ataque termina en un script PowerShell funcional que consulta el Visor de eventos (`Get-WinEvent`), filtra por Event ID real y genera alertas — sin depender de un SIEM de pago.
- **Doble perspectiva ofensiva/defensiva** sobre el mismo entorno: ejecuto el ataque desde el rol de atacante (Kali/WS01) y después me pongo del lado del defensor para diseñar la detección y el hardening.
- **Autonomía de infraestructura**: el laboratorio (DC, cliente Windows, atacante Kali) está montado, configurado y documentado por mí, incluyendo la activación de las políticas de auditoría necesarias para que cada evento se genere.
- **Comunicación técnica clara**: cada módulo sigue la misma estructura (teoría → ataque reproducible → evidencia real en capturas → IoCs → detección → mitigación), pensada para que cualquier compañero de equipo pueda seguirla sin contexto previo.

---

## Qué es este proyecto

**AD Attack Detection** es un toolkit de detección de código abierto basado en PowerShell, diseñado para administradores de Active Directory que quieren saber si su infraestructura está siendo atacada.

La herramienta monitoriza los registros de eventos de Windows de forma diaria, correlaciona indicadores de compromiso (IoCs) para los ataques de AD más comunes y genera un informe HTML detallado que puedes revisar cada mañana.

Sin agentes. Sin software de terceros. Solo PowerShell y los registros de eventos de Windows.

---

## Por qué existe este proyecto

Active Directory es la columna vertebral de la mayoría de entornos empresariales, y el objetivo principal de los atacantes. Técnicas como Kerberoasting, DCSync o los ataques de Golden Ticket están bien documentadas, son ampliamente utilizadas y a menudo pasan desapercibidas durante semanas o meses.

La mayoría de herramientas de detección requieren licencias costosas o infraestructura compleja. Este proyecto ofrece a cualquier administrador de AD una forma gratuita, sencilla y eficaz de monitorizar su entorno.

---

## Cómo funciona

```
Registros de eventos de Windows (Security, System, Directory Service)
        ↓
AD-ThreatDetector.ps1 (se ejecuta diariamente via Tarea Programada)
        ↓
Correlaciona IoCs para cada tipo de ataque
        ↓
AD-DailyReport.html (se abre automáticamente)
```

El script se ejecuta a las 23:59 cada día y genera un informe con:
- Resumen ejecutivo
- Alertas agrupadas por tipo de ataque
- IoCs detectados (cuentas, IPs, marcas de tiempo)
- Acciones recomendadas para cada hallazgo

---

## Ataques cubiertos

| # | Ataque | Event IDs | Documentación | Detección |
|---|--------|-----------|----------------|-----------|
| 01 | AS-REProasting | 4768 | [Documentación](01_ReProasting/01_AS-REProasting_ES.md) | [Script](01_ReProasting/01_detection_ASREProasting.ps1) |
| 02 | Kerberoasting | 4769 | [Documentación](02_Kerberoasting/02_Kerberoasting.md) | [Script](02_Kerberoasting/02_detection_Kerberoasting.ps1) |
| 03 | GPP Passwords | 5145 | [Documentación](<03_GPP Passwords/03_GPPPasswords.md>) | [Script](<03_GPP Passwords/03_detection_GPPPasswords.ps1>) |
| 04 | GPO Permissions / GPO Files | 4688, 5136 | [Documentación](<04_GPO Permisos y ficheros/04_GPO_Permissions.md>) | [Script](<04_GPO Permisos y ficheros/AD-ThreatDetector.ps1>) |
| 05 | Credentials in Shares | 5145 | [Documentación](<05_Credenciales compartidas/05_Credentials_in_Shares.md>) | [Script](<05_Credenciales compartidas/Detect-CredentialEnumeration.ps1>) |
| 06 | Credentials in Object Properties | 4624 | [Documentación](<06_informacion en propiedades de objeto/06_Credentials_in_Object_Properties.md>) | [Script](<06_informacion en propiedades de objeto/Detect-HoneypotAttack.ps1>) |
| 07 | DCSync | 4662 | [Documentación](07_DCSync/07_DCSync.md) | [Script](07_DCSync/Detect-DCSync.ps1) |
| 08 | Golden Ticket | 4768, 4769, 4776 | [Documentación](08_GoldenTicket/08_Golden_Ticket.md) | [Script](08_GoldenTicket/Detect-GoldenTicket.ps1) |
| 09 | Kerberos Constrained Delegation | 4768, 4769, 4624 | [Documentación](<09_Kerberos Constrained Delegation/09_KerberosConstrainedDelegation.md>) | [Script](<09_Kerberos Constrained Delegation/Detect-KerberosConstrainedDelegation.ps1>) |
| 10 | Print Spooler & NTLM Relaying | 4648, 4624 | ⬜ Pendiente | — |
| 11 | Coercing & Unconstrained Delegation | 4768 | ⬜ Pendiente | — |
| 12 | Object ACLs | 4662, 5136 | ⬜ Pendiente | — |
| 13 | PKI - ESC1 | 4886, 4887 | ⬜ Pendiente | — |

---

## Entorno de laboratorio

Este proyecto fue construido y probado en el siguiente entorno:

| Máquina | SO | IP | Rol |
|---------|----|----|-----|
| DC01 | Windows Server 2022 | 100.100.100.50 | Controlador de dominio |
| WS01 | Windows 10 Enterprise | 100.100.100.40 | Cliente unido al dominio |
| Kali | Kali Linux 2024 | 100.100.100.20 | Atacante |

Dominio: `adlab.local`

---

## Estructura del repositorio

```
AD_Attack_Detection/
│
├── README.md
│
├── 01_ReProasting/
│   ├── 01_AS-REProasting_ES.md
│   ├── 01_detection_ASREProasting.ps1
│   └── img/
│
├── 02_Kerberoasting/
│   ├── 02_Kerberoasting.md
│   ├── 02_detection_Kerberoasting.ps1
│   └── img/
│
├── 03_GPP Passwords/
│   ├── 03_GPPPasswords.md
│   ├── 03_detection_GPPPasswords.ps1
│   └── img/
│
├── 04_GPO Permisos y ficheros/
│   ├── 04_GPO_Permissions.md
│   ├── AD-ThreatDetector.ps1
│   └── img/
│
├── 05_Credenciales compartidas/
│   ├── 05_Credentials_in_Shares.md
│   ├── Detect-CredentialEnumeration.ps1
│   └── img/
│
├── 06_informacion en propiedades de objeto/
│   ├── 06_Credentials_in_Object_Properties.md
│   ├── Detect-HoneypotAttack.ps1
│   └── img/
│
├── 07_DCSync/
│   ├── 07_DCSync.md
│   ├── Detect-DCSync.ps1
│   └── img/
│
├── 08_GoldenTicket/
│   ├── 08_Golden_Ticket.md
│   ├── Detect-GoldenTicket.ps1
│   └── img/
│
├── 09_Kerberos Constrained Delegation/
│   ├── 09_KerberosConstrainedDelegation.md
│   ├── Detect-KerberosConstrainedDelegation.ps1
│   └── img/
│
└── (próximos módulos: 10_PrintSpoolerNTLMRelaying, ...)
```

---

## Requisitos

- Windows Server 2016 o posterior
- PowerShell 5.1 o posterior
- Privilegios de administrador en el Controlador de Dominio
- Políticas de auditoría habilitadas (ver guía de configuración)

---

## Contribuciones

Este proyecto está en desarrollo activo. Cada módulo de ataque está documentado de forma independiente para que puedas contribuir a detecciones individuales sin tocar el resto del código.

Los pull requests son bienvenidos.

---

## Contacto

Si este proyecto te resulta útil o quieres hablar sobre ciberseguridad de Active Directory, blue team o detection engineering, contáctame:

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Jorge%20González-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/jorge-gonz%C3%A1lez-gonz%C3%A1lez-5740614b/)
[![GitHub](https://img.shields.io/badge/GitHub-JorgeGonzalezVlc-181717?logo=github&logoColor=white)](https://github.com/JorgeGonzalezVlc)
