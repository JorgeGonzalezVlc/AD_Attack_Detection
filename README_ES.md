# AD Attack Detection

> Una herramienta práctica para administradores IT que quieren detectar los ataques más comunes contra Active Directory en tiempo real.

---

## ¿Qué es este proyecto?

**AD Attack Detection** es un toolkit de detección de código abierto basado en PowerShell, diseñado para administradores de Active Directory que quieren saber si su infraestructura está siendo atacada.

La herramienta monitoriza los registros de eventos de Windows de forma diaria, correlaciona indicadores de compromiso (IoCs) para los ataques de AD más comunes y genera un informe HTML detallado que puedes revisar cada mañana.

Sin agentes. Sin software de terceros. Solo PowerShell y los registros de eventos de Windows.

---

## ¿Por qué existe este proyecto?

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

| # | Ataque | Event IDs | Estado |
|---|--------|-----------|--------|
| 01 | AS-REProasting | 4768 | ✅ Completado |
| 02 | Kerberoasting | 4769 | 🔄 En progreso |
| 03 | GPP Passwords | 4688 | ⬜ Pendiente |
| 04 | GPO Permissions / GPO Files | 5136, 4670 | ⬜ Pendiente |
| 05 | Credentials in Shares | 5140, 5145 | ⬜ Pendiente |
| 06 | Credentials in Object Properties | 4662 | ⬜ Pendiente |
| 07 | DCSync | 4662, 4929 | ⬜ Pendiente |
| 08 | Golden Ticket | 4768, 4769 | ⬜ Pendiente |
| 09 | Kerberos Constrained Delegation | 4769 | ⬜ Pendiente |
| 10 | Print Spooler & NTLM Relaying | 4648, 4624 | ⬜ Pendiente |
| 11 | Coercing & Unconstrained Delegation | 4768 | ⬜ Pendiente |
| 12 | Object ACLs | 4662, 5136 | ⬜ Pendiente |
| 13 | PKI - ESC1 | 4886, 4887 | ⬜ Pendiente |

---

## Entorno de laboratorio

Este proyecto fue construido y probado en el siguiente entorno:

| Máquina | SO | IP | Rol |
|---------|----|----|-----|
| DC01 | Windows Server 2022 | 100.100.100.50 | Controlador de dominio |
| WS01 | Windows 10 Enterprise | 100.100.100.40 | Cliente unido al dominio |
| Kali | Kali Linux 2024 | 100.100.100.20 | Atacante |

Dominio: `adlab.local`

Consulta [lab-setup/setup_es.md](lab-setup/setup_es.md) para la guía completa de montaje del entorno.

---

## Estructura del repositorio

```
AD_Attack_Detection/
│
├── README.md
├── README_ES.md
│
├── lab-setup/
│   ├── setup_en.md
│   └── setup_es.md
│
├── attacks/
│   ├── 01_AS-REProasting/
│   │   ├── attack_en.md
│   │   ├── attack_es.md
│   │   └── detection.ps1
│   ├── 02_Kerberoasting/
│   └── ...
│
└── detection/
    └── AD-ThreatDetector.ps1
```

---

## Requisitos

- Windows Server 2016 o posterior
- PowerShell 5.1 o posterior
- Privilegios de administrador en el Controlador de Dominio
- Políticas de auditoría habilitadas (ver guía de configuración)

---

## Inicio rápido

```powershell
# Clonar el repositorio
git clone https://github.com/JorgeGonzalezVlc/AD_Attack_Detection.git

# Ejecutar el script de detección
cd AD_Attack_Detection\detection
.\AD-ThreatDetector.ps1

# El informe HTML se abrirá automáticamente
```

---

## Contribuciones

Este proyecto está en desarrollo activo. Cada módulo de ataque está documentado de forma independiente para que puedas contribuir a detecciones individuales sin tocar el resto del código.

Los pull requests son bienvenidos.

---

## Aviso legal

Este proyecto está destinado **únicamente a fines educativos y defensivos**. Todas las simulaciones de ataques se realizaron en un entorno de laboratorio aislado. Nunca utilices estas técnicas contra sistemas que no sean de tu propiedad o para los que no tengas permiso explícito.

---

## Licencia

Licencia MIT — consulta [LICENSE](LICENSE) para más detalles.

---

*Desarrollado por [@JorgeGonzalezVlc](https://github.com/JorgeGonzalezVlc)*
