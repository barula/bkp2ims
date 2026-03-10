# bkp2ims — ECS Backup Scheduler

Aplicación web para programar y gestionar backups automáticos de instancias ECS de Huawei Cloud mediante imágenes IMS.

## Características

- Backup automático de discos de sistema y datos vía IMS
- Restauración desde cualquier punto de backup
- Paralelismo: todos los discos se respaldan simultáneamente
- Retención configurable (elimina backups viejos automáticamente)
- Interfaz web para gestionar programaciones, historial y restauraciones
- Soporte para selección individual de discos por ECS

## Instalación rápida

En una ECS de Huawei Cloud con Ubuntu Server 24.04 y agencia IAM asignada:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/barula/bkp2ims/main/install.sh)
```

El script detecta automáticamente la región y el Project ID desde el metadata de la ECS. Si no los puede leer (sin agencia IAM), los solicita de forma interactiva.

### Opciones

```bash
# Pasar región y project_id directamente (sin prompts)
bash <(curl -fsSL https://raw.githubusercontent.com/barula/bkp2ims/main/install.sh) \
  --region sa-argentina-1 \
  --project-id <tu-project-id>

# Con dominio propio (HTTPS automático via Let's Encrypt)
bash <(curl -fsSL https://raw.githubusercontent.com/barula/bkp2ims/main/install.sh) \
  --domain backup.miempresa.com
```

Una vez instalado, la UI queda disponible en `http://<EIP-del-servidor>`.

## Requisitos

- Ubuntu Server 24.04 LTS
- ECS de Huawei Cloud con **agencia IAM** que tenga los permisos:
  - `ECS FullAccess`
  - `IMS FullAccess`
  - `EVS FullAccess`
- Security Group con puertos 80 y 443 abiertos
- EIP asignada

## Actualizar

```bash
cd /opt/bkp2ims && git pull && docker compose up --build -d app
```

## Documentación completa

Ver [DEPLOY.md](DEPLOY.md) para instrucciones detalladas, configuración de agencia IAM y troubleshooting.

## Stack

- **Backend**: Python 3.12 + Flask + APScheduler + Gunicorn
- **Frontend**: HTML/JS vanilla (single-page, sin dependencias externas)
- **Proxy**: Caddy 2 (HTTP/HTTPS automático)
- **Base de datos**: SQLite (persistida en volumen Docker)
- **Cloud**: Huawei Cloud ECS + IMS + EVS
