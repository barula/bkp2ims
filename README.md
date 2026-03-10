# bkp2ims — ECS Backup Scheduler

Aplicación web para programar y gestionar backups automáticos de instancias ECS de Huawei Cloud mediante imágenes IMS, con soporte para externalización a OBS.

## Características

- Backup automático de discos de sistema y datos vía IMS
- **Exportación a OBS**: externaliza imágenes al bucket `bkp2ims-{project_id}` con un clic
- **Restauración desde OBS**: importa automáticamente desde OBS si la imagen IMS fue eliminada
- Paralelismo: todos los discos se respaldan simultáneamente
- Retención configurable (elimina backups viejos automáticamente)
- Interfaz web para gestionar programaciones, historial y restauraciones
- Soporte para selección individual de discos por ECS

## Instalación rápida (v0.4.x — última versión)

En una ECS de Huawei Cloud con Ubuntu Server 24.04 y agencia IAM asignada:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/barula/bkp2ims/main/install.sh)
```

### Instalar versión estable anterior (v0.2.x — sin OBS)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/barula/bkp2ims/v0.2.1/install.sh)
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
  - `OBS OperateAccess` *(requerido para exportar/importar a OBS)*
- Security Group con puertos 80 y 443 abiertos
- EIP asignada

## Flujo de externalización a OBS

1. El backup crea imágenes IMS normalmente
2. El botón **OBS** exporta las imágenes al bucket `bkp2ims-{project_id}` (formato zvhd2)
3. Los backups exportados muestran el tag **external** en la UI
4. Si se elimina la imagen IMS, el backup queda marcado como **solo OBS**
5. El botón **Restaurar** importa desde OBS automáticamente cuando la imagen IMS no está disponible

El bucket se crea automáticamente en el primer export si la agencia tiene `OBS OperateAccess`.

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
- **Cloud**: Huawei Cloud ECS + IMS + EVS + OBS
