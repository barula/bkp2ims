# Guía de despliegue — bkp2ims

Despliegue desde cero en Ubuntu Server 24.04 sobre una ECS de Huawei Cloud.

---

## Requisitos previos

### ECS mínima recomendada
- **OS**: Ubuntu Server 24.04 LTS
- **Flavor**: s6.medium.2 (1 vCPU, 2 GB RAM) o superior
- **Disco**: 20 GB sistema
- **Red**: EIP asignada (para acceso web y SSH)
- **Rol de agencia**: la ECS debe tener una agencia IAM con permisos sobre ECS, EVS e IMS
  - Permisos mínimos: `ECS FullAccess`, `IMS FullAccess`, `EVS FullAccess`

### Puerto abierto en el Security Group
| Puerto | Protocolo | Origen | Uso |
|--------|-----------|--------|-----|
| 22     | TCP       | tu IP  | SSH |
| 80     | TCP       | 0.0.0.0/0 | HTTP (UI) |
| 443    | TCP       | 0.0.0.0/0 | HTTPS (opcional) |

---

## 1. Preparar el servidor

```bash
apt update && apt upgrade -y
apt install -y git curl
```

---

## 2. Instalar Docker

```bash
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker
```

Verificar:
```bash
docker version
docker compose version
```

---

## 3. Clonar el repositorio

```bash
git clone https://github.com/barula/bkp2ims.git /opt/bkp2ims
cd /opt/bkp2ims
```

---

## 4. Configurar variables de entorno

Editar `docker-compose.yml` y ajustar las variables del servicio `app`:

```yaml
environment:
  - HWC_REGION=sa-argentina-1          # región de la ECS objetivo
  - HWC_PROJECT_ID=<tu-project-id>     # ID del proyecto HWC
  - DB_PATH=/data/backup.db
```

Para obtener el Project ID:
- Consola HWC → esquina superior derecha → *Mi credencial* → columna *ID de proyecto*

> **Nota:** Las credenciales AK/SK se obtienen automáticamente desde el metadata de la ECS
> (`169.254.169.254`), siempre que la ECS tenga una agencia IAM asignada. No es necesario
> configurar claves manualmente.

---

## 5. Configurar el dominio o IP (Caddyfile)

El `Caddyfile` incluido escucha en el puerto 80 sin dominio. Para acceso por IP pública
no se necesita modificar nada.

Si querés HTTPS con un dominio propio, reemplazá `:80` por tu dominio:

```
backup.miempresa.com {
    reverse_proxy app:8000
    encode gzip
}
```

Caddy obtiene el certificado TLS automáticamente via Let's Encrypt.

---

## 6. Construir y levantar

```bash
cd /opt/bkp2ims
docker compose up --build -d
```

Verificar que los contenedores estén corriendo:
```bash
docker compose ps
docker compose logs app --tail 20
```

La app debería mostrar:
```
INFO App started. Region=sa-argentina-1 ProjectID=...
```

---

## 7. Verificar el estado

```bash
curl http://localhost:80/api/status
```

Respuesta esperada:
```json
{"ok": true, "expires_at": "...", "region": "sa-argentina-1", "project_id": "..."}
```

Si `ok` es `false`, revisar que la ECS tenga la agencia IAM configurada correctamente.

---

## 8. Acceder a la UI

Abrir en el navegador:
```
http://<EIP-del-servidor>
```

---

## Actualizar a una versión nueva

```bash
cd /opt/bkp2ims
git pull
docker compose up --build -d app
```

La base de datos persiste en el volumen `app-data` — las programaciones y el historial
no se pierden con las actualizaciones.

---

## Estructura del proyecto

```
bkp2ims/
├── docker-compose.yml       # orquestación: app (Flask/Gunicorn) + Caddy
├── Caddyfile                # configuración del reverse proxy
└── backend/
    ├── Dockerfile           # Python 3.12-slim + gunicorn
    ├── requirements.txt     # flask, apscheduler, requests, gunicorn
    ├── app.py               # lógica principal (API + scheduler + backup/restore)
    └── static/
        └── index.html       # UI single-page
```

---

## Troubleshooting

| Síntoma | Causa probable | Solución |
|---------|---------------|----------|
| `ok: false` en `/api/status` | Sin agencia IAM o expirada | Asignar agencia a la ECS en consola HWC |
| Backup falla con `No se pudieron obtener los volúmenes` | Error de red al metadata | Verificar que la ECS tenga agencia y red interna OK |
| Puerto 80 no responde | Caddy no inició | `docker compose logs caddy` |
| `IMG.0079` en backup | Imagen Marketplace sin permisos de clonación | El backup usa `instance_id` — debería resolverlo solo |

---

## Notas sobre la agencia IAM

En la consola HWC: **ECS → instancia → pestaña "Básico" → "Agencia"**

Si no existe una agencia, crearla en **IAM → Agencias**:
- Tipo: `Account service`
- Servicios de nube: `ECS`
- Políticas: `ECS FullAccess`, `IMS FullAccess`, `EVS FullAccess`

Luego asignarla a la ECS (requiere reinicio en algunos casos).
