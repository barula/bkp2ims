import os
import json
import hmac
import hashlib
import datetime
import threading
import sqlite3
import time
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlencode, quote
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static', static_url_path='')
CORS(app)

REGION = os.environ.get('HWC_REGION', 'sa-argentina-1')
PROJECT_ID = os.environ.get('HWC_PROJECT_ID', '')
DB_PATH = os.environ.get('DB_PATH', '/data/backup.db')
METADATA_URL = 'http://169.254.169.254/openstack/latest/securitykey'
META_URL = 'http://169.254.169.254/openstack/latest/meta_data.json'

ECS_ENDPOINT = 'https://ecs.{}.myhuaweicloud.com'.format(REGION)
EVS_ENDPOINT = 'https://evs.{}.myhuaweicloud.com'.format(REGION)
IMS_ENDPOINT = 'https://ims.{}.myhuaweicloud.com'.format(REGION)
VBS_ENDPOINT = 'https://vbs.{}.myhuaweicloud.com'.format(REGION)

# ── Credentials ──────────────────────────────────────────────────────────────

_cred_cache = {}
_cred_lock = threading.Lock()

def get_credentials():
    with _cred_lock:
        if _cred_cache.get('ak'):
            try:
                expires = datetime.datetime.fromisoformat(
                    _cred_cache['expires_at'].replace('Z', '+00:00'))
                if datetime.datetime.now(datetime.timezone.utc) < expires - datetime.timedelta(minutes=5):
                    return dict(_cred_cache)
            except Exception:
                pass
        try:
            r = requests.get(METADATA_URL, timeout=5)
            r.raise_for_status()
            cred = r.json()['credential']
            _cred_cache.update({
                'ak': cred['access'],
                'sk': cred['secret'],
                'token': cred['securitytoken'],
                'expires_at': cred['expires_at'],
            })
            log.info('Credentials refreshed, expires %s', _cred_cache['expires_at'])
            return dict(_cred_cache)
        except Exception as e:
            log.error('Failed to get credentials: %s', e)
            raise

def get_project_id():
    if PROJECT_ID:
        return PROJECT_ID
    try:
        r = requests.get(META_URL, timeout=5)
        return r.json().get('project_id', '')
    except Exception:
        return ''

# ── HWC API Signing ───────────────────────────────────────────────────────────
# Rules:
#  - Canonical URI: always append trailing '/' (APIGW normalizes path this way)
#  - X-Security-Token: pass as header but DO NOT include in SignedHeaders
#  - SK used directly (no key derivation, unlike AWS v4)

def hwc_request(method, url, body=None, params=None, content_type='application/json'):
    cred = get_credentials()
    ak, sk, token = cred['ak'], cred['sk'], cred['token']

    if params:
        # Use quote() not urlencode() — urlencode encodes spaces as '+' but
        # canonical query string requires '%20', causing signature mismatch
        qs_parts = ['%s=%s' % (quote(str(k), safe=''), quote(str(v), safe=''))
                    for k, v in sorted(params.items())]
        sep = '&' if '?' in url else '?'
        url = url + sep + '&'.join(qs_parts)

    parsed = urlparse(url)
    host = parsed.netloc
    # Canonical URI: URL-encode each path segment, append trailing slash
    raw_path = parsed.path or '/'
    segments = raw_path.split('/')
    encoded_segments = [quote(s, safe='') for s in segments]
    canonical_path = '/'.join(encoded_segments)
    if not canonical_path.endswith('/'):
        canonical_path += '/'

    query = parsed.query

    now = datetime.datetime.now(datetime.timezone.utc)
    timestamp = now.strftime('%Y%m%dT%H%M%SZ')

    body_str = json.dumps(body) if body is not None else ''

    # Only sign: content-type, host, x-sdk-date (NOT x-security-token)
    headers_to_sign = {
        'content-type': content_type,
        'host': host,
        'x-sdk-date': timestamp,
    }

    signed_keys = sorted(headers_to_sign.keys())
    canonical_headers = ''.join('%s:%s\n' % (k, headers_to_sign[k]) for k in signed_keys)
    signed_headers = ';'.join(signed_keys)

    # Canonical query string: sort and encode params
    if query:
        pairs = []
        for part in query.split('&'):
            if '=' in part:
                k, v = part.split('=', 1)
            else:
                k, v = part, ''
            pairs.append((quote(k, safe=''), quote(v, safe='')))
        canonical_qs = '&'.join('%s=%s' % (k, v) for k, v in sorted(pairs))
    else:
        canonical_qs = ''

    body_hash = hashlib.sha256(body_str.encode('utf-8')).hexdigest()

    canonical_request = '\n'.join([
        method.upper(),
        canonical_path,
        canonical_qs,
        canonical_headers,
        signed_headers,
        body_hash,
    ])

    cr_hash = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
    string_to_sign = 'SDK-HMAC-SHA256\n%s\n%s' % (timestamp, cr_hash)
    sig = hmac.new(sk.encode('utf-8'), string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

    auth = 'SDK-HMAC-SHA256 Access=%s, SignedHeaders=%s, Signature=%s' % (ak, signed_headers, sig)

    req_headers = {
        'X-Sdk-Date': timestamp,
        'Authorization': auth,
        'Content-Type': content_type,
        'X-Security-Token': token,
    }

    resp = requests.request(
        method.upper(), url,
        headers=req_headers,
        data=body_str if body_str else None,
        timeout=30,
    )
    return resp

# ── Database ──────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    # Migrations: add columns if missing
    for migration in [
        'ALTER TABLE schedules ADD COLUMN selected_volumes TEXT DEFAULT "[]"',
        'ALTER TABLE backup_snapshots ADD COLUMN volume_role TEXT DEFAULT "data"',
        'ALTER TABLE backup_snapshots ADD COLUMN backup_type TEXT DEFAULT "ims_image"',
        'ALTER TABLE backup_snapshots ADD COLUMN device TEXT',
        'ALTER TABLE backup_snapshots ADD COLUMN volume_type TEXT',
    ]:
        try:
            conn.execute(migration)
            conn.commit()
        except Exception:
            pass
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ecs_id TEXT NOT NULL,
            ecs_name TEXT NOT NULL,
            frequency_hours INTEGER NOT NULL DEFAULT 24,
            retention_count INTEGER NOT NULL DEFAULT 7,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            last_run TEXT,
            next_run TEXT,
            selected_volumes TEXT DEFAULT "[]"
        );
        CREATE TABLE IF NOT EXISTS job_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            schedule_id INTEGER,
            schedule_name TEXT,
            ecs_id TEXT,
            ecs_name TEXT,
            image_id TEXT,
            image_name TEXT,
            status TEXT NOT NULL,
            message TEXT,
            started_at TEXT NOT NULL,
            finished_at TEXT
        );
        CREATE TABLE IF NOT EXISTS backup_images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            schedule_id INTEGER,
            ecs_id TEXT,
            ecs_name TEXT,
            image_id TEXT UNIQUE,
            image_name TEXT,
            created_at TEXT NOT NULL,
            deleted INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS backup_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            backup_image_id INTEGER,
            schedule_id INTEGER,
            ecs_id TEXT,
            snapshot_id TEXT UNIQUE,
            snapshot_name TEXT,
            volume_id TEXT,
            volume_role TEXT DEFAULT "data",
            backup_type TEXT DEFAULT "ims_image",
            size_gb INTEGER,
            device TEXT,
            volume_type TEXT,
            created_at TEXT NOT NULL,
            deleted INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS restore_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            backup_image_id INTEGER,
            ecs_id TEXT,
            ecs_name TEXT,
            status TEXT NOT NULL,
            message TEXT,
            started_at TEXT NOT NULL,
            finished_at TEXT
        );
    ''')
    conn.commit()
    conn.close()

# ── Volume Helper ────────────────────────────────────────────────────────────

def fetch_ecs_volumes(ecs_id):
    """Return a list of volume dicts for the given ECS."""
    project_id = get_project_id()
    try:
        url = '%s/v2/%s/servers/%s' % (ECS_ENDPOINT, project_id, ecs_id)
        r = hwc_request('GET', url)
        if r.status_code != 200:
            return []
        server = r.json().get('server', {})
        attachments = server.get('os-extended-volumes:volumes_attached', [])
        volumes = []
        for va in attachments:
            vol_id = va.get('id')
            if not vol_id:
                continue
            vr = hwc_request('GET', '%s/v2/%s/volumes/%s' % (EVS_ENDPOINT, project_id, vol_id))
            if vr.status_code == 200:
                v = vr.json().get('volume', {})
                device = ''
                for att in v.get('attachments', []):
                    if att.get('server_id') == ecs_id:
                        device = att.get('device', '')
                        break
                volumes.append({
                    'id': vol_id,
                    'device': device,
                    'name': v.get('name') or vol_id[:8],
                    'type': v.get('volume_type', ''),
                    'size': v.get('size'),
                    'status': v.get('status', ''),
                    'bootable': v.get('bootable', 'false'),
                })
        volumes.sort(key=lambda v: (v.get('bootable') != 'true', v.get('device', '')))
        return volumes
    except Exception as e:
        log.warning('fetch_ecs_volumes error: %s', e)
        return []

# ── EVS / VBS Primitives ──────────────────────────────────────────────────────

def _poll_volume_status(vol_id, target_status, timeout=600):
    """Poll EVS volume until it reaches target_status."""
    project_id = get_project_id()
    url = '%s/v2/%s/volumes/%s' % (EVS_ENDPOINT, project_id, vol_id)
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = hwc_request('GET', url)
        if r.status_code == 200:
            status = r.json().get('volume', {}).get('status', '')
            if status == target_status:
                return
            if 'error' in status:
                raise Exception('Volume %s in error state: %s' % (vol_id[:8], status))
        time.sleep(10)
    raise Exception('Volume %s did not reach %s within %ds' % (vol_id[:8], target_status, timeout))

def _evs_create_snapshot(vol_id, name, description=''):
    """Create EVS snapshot with force=True (works on in-use volumes). Returns snapshot_id after available."""
    project_id = get_project_id()
    body = {'snapshot': {'volume_id': vol_id, 'name': name, 'description': description, 'force': True}}
    r = hwc_request('POST', '%s/v2/%s/snapshots' % (EVS_ENDPOINT, project_id), body=body)
    if r.status_code not in (200, 202):
        raise Exception('Create snapshot HTTP %s: %s' % (r.status_code, r.text[:300]))
    snap_id = r.json().get('snapshot', {}).get('id')
    if not snap_id:
        raise Exception('No snapshot id in response')
    snap_url = '%s/v2/%s/snapshots/%s' % (EVS_ENDPOINT, project_id, snap_id)
    deadline = time.time() + 1800
    while time.time() < deadline:
        sr = hwc_request('GET', snap_url)
        if sr.status_code == 200:
            status = sr.json().get('snapshot', {}).get('status', '')
            if status == 'available':
                return snap_id
            if status == 'error':
                raise Exception('Snapshot %s in error state' % snap_id[:8])
        time.sleep(15)
    raise Exception('Snapshot %s timed out' % snap_id[:8])

def _evs_delete_snapshot(snap_id):
    """Delete an EVS snapshot."""
    project_id = get_project_id()
    r = hwc_request('DELETE', '%s/v2/%s/snapshots/%s' % (EVS_ENDPOINT, project_id, snap_id))
    if r.status_code not in (200, 202, 204, 404):
        log.warning('Delete snapshot %s: HTTP %s %s', snap_id[:8], r.status_code, r.text[:150])

def _vbs_create_backup(vol_id, snap_id, name, description=''):
    """Create VBS backup from snapshot. Returns backup_id after available."""
    project_id = get_project_id()
    body = {'backup': {'volume_id': vol_id, 'snapshot_id': snap_id, 'name': name, 'description': description}}
    r = hwc_request('POST', '%s/v2/%s/backups' % (VBS_ENDPOINT, project_id), body=body)
    if r.status_code not in (200, 202):
        raise Exception('VBS backup HTTP %s: %s' % (r.status_code, r.text[:300]))
    backup_id = r.json().get('backup', {}).get('id')
    if not backup_id:
        raise Exception('No backup id in VBS response')
    bkp_url = '%s/v2/%s/backups/%s' % (VBS_ENDPOINT, project_id, backup_id)
    deadline = time.time() + 3600
    while time.time() < deadline:
        br = hwc_request('GET', bkp_url)
        if br.status_code == 200:
            status = br.json().get('backup', {}).get('status', '')
            if status == 'available':
                return backup_id
            if status == 'error':
                raise Exception('VBS backup %s in error state' % backup_id[:8])
        time.sleep(30)
    raise Exception('VBS backup %s timed out' % backup_id[:8])

def _vbs_restore_disk(backup_id, vol_id):
    """Restore VBS backup in-place to volume. Volume must be available (detached)."""
    project_id = get_project_id()
    url = '%s/v2/%s/backups/%s/restore' % (VBS_ENDPOINT, project_id, backup_id)
    body = {'restore': {'volume_id': vol_id}}
    r = hwc_request('POST', url, body=body)
    if r.status_code not in (200, 202):
        raise Exception('VBS restore HTTP %s: %s' % (r.status_code, r.text[:300]))
    _poll_volume_status(vol_id, 'available', timeout=600)
    log.info('VBS backup %s restored to volume %s', backup_id[:8], vol_id[:8])

def _detach_volume_and_wait(ecs_id, vol_id, timeout=300):
    """Detach volume from ECS and wait until available."""
    project_id = get_project_id()
    url = '%s/v2/%s/servers/%s/os-volume_attachments/%s' % (ECS_ENDPOINT, project_id, ecs_id, vol_id)
    r = hwc_request('DELETE', url)
    if r.status_code not in (200, 202, 204):
        raise Exception('Detach volume %s HTTP %s: %s' % (vol_id[:8], r.status_code, r.text[:200]))
    _poll_volume_status(vol_id, 'available', timeout=timeout)
    log.info('Volume %s detached', vol_id[:8])

def _attach_volume_and_wait(ecs_id, vol_id, device, timeout=120):
    """Attach volume to ECS at given device path and wait until in-use."""
    project_id = get_project_id()
    url = '%s/v2/%s/servers/%s/os-volume_attachments' % (ECS_ENDPOINT, project_id, ecs_id)
    body = {'volumeAttachment': {'volumeId': vol_id, 'device': device}}
    r = hwc_request('POST', url, body=body)
    if r.status_code not in (200, 202):
        raise Exception('Attach volume %s HTTP %s: %s' % (vol_id[:8], r.status_code, r.text[:200]))
    _poll_volume_status(vol_id, 'in-use', timeout=timeout)
    log.info('Volume %s attached at %s', vol_id[:8], device)

# ── VBS Backup Pipeline ───────────────────────────────────────────────────────

def _register_disk_backup(conn, backup_row_id, schedule_id, ecs_id, backup_id, backup_name,
                          volume_id, size_gb, device='', volume_type=''):
    """Register a VBS backup entry in backup_snapshots table."""
    now_str = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    conn.execute(
        'INSERT INTO backup_snapshots '
        '(backup_image_id, schedule_id, ecs_id, snapshot_id, snapshot_name, volume_id, volume_role, backup_type, size_gb, device, volume_type, created_at) '
        'VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
        (backup_row_id, schedule_id, ecs_id,
         backup_id, backup_name, volume_id, 'disk', 'vbs_backup',
         size_gb or 0, device or '', volume_type or '', now_str)
    )

def _vbs_backup_disk(vol, backup_row_id, schedule_id, ecs_id, ts, description):
    """Full VBS backup pipeline for one disk: snapshot → VBS backup → delete snapshot → register in DB.
    Snapshot and VBS backup run sequentially within each disk's thread, but all disks run in parallel.
    As soon as a disk's snapshot is available, VBS backup fires immediately (no waiting for other disks).
    """
    vol_safe = ''.join(c if c.isalnum() or c == '-' else '-' for c in vol.get('name', 'vol'))[:20]
    snap_name = 'snap-%s-%s' % (vol_safe, ts)
    bkp_name = 'vbs-%s-%s' % (vol_safe, ts)

    log.info('VBS backup: creating snapshot for volume %s (%s GB) device=%s',
             vol['id'][:8], vol.get('size'), vol.get('device', ''))
    snap_id = _evs_create_snapshot(vol['id'], snap_name, description)
    log.info('Snapshot %s available for volume %s, firing VBS backup', snap_id[:8], vol['id'][:8])

    backup_id = _vbs_create_backup(vol['id'], snap_id, bkp_name, description)
    log.info('VBS backup %s available for volume %s', backup_id[:8], vol['id'][:8])

    # Delete snapshot now that VBS backup is complete
    try:
        _evs_delete_snapshot(snap_id)
        log.info('Snapshot %s deleted', snap_id[:8])
    except Exception as e:
        log.warning('Failed to delete snapshot %s: %s', snap_id[:8], e)

    conn = get_db()
    _register_disk_backup(conn, backup_row_id, schedule_id, ecs_id,
                          backup_id, bkp_name, vol['id'], vol.get('size'),
                          vol.get('device', ''), vol.get('type', ''))
    conn.commit()
    conn.close()
    log.info('VBS backup registered: %s device=%s', backup_id[:8], vol.get('device', ''))
    return bkp_name

# ── Delete Logic ──────────────────────────────────────────────────────────────

def delete_image_and_snapshots(img_id, img_name, backup_image_row_id):
    """Delete backup resources from cloud and mark as deleted in DB."""
    project_id = get_project_id()

    # Legacy IMS system disk image (not a VBS placeholder)
    if img_id and not img_id.startswith('vbs-') and img_id != 'data-only':
        try:
            r = hwc_request('DELETE', '%s/v2/images/%s' % (IMS_ENDPOINT, img_id))
            if r.status_code in (200, 204, 404):
                log.info('Deleted IMS image %s (%s) [HTTP %s]', img_id, img_name, r.status_code)
            else:
                log.warning('Delete IMS image %s: HTTP %s %s', img_id, r.status_code, r.text[:150])
        except Exception as e:
            log.error('Delete IMS image %s error: %s', img_id, e)

    # Mark backup_images row deleted
    conn = get_db()
    conn.execute('UPDATE backup_images SET deleted=1 WHERE id=?', (backup_image_row_id,))
    conn.commit()
    conn.close()

    # Delete associated disk backup entries
    conn = get_db()
    items = conn.execute(
        'SELECT snapshot_id, snapshot_name, backup_type FROM backup_snapshots WHERE backup_image_id=? AND deleted=0',
        (backup_image_row_id,)
    ).fetchall()
    conn.close()

    for item in items:
        try:
            btype = item['backup_type']
            if btype == 'vbs_backup':
                r = hwc_request('DELETE', '%s/v2/%s/backups/%s' % (VBS_ENDPOINT, project_id, item['snapshot_id']))
            elif btype == 'evs_snapshot':
                r = hwc_request('DELETE', '%s/v2/%s/snapshots/%s' % (EVS_ENDPOINT, project_id, item['snapshot_id']))
            else:
                # Legacy IMS data image
                r = hwc_request('DELETE', '%s/v2/images/%s' % (IMS_ENDPOINT, item['snapshot_id']))

            if r.status_code in (200, 202, 204, 404):
                log.info('Deleted %s item %s (%s) [HTTP %s]',
                         btype, item['snapshot_id'], item['snapshot_name'], r.status_code)
                conn = get_db()
                conn.execute('UPDATE backup_snapshots SET deleted=1 WHERE snapshot_id=?', (item['snapshot_id'],))
                conn.commit()
                conn.close()
            else:
                log.warning('Delete %s item %s: HTTP %s %s',
                            btype, item['snapshot_id'], r.status_code, r.text[:150])
        except Exception as e:
            log.error('Delete item %s error: %s', item['snapshot_id'], e)

def apply_retention(schedule_id, ecs_id, retention_count):
    """Delete oldest backup images beyond retention_count for this schedule."""
    conn = get_db()
    rows = conn.execute(
        'SELECT id, image_id, image_name FROM backup_images WHERE schedule_id=? AND ecs_id=? AND deleted=0 ORDER BY created_at ASC',
        (schedule_id, ecs_id)
    ).fetchall()
    conn.close()

    excess = len(rows) - retention_count
    if excess <= 0:
        return
    for row in rows[:excess]:
        delete_image_and_snapshots(row['image_id'], row['image_name'], row['id'])

# ── Backup Logic ──────────────────────────────────────────────────────────────

def run_backup(schedule_id):
    """Execute a VBS backup for a given schedule. All disks backed up in parallel."""
    project_id = get_project_id()
    conn = get_db()
    sched = conn.execute('SELECT * FROM schedules WHERE id=?', (schedule_id,)).fetchone()
    conn.close()

    if not sched or not sched['enabled']:
        return
    sched = dict(sched)

    now_str = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    ts = datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')
    safe_name = ''.join(c if c.isalnum() or c == '-' else '-' for c in sched['ecs_name'])[:30].strip('-')
    image_name = 'bkp-%s-%s' % (safe_name, ts)
    # VBS backups use a timestamp-based placeholder as image_id (unique per backup run)
    vbs_image_id = 'vbs-%s' % ts

    conn = get_db()
    cur = conn.execute(
        'INSERT INTO job_history (schedule_id, schedule_name, ecs_id, ecs_name, status, started_at) VALUES (?,?,?,?,?,?)',
        (schedule_id, sched['name'], sched['ecs_id'], sched['ecs_name'], 'running', now_str)
    )
    job_id_db = cur.lastrowid
    conn.execute('UPDATE schedules SET last_run=? WHERE id=?', (now_str, schedule_id))
    conn.commit()
    conn.close()

    log.info('Starting VBS backup: schedule=%s ecs=%s', schedule_id, sched['ecs_name'])

    try:
        # Determine which volumes to back up
        selected_vol_ids = json.loads(sched.get('selected_volumes') or '[]')
        all_vols = fetch_ecs_volumes(sched['ecs_id'])
        if selected_vol_ids:
            target_vols = [v for v in all_vols if v['id'] in selected_vol_ids]
        else:
            target_vols = all_vols

        if not all_vols:
            raise Exception('No se pudieron obtener los volúmenes de la ECS (API vacía o error de red)')
        if not target_vols:
            raise Exception('Ningún volumen seleccionado coincide con los discos actuales de la ECS')

        # Build description
        vol_lines = []
        for v in target_vols:
            rol = 'Sistema' if v.get('device') == '/dev/vda' else 'Datos'
            vol_lines.append('%s | %s | %s | %s GB | %s | %s' % (
                v.get('device', '-'), v.get('name', '-'), v.get('type', '-'),
                v.get('size', '?'), v.get('status', '-'), rol))
        description = ('Backup automatico. Programacion: %s. Discos: %s' % (
            sched['name'], ' | '.join(vol_lines) if vol_lines else '-'))[:255]

        # Create header row in backup_images before launching disk threads
        conn = get_db()
        cur = conn.execute(
            'INSERT INTO backup_images (schedule_id, ecs_id, ecs_name, image_id, image_name, created_at) VALUES (?,?,?,?,?,?)',
            (schedule_id, sched['ecs_id'], sched['ecs_name'], vbs_image_id, image_name, now_str)
        )
        backup_row_id = cur.lastrowid
        conn.commit()
        conn.close()

        # Back up all disks in parallel — each disk independently runs snapshot → VBS backup
        log.info('VBS: backing up %d disk(s) in parallel', len(target_vols))
        with ThreadPoolExecutor(max_workers=len(target_vols)) as executor:
            futures = {
                executor.submit(_vbs_backup_disk, vol, backup_row_id,
                                schedule_id, sched['ecs_id'], ts, description): vol
                for vol in target_vols
            }
            errors = []
            for future in as_completed(futures):
                vol = futures[future]
                try:
                    future.result()
                except Exception as e:
                    errors.append('device %s: %s' % (vol.get('device', vol['id'][:8]), e))
                    log.error('VBS backup failed for %s: %s', vol.get('device', ''), e)
            if errors:
                raise Exception('Fallo backup de disco(s): ' + '; '.join(errors))

        # Finalize job history
        finished_str = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        msg = 'VBS: %d disco(s) respaldado(s)' % len(target_vols)
        conn = get_db()
        conn.execute(
            'UPDATE job_history SET status=?, image_id=?, image_name=?, finished_at=?, message=? WHERE id=?',
            ('success', vbs_image_id, image_name, finished_str, msg, job_id_db)
        )
        conn.commit()
        conn.close()
        log.info('VBS backup success for schedule %s', schedule_id)
        apply_retention(schedule_id, sched['ecs_id'], sched['retention_count'])

    except Exception as e:
        import traceback
        finished_str = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        log.error('Backup failed for schedule %s: %s\n%s', schedule_id, e, traceback.format_exc())
        conn = get_db()
        conn.execute(
            'UPDATE job_history SET status=?, message=?, finished_at=? WHERE id=?',
            ('failed', str(e)[:500], finished_str, job_id_db)
        )
        conn.commit()
        conn.close()

    next_run = (datetime.datetime.utcnow() +
                datetime.timedelta(hours=sched['frequency_hours'])).strftime('%Y-%m-%dT%H:%M:%SZ')
    conn = get_db()
    conn.execute('UPDATE schedules SET next_run=? WHERE id=?', (next_run, schedule_id))
    conn.commit()
    conn.close()

# ── Restore Logic ─────────────────────────────────────────────────────────────

def get_ecs_status(ecs_id):
    """Return ECS status string (ACTIVE, SHUTOFF, etc.) or None on error."""
    project_id = get_project_id()
    try:
        r = hwc_request('GET', '%s/v2/%s/servers/%s' % (ECS_ENDPOINT, project_id, ecs_id))
        if r.status_code == 200:
            return r.json().get('server', {}).get('status')
    except Exception:
        pass
    return None

def wait_ecs_state(ecs_id, target_state, timeout=600):
    """Poll ECS status until it matches target_state. Raises on timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = get_ecs_status(ecs_id)
        if status == target_state:
            return
        time.sleep(10)
    raise Exception('ECS %s no alcanzó estado %s en %ds' % (ecs_id[:8], target_state, timeout))

def stop_ecs_and_wait(ecs_id):
    """Stop ECS if not already SHUTOFF. Waits until SHUTOFF."""
    status = get_ecs_status(ecs_id)
    if status == 'SHUTOFF':
        return
    project_id = get_project_id()
    r = hwc_request('POST', '%s/v2/%s/servers/%s/action' % (ECS_ENDPOINT, project_id, ecs_id),
                    body={'os-stop': {}})
    if r.status_code not in (200, 202, 204):
        raise Exception('Stop ECS HTTP %s: %s' % (r.status_code, r.text[:200]))
    wait_ecs_state(ecs_id, 'SHUTOFF', timeout=300)
    log.info('ECS %s stopped', ecs_id[:8])

def start_ecs_and_wait(ecs_id):
    """Start ECS and wait until ACTIVE. No-op if already running."""
    status = get_ecs_status(ecs_id)
    if status == 'ACTIVE':
        log.info('ECS %s already ACTIVE, nothing to do', ecs_id[:8])
        return
    project_id = get_project_id()
    r = hwc_request('POST', '%s/v2/%s/servers/%s/action' % (ECS_ENDPOINT, project_id, ecs_id),
                    body={'os-start': {}})
    # 409 means ECS is already starting — treat as success
    if r.status_code == 409:
        log.info('ECS %s already starting (409), waiting for ACTIVE', ecs_id[:8])
    elif r.status_code not in (200, 202, 204):
        raise Exception('Start ECS HTTP %s: %s' % (r.status_code, r.text[:200]))
    wait_ecs_state(ecs_id, 'ACTIVE', timeout=300)
    log.info('ECS %s started', ecs_id[:8])

def _run_parallel(tasks, label_fn, error_prefix):
    """Run dict of {future: item} tasks, collect errors. Returns list of errors."""
    errors = []
    for future, item in tasks.items():
        label = label_fn(item)
        try:
            future.result()
            log.info('%s completed: %s', error_prefix, label)
        except Exception as e:
            errors.append('%s: %s' % (label, e))
            log.error('%s failed for %s: %s', error_prefix, label, e)
    return errors

def run_restore(backup_image_id):
    """Execute full VBS restore for a backup (all disks) in a background thread.
    Flow: Stop ECS → Detach all (parallel) → VBS restore all (parallel) → Reattach all (parallel) → Start ECS
    """
    conn = get_db()
    bimg = conn.execute('SELECT * FROM backup_images WHERE id=?', (backup_image_id,)).fetchone()
    if not bimg:
        conn.close()
        log.error('run_restore: backup_image_id=%s not found', backup_image_id)
        return
    bimg = dict(bimg)

    # Load all disk entries for this backup (both system and data)
    disk_items = conn.execute(
        'SELECT * FROM backup_snapshots WHERE backup_image_id=? AND deleted=0',
        (backup_image_id,)
    ).fetchall()
    disk_items = [dict(r) for r in disk_items]
    conn.close()

    now_str = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    conn = get_db()
    cur = conn.execute(
        'INSERT INTO restore_history (backup_image_id, ecs_id, ecs_name, status, started_at) VALUES (?,?,?,?,?)',
        (backup_image_id, bimg['ecs_id'], bimg['ecs_name'], 'running', now_str)
    )
    restore_id = cur.lastrowid
    conn.commit()
    conn.close()

    ecs_id = bimg['ecs_id']

    try:
        # Validate: all disk items need volume_id and device
        vbs_items = [i for i in disk_items if i.get('backup_type') == 'vbs_backup']
        if not vbs_items:
            raise Exception('No hay backups VBS en este punto de restauración')

        missing_device = [i for i in vbs_items if not i.get('device')]
        if missing_device:
            raise Exception('Disco(s) sin información de device: %s' %
                            ', '.join(i['snapshot_id'][:8] for i in missing_device))

        log.info('Restore %d: deteniendo ECS %s', restore_id, ecs_id[:8])
        stop_ecs_and_wait(ecs_id)

        # Detach all volumes in parallel
        log.info('Restore %d: desconectando %d disco(s) en paralelo', restore_id, len(vbs_items))
        with ThreadPoolExecutor(max_workers=len(vbs_items)) as executor:
            futures = {
                executor.submit(_detach_volume_and_wait, ecs_id, item['volume_id']): item
                for item in vbs_items if item.get('volume_id')
            }
            errors = _run_parallel(futures,
                                   lambda i: 'device %s' % i.get('device', i['volume_id'][:8]),
                                   'Detach')
        if errors:
            raise Exception('Fallo desconexión de discos: ' + '; '.join(errors))

        # VBS restore all volumes in parallel
        log.info('Restore %d: restaurando %d disco(s) en paralelo', restore_id, len(vbs_items))
        with ThreadPoolExecutor(max_workers=len(vbs_items)) as executor:
            futures = {
                executor.submit(_vbs_restore_disk, item['snapshot_id'], item['volume_id']): item
                for item in vbs_items
            }
            errors = _run_parallel(futures,
                                   lambda i: 'device %s' % i.get('device', i['volume_id'][:8]),
                                   'VBS restore')
        if errors:
            raise Exception('Fallo restauración VBS: ' + '; '.join(errors))

        # Reattach all volumes in parallel
        log.info('Restore %d: reconectando %d disco(s) en paralelo', restore_id, len(vbs_items))
        with ThreadPoolExecutor(max_workers=len(vbs_items)) as executor:
            futures = {
                executor.submit(_attach_volume_and_wait, ecs_id, item['volume_id'], item['device']): item
                for item in vbs_items if item.get('device')
            }
            errors = _run_parallel(futures,
                                   lambda i: 'device %s' % i.get('device', i['volume_id'][:8]),
                                   'Attach')
        if errors:
            raise Exception('Fallo reconexión de discos: ' + '; '.join(errors))

        log.info('Restore %d: iniciando ECS', restore_id)
        start_ecs_and_wait(ecs_id)

        finished_str = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        msg = '%d disco(s) restaurado(s) desde VBS' % len(vbs_items)
        conn = get_db()
        conn.execute(
            'UPDATE restore_history SET status=?, message=?, finished_at=? WHERE id=?',
            ('success', msg, finished_str, restore_id)
        )
        conn.commit()
        conn.close()
        log.info('Restore %d completado', restore_id)

    except Exception as e:
        import traceback
        finished_str = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        log.error('Restore %d fallido: %s\n%s', restore_id, e, traceback.format_exc())
        conn = get_db()
        conn.execute(
            'UPDATE restore_history SET status=?, message=?, finished_at=? WHERE id=?',
            ('failed', str(e)[:500], finished_str, restore_id)
        )
        conn.commit()
        conn.close()

# ── Scheduler ─────────────────────────────────────────────────────────────────

scheduler = BackgroundScheduler(daemon=True, job_defaults={'max_instances': 1},
                               executors={'default': {'type': 'threadpool', 'max_workers': 20}})

def schedule_job_id(sched_id):
    return 'backup_%s' % sched_id

def add_scheduler_job(sched_id, frequency_hours):
    jid = schedule_job_id(sched_id)
    if scheduler.get_job(jid):
        scheduler.remove_job(jid)
    scheduler.add_job(
        run_backup,
        trigger=IntervalTrigger(hours=frequency_hours),
        id=jid,
        args=[sched_id],
        replace_existing=True,
        misfire_grace_time=3600,
    )
    log.info('Scheduled job %s every %sh', jid, frequency_hours)

def remove_scheduler_job(sched_id):
    jid = schedule_job_id(sched_id)
    if scheduler.get_job(jid):
        scheduler.remove_job(jid)

def reload_schedules():
    conn = get_db()
    rows = conn.execute('SELECT * FROM schedules WHERE enabled=1').fetchall()
    conn.close()
    for row in rows:
        add_scheduler_job(row['id'], row['frequency_hours'])
    log.info('Loaded %d schedules', len(rows))

# ── API Routes ────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/status')
def api_status():
    try:
        cred = get_credentials()
        return jsonify({'ok': True, 'expires_at': cred['expires_at'], 'region': REGION, 'project_id': get_project_id()})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/api/ecs')
def api_list_ecs():
    project_id = get_project_id()
    try:
        url = '%s/v2/%s/servers/detail' % (ECS_ENDPOINT, project_id)
        r = hwc_request('GET', url)
        if r.status_code != 200:
            return jsonify({'error': r.text[:300]}), r.status_code
        servers = r.json().get('servers', [])
        result = []
        for s in servers:
            ips = []
            for _net, addrs in s.get('addresses', {}).items():
                for addr in addrs:
                    ips.append({'ip': addr.get('addr', ''), 'type': addr.get('OS-EXT-IPS:type', '')})

            vols = [v['id'] for v in s.get('os-extended-volumes:volumes_attached', [])]

            flavor_id = ''
            flavor_links = s.get('flavor', {}).get('links', [])
            if flavor_links:
                href = flavor_links[-1].get('href', '')
                flavor_id = href.rstrip('/').split('/')[-1]

            result.append({
                'id': s.get('id'),
                'name': s.get('name'),
                'status': s.get('status'),
                'vm_state': s.get('OS-EXT-STS:vm_state', ''),
                'flavor': flavor_id,
                'ips': ips,
                'volume_ids': vols,
                'created': s.get('created', ''),
                'az': s.get('OS-EXT-AZ:availability_zone', ''),
                'metadata': s.get('metadata', {}),
            })
        return jsonify({'servers': result})
    except Exception as e:
        log.exception('list ecs error')
        return jsonify({'error': str(e)}), 500

@app.route('/api/ecs/<ecs_id>/volumes')
def api_ecs_volumes(ecs_id):
    project_id = get_project_id()
    try:
        url = '%s/v2/%s/servers/%s' % (ECS_ENDPOINT, project_id, ecs_id)
        r = hwc_request('GET', url)
        if r.status_code != 200:
            return jsonify({'error': r.text[:300]}), r.status_code
        server = r.json().get('server', {})
        attachments = server.get('os-extended-volumes:volumes_attached', [])

        volumes = []
        for va in attachments:
            vol_id = va.get('id')
            if not vol_id:
                continue
            vol_url = '%s/v2/%s/volumes/%s' % (EVS_ENDPOINT, project_id, vol_id)
            vr = hwc_request('GET', vol_url)
            if vr.status_code == 200:
                v = vr.json().get('volume', {})
                device = ''
                for att in v.get('attachments', []):
                    if att.get('server_id') == ecs_id:
                        device = att.get('device', '')
                        break
                volumes.append({
                    'id': v.get('id'),
                    'name': v.get('name') or v.get('id', '')[:8],
                    'size': v.get('size'),
                    'type': v.get('volume_type'),
                    'status': v.get('status'),
                    'bootable': v.get('bootable'),
                    'device': device,
                    'multiattach': v.get('multiattach', False),
                })
            else:
                volumes.append({'id': vol_id, 'name': vol_id[:8], 'size': None, 'device': '', 'bootable': 'unknown'})

        volumes.sort(key=lambda v: (v.get('bootable') != 'true', v.get('device', '')))
        return jsonify({'volumes': volumes})
    except Exception as e:
        log.exception('get volumes error')
        return jsonify({'error': str(e)}), 500

@app.route('/api/schedules', methods=['GET'])
def api_list_schedules():
    ecs_id = request.args.get('ecs_id')
    conn = get_db()
    if ecs_id:
        rows = conn.execute('SELECT * FROM schedules WHERE ecs_id=? ORDER BY created_at DESC', (ecs_id,)).fetchall()
    else:
        rows = conn.execute('SELECT * FROM schedules ORDER BY created_at DESC').fetchall()
    conn.close()
    return jsonify({'schedules': [dict(r) for r in rows]})

@app.route('/api/schedules', methods=['POST'])
def api_create_schedule():
    data = request.json
    for f in ['name', 'ecs_id', 'ecs_name', 'frequency_hours', 'retention_count']:
        if f not in data:
            return jsonify({'error': 'Missing field: %s' % f}), 400

    now_str = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    next_run = (datetime.datetime.utcnow() +
                datetime.timedelta(hours=int(data['frequency_hours']))).strftime('%Y-%m-%dT%H:%M:%SZ')

    selected_volumes = json.dumps(data.get('selected_volumes', []))
    conn = get_db()
    cur = conn.execute(
        'INSERT INTO schedules (name, ecs_id, ecs_name, frequency_hours, retention_count, enabled, created_at, next_run, selected_volumes) VALUES (?,?,?,?,?,1,?,?,?)',
        (data['name'], data['ecs_id'], data['ecs_name'],
         int(data['frequency_hours']), int(data['retention_count']), now_str, next_run, selected_volumes)
    )
    sched_id = cur.lastrowid
    conn.commit()
    conn.close()

    add_scheduler_job(sched_id, int(data['frequency_hours']))
    return jsonify({'id': sched_id, 'next_run': next_run}), 201

@app.route('/api/schedules/<int:sched_id>', methods=['PUT'])
def api_update_schedule(sched_id):
    data = request.json
    conn = get_db()
    sched = conn.execute('SELECT * FROM schedules WHERE id=?', (sched_id,)).fetchone()
    if not sched:
        conn.close()
        return jsonify({'error': 'Not found'}), 404

    name = data.get('name', sched['name'])
    freq = int(data.get('frequency_hours', sched['frequency_hours']))
    ret = int(data.get('retention_count', sched['retention_count']))
    enabled = int(data.get('enabled', sched['enabled']))
    sel_vols = json.dumps(data.get('selected_volumes', json.loads(sched['selected_volumes'] or '[]')))
    next_run = (datetime.datetime.utcnow() +
                datetime.timedelta(hours=freq)).strftime('%Y-%m-%dT%H:%M:%SZ')

    conn.execute(
        'UPDATE schedules SET name=?, frequency_hours=?, retention_count=?, enabled=?, next_run=?, selected_volumes=? WHERE id=?',
        (name, freq, ret, enabled, next_run, sel_vols, sched_id)
    )
    conn.commit()
    conn.close()

    if enabled:
        add_scheduler_job(sched_id, freq)
    else:
        remove_scheduler_job(sched_id)

    return jsonify({'ok': True})

@app.route('/api/schedules/<int:sched_id>', methods=['DELETE'])
def api_delete_schedule(sched_id):
    conn = get_db()
    conn.execute('DELETE FROM schedules WHERE id=?', (sched_id,))
    conn.commit()
    conn.close()
    remove_scheduler_job(sched_id)
    return jsonify({'ok': True})

@app.route('/api/schedules/<int:sched_id>/run', methods=['POST'])
def api_run_now(sched_id):
    thread = threading.Thread(target=run_backup, args=(sched_id,), daemon=True)
    thread.start()
    return jsonify({'ok': True, 'message': 'Backup job started'})

@app.route('/api/history')
def api_history():
    sched_id = request.args.get('schedule_id')
    limit = int(request.args.get('limit', 50))
    conn = get_db()
    if sched_id:
        rows = conn.execute(
            'SELECT * FROM job_history WHERE schedule_id=? ORDER BY started_at DESC LIMIT ?',
            (sched_id, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            'SELECT * FROM job_history ORDER BY started_at DESC LIMIT ?', (limit,)
        ).fetchall()
    conn.close()
    return jsonify({'history': [dict(r) for r in rows]})

@app.route('/api/images')
def api_images():
    sched_id = request.args.get('schedule_id')
    ecs_id = request.args.get('ecs_id')
    conn = get_db()
    q = 'SELECT * FROM backup_images WHERE deleted=0'
    params = []
    if sched_id:
        q += ' AND schedule_id=?'
        params.append(sched_id)
    if ecs_id:
        q += ' AND ecs_id=?'
        params.append(ecs_id)
    q += ' ORDER BY created_at DESC'
    rows = conn.execute(q, params).fetchall()
    conn.close()

    # Enrich each backup with its disk count
    result = []
    conn = get_db()
    for row in rows:
        d = dict(row)
        count = conn.execute(
            'SELECT COUNT(*) FROM backup_snapshots WHERE backup_image_id=? AND deleted=0',
            (d['id'],)
        ).fetchone()[0]
        d['disk_count'] = count
        result.append(d)
    conn.close()
    return jsonify({'images': result})

@app.route('/api/images/<int:backup_id>', methods=['DELETE'])
def api_delete_image(backup_id):
    """Delete a backup by row ID (works for both VBS and legacy IMS backups)."""
    try:
        conn = get_db()
        row = conn.execute('SELECT * FROM backup_images WHERE id=?', (backup_id,)).fetchone()
        conn.close()
        if not row:
            return jsonify({'error': 'Backup no encontrado'}), 404
        delete_image_and_snapshots(row['image_id'], row['image_name'], row['id'])
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/restore/<int:backup_image_id>', methods=['POST'])
def api_restore(backup_image_id):
    """Start a VBS restore job for a backup."""
    conn = get_db()
    bimg = conn.execute('SELECT id FROM backup_images WHERE id=?', (backup_image_id,)).fetchone()
    conn.close()
    if not bimg:
        return jsonify({'error': 'Backup no encontrado'}), 404
    thread = threading.Thread(target=run_restore, args=(backup_image_id,), daemon=True)
    thread.start()
    return jsonify({'ok': True, 'message': 'Restauracion VBS iniciada'})

@app.route('/api/restore_history')
def api_restore_history():
    ecs_id = request.args.get('ecs_id')
    limit = int(request.args.get('limit', 50))
    conn = get_db()
    if ecs_id:
        rows = conn.execute(
            'SELECT * FROM restore_history WHERE ecs_id=? ORDER BY started_at DESC LIMIT ?',
            (ecs_id, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            'SELECT * FROM restore_history ORDER BY started_at DESC LIMIT ?', (limit,)
        ).fetchall()
    conn.close()
    return jsonify({'restore_history': [dict(r) for r in rows]})

@app.route('/api/snapshots')
def api_snapshots():
    ecs_id = request.args.get('ecs_id')
    sched_id = request.args.get('schedule_id')
    conn = get_db()
    q = 'SELECT * FROM backup_snapshots WHERE deleted=0'
    params = []
    if ecs_id:
        q += ' AND ecs_id=?'; params.append(ecs_id)
    if sched_id:
        q += ' AND schedule_id=?'; params.append(sched_id)
    q += ' ORDER BY created_at DESC'
    rows = conn.execute(q, params).fetchall()
    conn.close()
    return jsonify({'snapshots': [dict(r) for r in rows]})

# ── Startup ───────────────────────────────────────────────────────────────────

def startup():
    init_db()
    reload_schedules()
    scheduler.start()
    log.info('App started. Region=%s ProjectID=%s', REGION, get_project_id())

startup()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)
