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
            created_at TEXT NOT NULL,
            deleted INTEGER DEFAULT 0
        );
    ''')
    conn.commit()
    conn.close()

# ── Volume Helper ────────────────────────────────────────────────────────────

def fetch_ecs_volumes(ecs_id):
    """Return a list of volume dicts for the given ECS. Used for image description."""
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

# ── Backup Logic ──────────────────────────────────────────────────────────────

def poll_image_active(image_id, timeout=600):
    """Poll IMS until the image status becomes 'active'. Returns (ok, error_msg).
    Uses list+filter because GET /v2/cloudimages/{id} is not published in sa-argentina-1 APIGW.
    """
    url = '%s/v2/cloudimages' % IMS_ENDPOINT
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = hwc_request('GET', url, params={'id': image_id, 'limit': '1'})
            if r.status_code == 200:
                imgs = r.json().get('images', [])
                if imgs:
                    status = imgs[0].get('status', '')
                    if status == 'active':
                        return True, None
                    if status == 'error':
                        return False, 'Image entered error state'
            time.sleep(15)
        except Exception as e:
            log.warning('Poll image error: %s', e)
            time.sleep(15)
    return False, 'Timed out waiting for image to become active'

def _create_data_disk_image(volume_id, name, description=''):
    """Create an IMS image from a data disk volume via POST /v2/cloudimages/action.
    Polls the async job, then patches virtual_env_type=DataImage. Returns image_id.
    """
    project_id = get_project_id()
    body = {
        'name': name,
        'volume_id': volume_id,
        'os_version': 'Other Linux(64 bit)',
        'description': description,
    }
    r = hwc_request('POST', '%s/v2/cloudimages/action' % IMS_ENDPOINT, body=body)
    if r.status_code not in (200, 202):
        raise Exception('Data disk image create HTTP %s: %s' % (r.status_code, r.text[:200]))
    job_id = r.json().get('job_id')
    if not job_id:
        raise Exception('No job_id in data disk image create response')

    # Poll job until SUCCESS
    job_url = '%s/v1/%s/jobs/%s' % (IMS_ENDPOINT, project_id, job_id)
    deadline = time.time() + 600
    while time.time() < deadline:
        jr = hwc_request('GET', job_url)
        if jr.status_code == 200:
            j = jr.json()
            status = j.get('status', '')
            if status == 'SUCCESS':
                image_id = j.get('entities', {}).get('image_id')
                if not image_id:
                    raise Exception('No image_id in job result')
                # Patch virtual_env_type → DataImage so console shows it correctly
                patch = [{'op': 'replace', 'path': '/virtual_env_type', 'value': 'DataImage'}]
                hwc_request('PATCH', '%s/v2/images/%s' % (IMS_ENDPOINT, image_id),
                            body=patch,
                            content_type='application/openstack-images-v2.1-json-patch')
                log.info('Data disk image created and patched: %s', image_id)
                return image_id
            if status == 'FAIL':
                raise Exception('Data disk image job failed: %s' % j.get('fail_reason'))
        time.sleep(15)
    raise Exception('Data disk image job timed out (job_id=%s)' % job_id)

def _register_data_image(conn, backup_row_id, schedule_id, ecs_id, image_id, image_name, volume_id, size_gb):
    """Register a data disk IMS image in backup_snapshots table."""
    now_str = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    conn.execute(
        'INSERT OR IGNORE INTO backup_snapshots '
        '(backup_image_id, schedule_id, ecs_id, snapshot_id, snapshot_name, volume_id, volume_role, backup_type, size_gb, created_at) '
        'VALUES (?,?,?,?,?,?,?,?,?,?)',
        (backup_row_id, schedule_id, ecs_id,
         image_id, image_name, volume_id, 'data', 'ims_image',
         size_gb or 0, now_str)
    )

def delete_image_and_snapshots(img_id, img_name, backup_image_row_id):
    """Delete an IMS image and all its associated data disk IMS images."""
    # Delete system disk IMS image (skip placeholder 'data-only' entries)
    if img_id and img_id != 'data-only':
        try:
            r = hwc_request('DELETE', '%s/v2/images/%s' % (IMS_ENDPOINT, img_id))
            if r.status_code in (200, 204):
                log.info('Deleted IMS image %s (%s)', img_id, img_name)
                conn = get_db()
                conn.execute('UPDATE backup_images SET deleted=1 WHERE image_id=?', (img_id,))
                conn.commit()
                conn.close()
            else:
                log.warning('Delete IMS image %s: HTTP %s %s', img_id, r.status_code, r.text[:150])
        except Exception as e:
            log.error('Delete IMS image %s error: %s', img_id, e)

    # Delete associated data disk IMS images
    conn = get_db()
    items = conn.execute(
        'SELECT snapshot_id, snapshot_name, backup_type FROM backup_snapshots WHERE backup_image_id=? AND deleted=0',
        (backup_image_row_id,)
    ).fetchall()
    conn.close()
    for item in items:
        try:
            # All new items are ims_image; legacy evs_snapshot items use EVS DELETE
            if item['backup_type'] == 'evs_snapshot':
                project_id = get_project_id()
                r = hwc_request('DELETE', '%s/v2/%s/snapshots/%s' % (EVS_ENDPOINT, project_id, item['snapshot_id']))
            else:
                r = hwc_request('DELETE', '%s/v2/images/%s' % (IMS_ENDPOINT, item['snapshot_id']))
            if r.status_code in (200, 202, 204):
                log.info('Deleted data item %s (%s)', item['snapshot_id'], item['snapshot_name'])
                conn = get_db()
                conn.execute('UPDATE backup_snapshots SET deleted=1 WHERE snapshot_id=?', (item['snapshot_id'],))
                conn.commit()
                conn.close()
            else:
                log.warning('Delete data item %s: HTTP %s %s', item['snapshot_id'], r.status_code, r.text[:150])
        except Exception as e:
            log.error('Delete data item %s error: %s', item['snapshot_id'], e)

def apply_retention(schedule_id, ecs_id, retention_count):
    """Delete oldest backup images (+ snapshots) beyond retention_count for this schedule."""
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

def run_backup(schedule_id):
    """Execute a backup for a given schedule."""
    project_id = get_project_id()
    conn = get_db()
    sched = conn.execute('SELECT * FROM schedules WHERE id=?', (schedule_id,)).fetchone()
    conn.close()

    if not sched or not sched['enabled']:
        return
    sched = dict(sched)  # sqlite3.Row → dict (needed for .get())

    now_str = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    ts = datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')
    safe_name = ''.join(c if c.isalnum() or c == '-' else '-' for c in sched['ecs_name'])[:30].strip('-')
    image_name = 'bkp-%s-%s' % (safe_name, ts)

    conn = get_db()
    cur = conn.execute(
        'INSERT INTO job_history (schedule_id, schedule_name, ecs_id, ecs_name, status, started_at) VALUES (?,?,?,?,?,?)',
        (schedule_id, sched['name'], sched['ecs_id'], sched['ecs_name'], 'running', now_str)
    )
    job_id_db = cur.lastrowid
    conn.execute('UPDATE schedules SET last_run=? WHERE id=?', (now_str, schedule_id))
    conn.commit()
    conn.close()

    log.info('Starting backup: schedule=%s ecs=%s image=%s', schedule_id, sched['ecs_name'], image_name)

    try:
        # Determine which volumes to back up
        selected_vol_ids = json.loads(sched.get('selected_volumes') or '[]')
        all_vols = fetch_ecs_volumes(sched['ecs_id'])
        if selected_vol_ids:
            target_vols = [v for v in all_vols if v['id'] in selected_vol_ids]
        else:
            target_vols = all_vols

        system_vol = next((v for v in target_vols if v.get('bootable') == 'true'), None)
        data_vols  = [v for v in target_vols if v.get('bootable') != 'true']

        # Build description
        vol_lines = []
        for v in target_vols:
            rol = 'Sistema' if v.get('bootable') == 'true' else 'Datos'
            vol_lines.append('%s | %s | %s | %s GB | %s | %s' % (
                v.get('device','-'), v.get('name','-'), v.get('type','-'),
                v.get('size','?'), v.get('status','-'), rol))
        description = ('Backup automatico. Programacion: %s. Discos: %s' % (
            sched['name'], ' | '.join(vol_lines) if vol_lines else '-'))[:255]

        image_id    = None
        backup_row_id = None

        # ── System disk: ECS createImage → IMS system disk image ────────────
        if system_vol:
            url = '%s/v2/%s/servers/%s/action' % (ECS_ENDPOINT, project_id, sched['ecs_id'])
            r = hwc_request('POST', url, body={'createImage': {'name': image_name, 'description': description}})
            if r.status_code not in (200, 202):
                raise Exception('ECS createImage HTTP %s: %s' % (r.status_code, r.text[:300]))

            location = r.headers.get('Location', '')
            image_id = location.rstrip('/').split('/')[-1] if location else None
            if not image_id:
                raise Exception('No Location header in createImage response')
            log.info('System image creation started: image_id=%s', image_id)

            ok, err = poll_image_active(image_id)
            if not ok:
                raise Exception('Image polling failed: %s' % err)

            finished_str = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
            conn = get_db()
            cur = conn.execute(
                'INSERT OR IGNORE INTO backup_images (schedule_id, ecs_id, ecs_name, image_id, image_name, created_at) VALUES (?,?,?,?,?,?)',
                (schedule_id, sched['ecs_id'], sched['ecs_name'], image_id, image_name, finished_str)
            )
            backup_row_id = cur.lastrowid
            conn.commit()
            conn.close()
            log.info('System disk image registered: image_id=%s', image_id)

        # ── Data disks: IMS image via POST /v2/cloudimages/action ───────────
        if data_vols:
            if backup_row_id is None:
                # No system image — create a placeholder backup_images row to anchor data images
                ph_name = image_name + '-data'
                finished_str = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
                conn = get_db()
                cur = conn.execute(
                    'INSERT INTO backup_images (schedule_id, ecs_id, ecs_name, image_id, image_name, created_at) VALUES (?,?,?,?,?,?)',
                    (schedule_id, sched['ecs_id'], sched['ecs_name'], 'data-only', ph_name, finished_str)
                )
                backup_row_id = cur.lastrowid
                conn.commit()
                conn.close()

            for dv in data_vols:
                dv_safe = ''.join(c if c.isalnum() or c=='-' else '-' for c in dv.get('name','vol'))[:20]
                dv_img_name = 'bkp-data-%s-%s' % (dv_safe, ts)
                log.info('Creating IMS image for data disk %s (%s GB)', dv['id'][:8], dv.get('size'))
                dv_image_id = _create_data_disk_image(dv['id'], dv_img_name, description)
                conn = get_db()
                _register_data_image(conn, backup_row_id, schedule_id, sched['ecs_id'],
                                     dv_image_id, dv_img_name, dv['id'], dv.get('size'))
                conn.commit()
                conn.close()
                log.info('Data disk IMS image registered: %s', dv_image_id[:8])

        # ── Finalize job history ─────────────────────────────────────────────
        finished_str = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        msg = 'Sistema: imagen IMS' if system_vol else ''
        if data_vols:
            msg += ('%s | ' % (' + ' if msg else '')) + 'Datos: %d imagen(es) IMS' % len(data_vols)
        conn = get_db()
        conn.execute(
            'UPDATE job_history SET status=?, image_id=?, image_name=?, finished_at=?, message=? WHERE id=?',
            ('success', image_id or 'data-only', image_name, finished_str, msg or 'Backup completado', job_id_db)
        )
        conn.commit()
        conn.close()
        log.info('Backup success for schedule %s', schedule_id)
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

# ── Scheduler ─────────────────────────────────────────────────────────────────

scheduler = BackgroundScheduler(daemon=True)

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
            # Extract IPs (fixed + floating)
            ips = []
            for _net, addrs in s.get('addresses', {}).items():
                for addr in addrs:
                    ips.append({'ip': addr.get('addr', ''), 'type': addr.get('OS-EXT-IPS:type', '')})

            # Volume IDs
            vols = [v['id'] for v in s.get('os-extended-volumes:volumes_attached', [])]

            # Flavor ID from link URL
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
        # Get server to find volume IDs
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
                # Determine if system disk from bootable flag or attachments
                attachs = v.get('attachments', [])
                boot_index = None
                device = ''
                for att in attachs:
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

        # Sort: system disk first
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
    return jsonify({'images': [dict(r) for r in rows]})

@app.route('/api/images/<image_id>', methods=['DELETE'])
def api_delete_image(image_id):
    try:
        conn = get_db()
        row = conn.execute('SELECT id, image_name FROM backup_images WHERE image_id=?', (image_id,)).fetchone()
        conn.close()
        row_id = row['id'] if row else 0
        img_name = row['image_name'] if row else ''
        delete_image_and_snapshots(image_id, img_name, row_id)
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
