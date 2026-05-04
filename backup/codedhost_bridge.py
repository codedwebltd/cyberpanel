"""
codedhost_bridge — same-origin Django proxy that signs and forwards requests
to the Laravel storefront's /api/cp/* endpoints. The browser never sees the
shared secret — it only ever talks to CP, which talks to Laravel server-to-server.

Survives CP upgrades because it lives in /opt/codedhost-branding/cp-overrides/
and is copied into /usr/local/CyberCP/backup/ by apply-cp-overrides.sh.
"""

import hashlib
import hmac
import json
import os
import time

import requests
from django.http import JsonResponse
from functools import wraps

# CyberPanel uses its own session pattern (request.session['userID'] +
# loginSystem.Administrator model), not Django's contrib.auth. Django's
# @login_required always fails here because request.user is never set.
def cp_login_required(view):
    @wraps(view)
    def wrapper(request, *args, **kwargs):
        user_id = request.session.get('userID')
        if not user_id:
            return JsonResponse({'error': 'not_authenticated'}, status=401)
        try:
            from loginSystem.models import Administrator
            admin = Administrator.objects.filter(pk=user_id).first()
        except Exception as e:
            return JsonResponse({'error': 'admin_lookup_failed', 'detail': str(e)}, status=500)
        if not admin:
            return JsonResponse({'error': 'admin_not_found'}, status=401)
        request.cp_admin = admin  # stash for view to use
        return view(request, *args, **kwargs)
    return wrapper


# ─── Config — secret kept in /etc/codedhost/cp-bridge.env (root:lscpd 640) ───
def _load_env():
    env = {
        'CDH_API_BASE':  'https://codedhost.vip',
        'CDH_CP_SERVER': 'panel.codedhost.vip:8443',
        'CDH_API_SECRET': '',
    }
    path = '/etc/codedhost/cp-bridge.env'
    debug = []
    try:
        st = os.stat(path)
        debug.append(f'stat ok mode={oct(st.st_mode)} uid={st.st_uid} gid={st.st_gid} size={st.st_size}')
        # Explicit UTF-8 — lscpd workers spawn with LANG=C / ASCII codec,
        # so any non-ASCII byte (e.g. an emoji in a comment) blows up the
        # default text-mode decoder.
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        debug.append(f'read {len(content)} bytes')
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            k, _, v = line.partition('=')
            env[k.strip()] = v.strip()
        debug.append(f'parsed keys={list(env.keys())} secret_len={len(env["CDH_API_SECRET"])}')
    except Exception as e:
        debug.append(f'EXCEPTION {type(e).__name__}: {e}')
        env['_DEBUG'] = ' | '.join(debug)
        # also append to a tmp log for tracing the running worker
        try:
            import datetime
            with open('/tmp/cdh-bridge.log', 'a') as f:
                f.write(f'[{datetime.datetime.now().isoformat()}] uid={os.getuid()} gid={os.getgid()} -> {" | ".join(debug)}\n')
        except Exception:
            pass
        return env
    env['_DEBUG'] = ' | '.join(debug)
    try:
        import datetime
        with open('/tmp/cdh-bridge.log', 'a') as f:
            f.write(f'[{datetime.datetime.now().isoformat()}] uid={os.getuid()} gid={os.getgid()} -> {" | ".join(debug)}\n')
    except Exception:
        pass
    return env


# Lazy load — re-reads /etc/codedhost/cp-bridge.env on every call so perms
# changes or worker fork-time race conditions can't leave us stuck with an
# empty config. The file is small; cost is negligible compared to the HTTP
# call we're about to make.
def _cfg():
    return _load_env()


def _is_configured():
    return bool(_cfg().get('CDH_API_SECRET'))


def _sign(secret, server, admin, ts, body_bytes):
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    msg = f"{server}|{admin}|{ts}|{body_hash}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def _post(path, admin, body=None):
    """Server-to-server POST with HMAC headers. Returns (status_code, response_dict)."""
    cfg = _cfg()
    if not cfg.get('CDH_API_SECRET'):
        return 503, {
            'error': 'codedhost_bridge_not_configured',
            'detail': 'CDH_API_SECRET missing from /etc/codedhost/cp-bridge.env (or not readable by the cyberpanel user).',
        }

    server = cfg['CDH_CP_SERVER']
    ts = int(time.time())
    body_bytes = b'' if body is None else json.dumps(body).encode()
    sig = _sign(cfg['CDH_API_SECRET'], server, admin, ts, body_bytes)

    try:
        resp = requests.post(
            cfg['CDH_API_BASE'].rstrip('/') + path,
            data=body_bytes,
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-CP-Server': server,
                'X-CP-Admin':  admin,
                'X-CP-Ts':     str(ts),
                'X-CP-Sig':    sig,
            },
            timeout=10,
        )
    except requests.RequestException as e:
        return 502, {'error': 'codedhost_unreachable', 'detail': str(e)}

    try:
        return resp.status_code, resp.json()
    except ValueError:
        return resp.status_code, {'error': 'invalid_json', 'body': resp.text[:300]}


# ─── Site discovery ───────────────────────────────────────────────────────────

def _admin_sites(admin_obj):
    """
    Return a list of {domain} dicts for every website owned by this CP admin.
    Filters out CP's auto-created server hostname site (matches the box's own
    hostname). Failures are swallowed — site sync is best-effort, never blocks
    the status fetch.
    """
    try:
        from websiteFunctions.models import Websites
        import socket
        host = socket.gethostname()
        rows = Websites.objects.filter(admin=admin_obj).values_list('domain', flat=True)
        return [
            {'domain': d}
            for d in rows
            if d and d != host and not d.startswith('vmi')
        ]
    except Exception:
        return []


# ─── Views (mounted in backup/urls.py) ────────────────────────────────────────

@cp_login_required
def cdh_status(request):
    """GET /backup/cdh/status — proxies to Laravel /api/cp/status with site list."""
    admin = (request.cp_admin.userName or '').strip()
    body  = {'sites': _admin_sites(request.cp_admin)}
    code, data = _post('/api/cp/status', admin, body=body)
    return JsonResponse(data, status=code, safe=False)


@cp_login_required
def cdh_backup_now(request):
    """POST /backup/cdh/backup-now {site_ids:[...]} — proxies to Laravel /api/cp/backup/now."""
    if request.method != 'POST':
        return JsonResponse({'error': 'method_not_allowed'}, status=405)
    admin = (request.cp_admin.userName or '').strip()
    try:
        body = json.loads(request.body or b'{}')
    except Exception:
        body = {}
    site_ids = body.get('site_ids') or []
    if not isinstance(site_ids, list) or not site_ids:
        return JsonResponse({'error': 'site_ids_required'}, status=400)
    code, data = _post('/api/cp/backup/now', admin, body={'site_ids': site_ids})
    return JsonResponse(data, status=code, safe=False)


@cp_login_required
def cdh_oauth_link(request):
    """
    GET /backup/cdh/oauth-link
    Returns { url } pointing at Laravel /oauth/cp-server-link with an HMAC-signed
    query string. Browser navigates to it from the State A "Connect" button.
    """
    cfg = _cfg()
    if not cfg.get('CDH_API_SECRET'):
        return JsonResponse({
            'error': 'codedhost_bridge_not_configured',
            'detail': 'CDH_API_SECRET missing from /etc/codedhost/cp-bridge.env (or not readable by the cyberpanel user).',
        }, status=503)

    server = cfg['CDH_CP_SERVER']
    admin  = (request.cp_admin.userName or '').strip()
    if not admin:
        return JsonResponse({'error': 'no_cp_username'}, status=400)

    ts = int(time.time())
    msg = f"{server}|{admin}|{ts}".encode()
    sig = hmac.new(cfg['CDH_API_SECRET'].encode(), msg, hashlib.sha256).hexdigest()

    base = cfg['CDH_API_BASE'].rstrip('/') + '/oauth/cp-server-link'
    url  = f"{base}?cp_server={server}&cp_admin={admin}&cp_ts={ts}&cp_sig={sig}"
    return JsonResponse({'url': url})
