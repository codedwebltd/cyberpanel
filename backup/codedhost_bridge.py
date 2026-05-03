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
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse


# ─── Config — secret kept in /etc/codedhost/cp-bridge.env (root:lscpd 640) ───
def _load_env():
    env = {
        'CDH_API_BASE':  'https://codedhost.vip',
        'CDH_CP_SERVER': 'panel.codedhost.vip:8443',
        'CDH_API_SECRET': '',
    }
    try:
        with open('/etc/codedhost/cp-bridge.env', 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, _, v = line.partition('=')
                env[k.strip()] = v.strip()
    except Exception:
        # Missing file = bridge disabled. The view will fall back to "not_configured".
        pass
    return env


_CFG = _load_env()


def _is_configured():
    return bool(_CFG.get('CDH_API_SECRET'))


def _sign(server, admin, ts, body_bytes):
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    msg = f"{server}|{admin}|{ts}|{body_hash}".encode()
    return hmac.new(_CFG['CDH_API_SECRET'].encode(), msg, hashlib.sha256).hexdigest()


def _post(path, admin, body=None):
    """Server-to-server POST with HMAC headers. Returns (status_code, response_dict)."""
    if not _is_configured():
        return 503, {'error': 'codedhost_bridge_not_configured'}

    server = _CFG['CDH_CP_SERVER']
    ts = int(time.time())
    body_bytes = b'' if body is None else json.dumps(body).encode()
    sig = _sign(server, admin, ts, body_bytes)

    try:
        resp = requests.post(
            _CFG['CDH_API_BASE'].rstrip('/') + path,
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


# ─── Views (mounted in backup/urls.py) ────────────────────────────────────────

@login_required
def cdh_status(request):
    """GET /backup/cdh/status — proxies to Laravel /api/cp/status."""
    admin = (request.user.username or '').strip()
    code, data = _post('/api/cp/status', admin, body={})
    return JsonResponse(data, status=code, safe=False)
