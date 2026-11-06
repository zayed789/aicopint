import os
import re
from datetime import datetime
from urllib.parse import urlparse

import httpx

_URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"
_URLSCAN_RESULT = "https://urlscan.io/api/v1/result/"


def _normalize_target(raw_input):
    target = raw_input.strip()
    if '://' in target:
        target = urlparse(target).hostname or target
    target = target.split('/')[0].split('?')[0].strip()
    if ':' in target and not target.startswith('['):
        target = target.split(':')[0]
    return re.sub(r'^www\.', '', target)


def _is_ip(target):
    parts = target.split('.')
    return (
        len(parts) == 4
        and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    )


def _build_query(target):
    return f"page.ip:{target}" if _is_ip(target) else f"domain:{target}"


def _fmt_ts(val):
    if not val:
        return ""
    if isinstance(val, (int, float)):
        try:
            return datetime.utcfromtimestamp(val).strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            return str(val)
    return str(val)[:19].replace('T', ' ')


def query_urlscan(raw_input):
    """Search urlscan.io for existing scan records and return structured intelligence."""
    api_key = os.getenv('URLSCAN_API_KEY', '')
    headers = {}
    if api_key:
        headers['API-Key'] = api_key

    target = _normalize_target(raw_input)
    q = _build_query(target)

    resp = httpx.get(
        _URLSCAN_SEARCH,
        params={"q": q, "size": 1},
        headers=headers,
        timeout=20,
    )

    if resp.status_code == 429:
        raise ValueError("URLScan.io rate limit exceeded. Please try again later.")
    if resp.status_code != 200:
        raise ValueError(f"URLScan.io search returned HTTP {resp.status_code}.")

    hits = resp.json().get('results', [])
    if not hits:
        raise ValueError(
            f"No URLScan.io records found for '{target}'. "
            "The target may not have been scanned yet."
        )

    scan_id = hits[0].get('_id', '')

    result_resp = httpx.get(
        f"{_URLSCAN_RESULT}{scan_id}/",
        headers=headers,
        timeout=20,
    )

    if result_resp.status_code != 200:
        raise ValueError(
            f"URLScan.io result fetch returned HTTP {result_resp.status_code}."
        )

    return _parse_result(result_resp.json(), scan_id)


def _parse_result(data, scan_id):
    page     = data.get('page', {})
    task     = data.get('task', {})
    stats    = data.get('stats', {})
    meta     = data.get('meta', {})
    lists    = data.get('lists', {})
    verdicts = data.get('verdicts', {})

    # A. Scan Metadata
    scan_meta = {
        'scan_id':  scan_id,
        'timestamp': _fmt_ts(task.get('time', '')),
        'url':      page.get('url') or task.get('url', ''),
        'domain':   page.get('domain', ''),
        'ip':       page.get('ip', ''),
        'asn':      page.get('asn', ''),
        'asnname':  page.get('asnname', ''),
        'country':  page.get('country', ''),
        'server':   page.get('server', ''),
    }

    # B. Page Intelligence — technologies via Wappa processor
    techs = []
    wappa_items = meta.get('processors', {}).get('wappa', {}).get('data', [])
    for item in wappa_items:
        name = item.get('app', '')
        raw_cats = item.get('categories', [])
        if isinstance(raw_cats, list) and raw_cats and isinstance(raw_cats[0], dict):
            cats = [c.get('name', '') for c in raw_cats if c.get('name')]
        else:
            cats = [str(c) for c in raw_cats if c]
        if name:
            techs.append({'name': name, 'categories': cats})

    page_intel = {
        'title':       page.get('title', ''),
        'status':      str(page.get('status', '')),
        'mime_type':   page.get('mimeType', ''),
        'redirected':  page.get('redirected', ''),
        'technologies': techs,
    }

    # C. Security Indicators — TLS from first request that has securityDetails
    tls_info = {}
    for req in (data.get('data', {}).get('requests') or [])[:20]:
        sec = req.get('response', {}).get('securityDetails', {})
        if sec:
            tls_info = {
                'protocol':   sec.get('protocol', ''),
                'cipher':     sec.get('cipher', ''),
                'subject':    sec.get('subjectName', ''),
                'issuer':     sec.get('issuer', ''),
                'valid_from': _fmt_ts(sec.get('validFrom')),
                'valid_to':   _fmt_ts(sec.get('validTo')),
                'san_list':   sec.get('sanList', [])[:15],
            }
            break

    overall = verdicts.get('overall', {})
    security = {
        'tls':          tls_info,
        'malicious':    overall.get('malicious', False),
        'score':        overall.get('score', 0),
        'tags':         overall.get('tags', []),
        'has_verdicts': overall.get('hasVerdicts', False),
    }

    # D. Infrastructure Relationships
    infra = {
        'domains': lists.get('domains', [])[:20],
        'ips':     lists.get('ips', [])[:20],
        'asns':    lists.get('asns', [])[:10],
        'servers': lists.get('servers', [])[:10],
        'certificates': [],
    }
    for cert in (lists.get('certificates') or [])[:5]:
        if isinstance(cert, dict):
            infra['certificates'].append({
                'subject':    cert.get('subjectName', ''),
                'issuer':     cert.get('issuer', ''),
                'valid_from': _fmt_ts(cert.get('validFrom')),
                'valid_to':   _fmt_ts(cert.get('validTo')),
            })

    raw_req = stats.get('requests', 0)
    req_count = raw_req if isinstance(raw_req, int) else 0

    scan_stats = {
        'requests':    req_count,
        'data_length': stats.get('dataLength', 0),
        'countries':   len(stats.get('ipCountries', [])) if isinstance(stats.get('ipCountries'), list) else 0,
    }

    return {
        'scan_meta':      scan_meta,
        'page_intel':     page_intel,
        'security':       security,
        'infrastructure': infra,
        'stats':          scan_stats,
        'screenshot_url': f"https://urlscan.io/screenshots/{scan_id}.png",
        'result_url':     f"https://urlscan.io/result/{scan_id}/",
    }
