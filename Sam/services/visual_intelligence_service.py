"""
Visual Intelligence Service — Google Lens via SerpAPI
Based on actual API schema: https://serpapi.com/google-lens-api

Actual response structure (type=all):
  visual_matches  — array of results; each has exact_matches:bool flag
  related_content — array of {query, link, thumbnail, serpapi_link}
  ai_overview     — optional {page_token, serpapi_link}
  search_metadata — {google_lens_url, ...}

Fields that do NOT exist in this API (removed from previous incorrect version):
  knowledge_graph, text, entities, products, inline_images
"""

from __future__ import annotations
import os
import logging
import base64

logger = logging.getLogger(__name__)


class VisualIntelligenceService:

    def analyze(self, image_path: str) -> dict:
        """
        Run Google Lens reverse image search via SerpAPI.
        Relays image through ImgBB (ephemeral 10-min URL) then queries SerpAPI.
        Only outbound connections needed — works on localhost and internal servers.
        """
        serpapi_key = os.environ.get('SERPAPI_API_KEY', '').strip()
        imgbb_key   = os.environ.get('IMGBB_API_KEY', '').strip()

        if not serpapi_key:
            return {'error': 'SERPAPI_API_KEY not configured.'}
        if not imgbb_key:
            return {'error': 'IMGBB_API_KEY not configured.'}
        if not os.path.exists(image_path):
            return {'error': 'Image file not found. Please re-upload and run EXIF scan first.'}

        try:
            image_url = self._upload_to_imgbb(image_path, imgbb_key)
        except Exception as exc:
            logger.error('ImgBB upload failed: %s', exc)
            return {'error': f'Temporary image hosting failed: {str(exc)[:200]}'}

        try:
            raw = self._call_serpapi(image_url, serpapi_key)
        except Exception as exc:
            logger.error('SerpAPI call failed: %s', exc)
            return {'error': f'Google Lens API request failed: {str(exc)[:200]}'}

        if isinstance(raw, dict) and 'error' in raw:
            return {'error': str(raw['error'])}

        return self._parse_response(raw)

    # ── ImgBB upload ─────────────────────────────────────────────────────────

    def _upload_to_imgbb(self, image_path: str, api_key: str) -> str:
        import httpx
        with open(image_path, 'rb') as f:
            b64 = base64.b64encode(f.read()).decode('utf-8')
        resp = httpx.post(
            'https://api.imgbb.com/1/upload',
            data={'key': api_key, 'image': b64, 'expiration': 600},
            timeout=30.0,
        )
        resp.raise_for_status()
        data = resp.json()
        if not data.get('success'):
            msg = (data.get('error') or {}).get('message', 'unknown error')
            raise RuntimeError(f'ImgBB upload failed: {msg}')
        return data['data']['url']

    # ── SerpAPI call ──────────────────────────────────────────────────────────

    def _call_serpapi(self, image_url: str, api_key: str) -> dict:
        import httpx
        resp = httpx.get(
            'https://serpapi.com/search',
            params={
                'engine':   'google_lens',
                'url':      image_url,
                'api_key':  api_key,
                'hl':       'en',
                'no_cache': 'true',
            },
            timeout=45.0,
            follow_redirects=True,
        )
        resp.raise_for_status()
        return resp.json()

    # ── Response parser (based on actual API schema) ──────────────────────────

    def _parse_response(self, raw: dict) -> dict:
        visual_raw = raw.get('visual_matches', [])
        exact, visual = self._split_matches(visual_raw)

        parsed = {
            'exact_matches':    exact,
            'visual_matches':   visual,
            'related_searches': self._parse_related(raw.get('related_content', [])),
            'source_url':       (raw.get('search_metadata') or {}).get('google_lens_url', ''),
            'total_found':      len(visual_raw),
            'error':            None,
        }
        parsed['summary'] = self._generate_summary(parsed)
        return parsed

    def _split_matches(self, items: list) -> tuple[list, list]:
        """
        Split visual_matches into exact duplicates and visually similar results.
        exact_matches is a boolean flag on each item per the API schema.
        thumbnail and image are plain URL strings (not objects).
        """
        exact, visual = [], []
        for item in items:
            # thumbnail and image are plain URL strings per the actual API schema
            entry = {
                'position':  item.get('position', 0),
                'title':     (item.get('title') or '').strip(),
                'source':    item.get('source', ''),
                'link':      item.get('link', ''),
                'thumbnail': item.get('thumbnail', ''),   # plain URL string
                'image':     item.get('image', ''),       # plain URL string
                'price':     self._fmt_price(item.get('price')),
                'in_stock':  item.get('in_stock'),
                'condition': item.get('condition', ''),
            }
            if item.get('exact_matches'):
                exact.append(entry)
            else:
                visual.append(entry)
        return exact, visual

    def _parse_related(self, items: list) -> list:
        out = []
        for r in (items or []):
            if isinstance(r, dict) and r.get('query'):
                out.append({
                    'query':     r['query'],
                    'link':      r.get('link', ''),
                    'thumbnail': r.get('thumbnail', ''),  # plain URL string
                })
        return out

    def _fmt_price(self, price) -> str:
        if not price:
            return ''
        if isinstance(price, str):
            return price
        if isinstance(price, dict):
            return price.get('value') or str(price.get('extracted_value', ''))
        return str(price)

    # ── Officer-readable summary ──────────────────────────────────────────────

    def _generate_summary(self, parsed: dict) -> str:
        parts = []

        exact  = parsed.get('exact_matches', [])
        visual = parsed.get('visual_matches', [])

        if exact:
            sources = list(dict.fromkeys(
                m['source'] for m in exact if m.get('source')
            ))[:3]
            n   = len(exact)
            src = f" — sources: {', '.join(sources)}" if sources else ''
            parts.append(
                f"{n} exact duplicate{'s' if n != 1 else ''} of this image "
                f"found publicly online{src}."
            )

        if visual:
            n = len(visual)
            parts.append(
                f"{n} visually similar image{'s' if n != 1 else ''} "
                "indexed across the web."
            )

        related = parsed.get('related_searches', [])
        if related:
            queries = [r['query'] for r in related[:3] if r.get('query')]
            if queries:
                parts.append(f"Related visual context: {', '.join(queries)}.")

        if not parts:
            return (
                "No matches found. The image may not be publicly indexed, "
                "or Google Lens could not identify contextual data for this content."
            )

        return ' '.join(parts)
