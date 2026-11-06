"""
Professional PDF Report Service — OSINT/SOCMINT Investigation Platform
Hyderabad City Police / Telangana State Police

Single reusable service for generating law-enforcement-grade investigation
reports across all platform modules:
  - Main Dashboard  (email / username / phone intelligence)
  - Infrastructure Intel  (Shodan-powered host recon)
  - Image Intel  (EXIF / GPS / metadata forensics)
  - Ask AI  (AI investigation copilot output)

Dependencies: fpdf2 (already in requirements.txt)
Cross-platform: uses only built-in PDF core fonts (no system font paths).
"""

from __future__ import annotations

from datetime import datetime, timezone as dt_timezone
from urllib.parse import urlparse
from fpdf import FPDF


# ── Unicode → ASCII sanitiser (fpdf2 core fonts are Latin-1 only) ────────────

_REPLACEMENTS = {
    '–': '-',   '—': '-',   '‘': "'",  '’': "'",
    '“': '"',   '”': '"',   '…': '...',' ': ' ',
    '✓': 'Yes', '✗': 'No',  '✔': 'Yes','☐': '[ ]',
    '☑': '[X]', '✅': 'Yes', '❌': 'No', '✖': 'X',
    '➕': '+',   '➖': '-',   '●': '*',  '○': 'o',
    '■': '[#]', '□': '[]',  '°': 'deg','®': '(R)',
    '©': '(C)', '™': '(TM)','é': 'e',  'è': 'e',
    'ê': 'e',   'à': 'a',   'â': 'a',  'ô': 'o',
    'û': 'u',   'ü': 'u',   'ç': 'c',  'ñ': 'n',
    '→': '->',  '←': '<-',  '•': '*',  '·': '.',
}


def _s(text) -> str:
    """Return ASCII-safe string for fpdf2 core-font rendering."""
    if text is None:
        return ''
    text = str(text)
    for uc, ac in _REPLACEMENTS.items():
        text = text.replace(uc, ac)
    return text.encode('ascii', 'ignore').decode('ascii')


def _trunc(text, max_len: int = 80) -> str:
    t = _s(text)
    return t[:max_len] + '...' if len(t) > max_len else t


def _url_to_platform(url: str) -> str:
    """Derive a readable platform name from a profile URL."""
    try:
        host = urlparse(url).netloc or url
        host = host.replace('www.', '').replace('m.', '')
        return host.split('.')[0].title()
    except Exception:
        return _trunc(url, 20)


# ── Palette ───────────────────────────────────────────────────────────────────

_NAVY      = (6,  41, 82)
_NAVY_DARK = (4,  29, 57)
_KHAKI     = (202, 181, 138)
_ACCENT    = (243, 193, 75)
_SURFACE   = (244, 247, 251)
_WHITE     = (255, 255, 255)
_TEXT      = (30,  30, 30)
_MUTED     = (100, 100, 100)
_GREEN     = (22, 101, 52)
_GREEN_BG  = (220, 252, 231)
_RED       = (153, 27, 27)
_RED_BG    = (254, 226, 226)
_AMBER     = (120, 80, 0)
_AMBER_BG  = (255, 251, 235)


# ── Base PDF class ────────────────────────────────────────────────────────────

class _IntelReport(FPDF):
    """Shared header / footer / helpers for all report types."""

    def __init__(self, report_title: str, module_name: str,
                 officer_email: str = '', officer_role: str = ''):
        super().__init__()
        self.report_title  = report_title
        self.module_name   = module_name
        self.officer_email = officer_email
        self.officer_role  = officer_role
        self.generated_at  = datetime.now(dt_timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        self.set_auto_page_break(auto=True, margin=20)
        self.set_margins(14, 30, 14)   # top margin leaves room for header bar

    # ── header ────────────────────────────────────────────────────────────────

    def header(self):
        # Dark navy background bar
        self.set_fill_color(*_NAVY_DARK)
        self.rect(0, 0, 210, 26, 'F')

        # Khaki accent line at bottom of bar
        self.set_draw_color(*_KHAKI)
        self.set_line_width(1.0)
        self.line(0, 26, 210, 26)

        # Organisation name
        self.set_y(4)
        self.set_font('Arial', 'B', 11)
        self.set_text_color(*_WHITE)
        self.cell(0, 6, 'HYDERABAD CITY POLICE', 0, 1, 'C')

        # Sub-title: platform name
        self.set_font('Arial', '', 7.5)
        self.set_text_color(*_KHAKI)
        self.cell(0, 5, 'Repo of OSINT/SOCMINT -- Cyber Intelligence Investigation Platform', 0, 1, 'C')

        # Module tag right-aligned
        self.set_font('Arial', 'B', 7)
        self.set_text_color(*_ACCENT)
        self.set_x(-50)
        self.cell(36, 4, _s(self.module_name).upper(), 0, 0, 'R')

        self.ln(6)

    # ── footer ────────────────────────────────────────────────────────────────

    def footer(self):
        self.set_y(-14)
        self.set_fill_color(*_NAVY_DARK)
        self.rect(0, self.h - 14, 210, 14, 'F')

        self.set_font('Arial', 'I', 7)
        self.set_text_color(*_MUTED)

        left = f'Generated: {self.generated_at}'
        if self.officer_email:
            left += f'  |  Officer: {_s(self.officer_email)}'
            if self.officer_role:
                left += f' ({_s(self.officer_role)})'
        self.set_x(14)
        self.cell(0, 5, left, 0, 0, 'L')

        self.set_font('Arial', 'B', 7.5)
        self.set_text_color(*_KHAKI)
        self.set_x(-28)
        self.cell(14, 5, f'Page {self.page_no()}', 0, 0, 'R')

    # ── cover block ───────────────────────────────────────────────────────────

    def cover_block(self, title: str, subtitle: str = '', target: str = ''):
        """Navy box with report title, subtitle, optional target."""
        y0 = self.get_y()
        h  = 14 + (7 if subtitle else 0) + (7 if target else 0)
        self.set_fill_color(*_NAVY)
        self.set_draw_color(*_KHAKI)
        self.set_line_width(0.6)
        usable_w = self.w - 28
        self.rect(14, y0, usable_w, h, 'FD')

        self.set_y(y0 + 4)
        self.set_font('Arial', 'B', 15)
        self.set_text_color(*_WHITE)
        self.cell(0, 9, _s(title), 0, 1, 'C')

        if subtitle:
            self.set_font('Arial', '', 9)
            self.set_text_color(*_KHAKI)
            self.cell(0, 7, _s(subtitle), 0, 1, 'C')

        if target:
            self.set_font('Arial', 'B', 9)
            self.set_text_color(*_ACCENT)
            self.cell(0, 7, f'Target: {_s(target)}', 0, 1, 'C')

        self.ln(h - (self.get_y() - y0) + 10)

    # ── meta strip ────────────────────────────────────────────────────────────

    def meta_strip(self, items: list[tuple[str, str]]):
        """Light-grey row of key: value items spread horizontally."""
        self.set_fill_color(*_SURFACE)
        self.set_draw_color(210, 218, 230)
        self.set_line_width(0.3)
        usable_w = self.w - 28
        self.rect(14, self.get_y(), usable_w, 8, 'FD')
        self.set_font('Arial', '', 8)
        self.set_text_color(*_MUTED)
        col_w = usable_w / max(len(items), 1)
        x0 = 14
        y0 = self.get_y() + 1.5
        for i, (k, v) in enumerate(items):
            self.set_xy(x0 + i * col_w, y0)
            self.set_font('Arial', 'B', 7.5)
            self.set_text_color(*_NAVY)
            self.cell(col_w * 0.35, 5, _s(k) + ':', 0, 0)
            self.set_font('Arial', '', 7.5)
            self.set_text_color(*_TEXT)
            self.cell(col_w * 0.65, 5, _trunc(v, 28), 0, 0)
        self.ln(10)

    # ── section header ────────────────────────────────────────────────────────

    def section_header(self, title: str, count_badge: str = ''):
        """Navy gradient section divider bar."""
        if self.get_y() > 255:
            self.add_page()
        self.ln(3)
        self.set_fill_color(*_NAVY)
        self.set_text_color(*_WHITE)
        self.set_font('Arial', 'B', 9.5)
        usable_w = self.w - 28
        y0 = self.get_y()
        self.rect(14, y0, usable_w, 8, 'F')
        self.set_xy(16, y0 + 1)
        self.cell(usable_w - 30, 6, _s(title), 0, 0)
        if count_badge:
            self.set_font('Arial', 'B', 7.5)
            self.set_text_color(*_KHAKI)
            self.set_x(-44)
            self.cell(30, 6, _s(count_badge), 0, 0, 'R')
        self.ln(9)

    # ── KV row ────────────────────────────────────────────────────────────────

    def kv(self, key: str, value, key_w: float = 50):
        """Render a key / value pair row with explicit width positioning."""
        if self.get_y() > 265:
            self.add_page()
        l_margin = 14
        val_str  = _s(str(value)) if value is not None else '-'
        val_w    = self.w - l_margin * 2 - key_w   # remaining content width

        y = self.get_y()
        self.set_xy(l_margin, y)
        self.set_font('Arial', 'B', 8.5)
        self.set_text_color(*_NAVY)
        self.cell(key_w, 6, _s(key) + ':', 0, 0)

        self.set_xy(l_margin + key_w, y)
        self.set_font('Arial', '', 8.5)
        self.set_text_color(*_TEXT)
        self.multi_cell(val_w, 6, val_str)

    # ── table ─────────────────────────────────────────────────────────────────

    def table_head(self, cols: list[tuple[str, float]]):
        """Render a table header. cols = [(label, width_mm), ...]"""
        if self.get_y() > 255:
            self.add_page()
        self.set_fill_color(*_SURFACE)
        self.set_draw_color(190, 205, 225)
        self.set_line_width(0.25)
        self.set_font('Arial', 'B', 7.5)
        self.set_text_color(*_NAVY)
        for label, w in cols:
            self.cell(w, 7, _s(label), 1, 0, 'C', fill=True)
        self.ln()

    def table_row(self, vals: list[str], cols: list[tuple[str, float]],
                  alt: bool = False, highlight: tuple | None = None):
        """Render a table data row."""
        if self.get_y() > 265:
            self.add_page()
            self.table_head(cols)
        if highlight:
            self.set_fill_color(*highlight)
        elif alt:
            self.set_fill_color(250, 252, 255)
        else:
            self.set_fill_color(*_WHITE)
        self.set_draw_color(210, 218, 230)
        self.set_line_width(0.2)
        self.set_font('Arial', '', 7.5)
        self.set_text_color(*_TEXT)
        for val, (_, w) in zip(vals, cols):
            self.cell(w, 6, _trunc(str(val), int(w * 1.5)), 1, 0, 'L', fill=True)
        self.ln()

    # ── bullets ───────────────────────────────────────────────────────────────

    def bullet_list(self, items: list[str], numbered: bool = False):
        self.set_font('Arial', '', 8.5)
        self.set_text_color(*_TEXT)
        for i, item in enumerate(items, 1):
            prefix = f'{i}. ' if numbered else '  * '
            self.set_x(16)
            self.multi_cell(0, 6, prefix + _s(item))

    # ── note / callout box ────────────────────────────────────────────────────

    def note_box(self, text: str, level: str = 'info'):
        """Render a highlighted callout box. level: info | warning | success | danger"""
        colours = {
            'info':    (_NAVY,    _SURFACE),
            'warning': (_AMBER,   _AMBER_BG),
            'success': (_GREEN,   _GREEN_BG),
            'danger':  (_RED,     _RED_BG),
        }
        fg, bg = colours.get(level, colours['info'])
        if self.get_y() > 255:
            self.add_page()
        self.set_fill_color(*bg)
        self.set_draw_color(*fg)
        self.set_line_width(0.4)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(*fg)
        self.multi_cell(0, 6, _s(text), border=1, fill=True)
        self.ln(3)

    # ── divider ───────────────────────────────────────────────────────────────

    def divider(self):
        self.set_draw_color(*_KHAKI)
        self.set_line_width(0.4)
        self.line(14, self.get_y(), self.w - 14, self.get_y())
        self.ln(3)

    # ── output ────────────────────────────────────────────────────────────────

    def to_bytes(self) -> bytes:
        return bytes(self.output())


# ═══════════════════════════════════════════════════════════════════════════════
# Public generator functions
# ═══════════════════════════════════════════════════════════════════════════════

def generate_dashboard_pdf(payload: dict,
                            officer_email: str = '',
                            officer_role: str = '') -> bytes:
    """
    Generate a professional PDF from the main dashboard scan results.
    payload = session['last_export']
    """
    email    = payload.get('email', '')
    username = payload.get('username', '')
    phone    = payload.get('phone', '')
    tools    = payload.get('selected_tools', [])
    now_str  = datetime.now(dt_timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

    target = email or username or phone or 'Unknown'

    pdf = _IntelReport(
        report_title  = 'OSINT Investigation Report',
        module_name   = 'Main Dashboard',
        officer_email = officer_email,
        officer_role  = officer_role,
    )
    pdf.add_page()

    # Cover
    pdf.cover_block(
        title    = 'OSINT Investigation Report',
        subtitle = 'Open-Source Intelligence — Structured Scan Output',
        target   = target,
    )

    # Meta strip
    meta = []
    if email:    meta.append(('Email', email))
    if username: meta.append(('Username', username))
    if phone:    meta.append(('Phone', phone))
    meta.append(('Scan Date', now_str))
    if tools:    meta.append(('Tools', ', '.join(tools)))
    pdf.meta_strip(meta)

    # ── Holehe Email Footprint ─────────────────────────────────────────────
    holehe_results = [r for r in payload.get('results', []) if r.get('exists')]
    if holehe_results:
        pdf.section_header('Email Footprint (Holehe)',
                           count_badge=f'{len(holehe_results)} accounts found')
        cols = [('Platform / Domain', 80), ('Email Recovery', 52), ('Phone Number', 50)]
        pdf.table_head(cols)
        for i, item in enumerate(holehe_results[:50]):
            pdf.table_row(
                [item.get('domain', '—'),
                 item.get('emailrecovery') or '—',
                 item.get('phoneNumber') or '—'],
                cols, alt=(i % 2 == 1),
                highlight=_GREEN_BG if item.get('exists') else None,
            )
        if len(holehe_results) > 50:
            pdf.note_box(f'... and {len(holehe_results) - 50} more records. '
                         'Download JSON for complete data.', 'info')
        pdf.ln(4)

    # ── Disposable Email Check ────────────────────────────────────────────
    disp = payload.get('disposable_result')
    if isinstance(disp, dict) and disp:
        pdf.section_header('Disposable Email Risk Check')
        for k, v in disp.items():
            pdf.kv(k.replace('_', ' ').title(), v)
        pdf.ln(4)

    # ── Email Breach Pivots ───────────────────────────────────────────────
    pivots = payload.get('email_pivots_result')
    if isinstance(pivots, dict):
        pivot_list = pivots.get('pivots', [])
        if pivot_list:
            pdf.section_header('Email Breach & Intelligence Pivots',
                               count_badge=f'{len(pivot_list)} links')
            cols = [('Service', 70), ('URL', 112)]
            pdf.table_head(cols)
            for i, p in enumerate(pivot_list):
                pdf.table_row([p.get('name', ''), p.get('url', '')],
                              cols, alt=(i % 2 == 1))
            pdf.ln(4)

    # ── Phone Intelligence ────────────────────────────────────────────────
    phone_r = payload.get('phone_result')
    if isinstance(phone_r, dict) and phone_r.get('valid'):
        pdf.section_header('Phone Intelligence')
        kv_map = [
            ('Input', phone_r.get('input', '')),
            ('International', phone_r.get('international', '')),
            ('National', phone_r.get('national', '')),
            ('E.164', phone_r.get('e164', '')),
            ('Carrier', phone_r.get('carrier', '')),
            ('Region', phone_r.get('region', '')),
            ('Country Code', phone_r.get('country_code', '')),
            ('Number Type', phone_r.get('number_type', '')),
            ('Timezones', ', '.join(phone_r.get('timezones', []))),
        ]
        for k, v in kv_map:
            if v:
                pdf.kv(k, v)
        pdf.ln(4)

    # ── User-Scanner — Email Results ──────────────────────────────────────
    us_email = payload.get('user_scanner_email', [])
    if us_email:
        pdf.section_header('User-Scanner: Email Intelligence Findings',
                           count_badge=f'{len(us_email)} platforms found')
        cols = [('Platform', 48), ('Category', 38), ('Profile / Link', 76), ('Status', 20)]
        pdf.table_head(cols)
        for i, item in enumerate(us_email[:100]):
            pdf.table_row(
                [item.get('platform', '—'),
                 item.get('category', '—'),
                 item.get('url', '—'),
                 item.get('status', 'Found')],
                cols, alt=(i % 2 == 1), highlight=_GREEN_BG,
            )
        if len(us_email) > 100:
            pdf.note_box(f'... and {len(us_email) - 100} more. Download JSON for full data.', 'info')
        pdf.ln(4)

    # ── BehindTheEmail Intelligence ──────────────────────────────────────
    bte_result = payload.get('behindtheemail_result')
    if isinstance(bte_result, dict):
        profile = bte_result.get('profile') if isinstance(bte_result.get('profile'), dict) else None
        if profile:
            pdf.section_header('BehindTheEmail Intelligence')

            # Identity summary
            summary = profile.get('summary', {})
            if isinstance(summary, dict):
                for label, keys in [
                    ('Name',     ['displayName', 'name', 'fullName']),
                    ('Location', ['location', 'city']),
                    ('Bio',      ['bio', 'description', 'headline']),
                    ('Website',  ['website', 'url']),
                ]:
                    for k in keys:
                        v = summary.get(k)
                        if v and isinstance(v, str) and v.strip():
                            pdf.kv(label, v[:200])
                            break

            # Platform presence table
            _PLAT_KEYS = [
                'linkedIn', 'linkedin', 'github', 'gitlab', 'google', 'microsoft',
                'tiktok', 'gravatar', 'chess', 'duolingo', 'etsy', 'flickr', 'adobe', 'vsco',
            ]
            plat_rows = []
            for key in _PLAT_KEYS:
                val = profile.get(key)
                if not val:
                    continue
                plat_label = key[0].upper() + key[1:]
                if isinstance(val, dict):
                    url   = val.get('profileUrl') or val.get('url') or ''
                    uname = (val.get('username') or
                             (val.get('basic') or {}).get('displayName') or
                             val.get('displayName') or '')
                    status = val.get('status', 'Found')
                    plat_rows.append((plat_label, uname, url, status))
                elif isinstance(val, str) and val:
                    plat_rows.append((plat_label, '', val, 'Found'))

            # registeredAccounts supplemental
            reg = profile.get('registeredAccounts')
            if isinstance(reg, list):
                for item in reg[:20]:
                    if isinstance(item, dict):
                        plat_rows.append((
                            _s(item.get('platform') or _url_to_platform(item.get('url', ''))),
                            _s(item.get('username', '')),
                            item.get('url') or item.get('profileUrl', ''),
                            item.get('status', 'Found'),
                        ))
                    elif isinstance(item, str):
                        plat_rows.append((_url_to_platform(item), '', item, 'Found'))

            if plat_rows:
                pdf.ln(2)
                cols = [('Platform', 38), ('Name / Username', 44), ('Profile URL', 72), ('Status', 28)]
                pdf.table_head(cols)
                for i, (plat, uname, url, status) in enumerate(plat_rows[:50]):
                    pdf.table_row(
                        [_s(plat), _s(uname) or '—', _s(url) or '—', _s(status) or 'Found'],
                        cols, alt=(i % 2 == 1), highlight=_GREEN_BG,
                    )
                if len(plat_rows) > 50:
                    pdf.note_box(f'... and {len(plat_rows) - 50} more. Download JSON for full data.', 'info')
            else:
                pdf.note_box('Profile found but no linked platform accounts detected.', 'info')

            # Data breach indicators
            breach = profile.get('dataBreach')
            if isinstance(breach, dict) and any(v for v in breach.values() if v):
                pdf.ln(3)
                pdf.set_font('Arial', 'B', 8.5)
                pdf.set_text_color(*_NAVY)
                pdf.cell(0, 6, 'Data Breach Indicators:', 0, 1)
                for k, v in breach.items():
                    if v:
                        pdf.kv(k.replace('_', ' ').title(), str(v), key_w=65)

            # Email service / pattern fields
            for field_key, field_label in [('emailService', 'Email Service'), ('emailPattern', 'Email Pattern')]:
                field = profile.get(field_key)
                if isinstance(field, dict) and any(v for v in field.values() if v):
                    pdf.ln(2)
                    pdf.set_font('Arial', 'B', 8.5)
                    pdf.set_text_color(*_NAVY)
                    pdf.cell(0, 6, f'{field_label}:', 0, 1)
                    for k, v in field.items():
                        if v:
                            pdf.kv(k.replace('_', ' ').title(), str(v)[:120], key_w=65)

            pdf.ln(4)

        elif bte_result.get('error'):
            pdf.section_header('BehindTheEmail Intelligence')
            pdf.note_box(f'BehindTheEmail query error: {_s(str(bte_result.get("error", "Unknown error")))}', 'warning')
            pdf.ln(4)
        else:
            pdf.section_header('BehindTheEmail Intelligence')
            pdf.note_box('No BehindTheEmail findings available for this email address.', 'info')
            pdf.ln(4)

    # ── User-Scanner — Username Results ───────────────────────────────────
    us_user = payload.get('user_scanner_username', [])
    if us_user:
        pdf.section_header('User-Scanner: Username Intelligence Findings',
                           count_badge=f'{len(us_user)} platforms found')
        cols = [('Platform', 48), ('Category', 38), ('Profile / Link', 76), ('Status', 20)]
        pdf.table_head(cols)
        for i, item in enumerate(us_user[:100]):
            pdf.table_row(
                [item.get('platform', '—'),
                 item.get('category', '—'),
                 item.get('url', '—'),
                 item.get('status', 'Found')],
                cols, alt=(i % 2 == 1), highlight=_GREEN_BG,
            )
        if len(us_user) > 100:
            pdf.note_box(f'... and {len(us_user) - 100} more. Download JSON for full data.', 'info')
        pdf.ln(4)

    # ── Sherlock Results ──────────────────────────────────────────────────
    sherlock = payload.get('sherlock_result')
    if isinstance(sherlock, dict) and sherlock.get('installed'):
        profiles = sherlock.get('found_profiles', [])
        pdf.section_header('Sherlock Username Deep Scan',
                           count_badge=f'{len(profiles)} profiles found')
        if profiles:
            cols = [('Platform', 45), ('Username', 30), ('Profile URL', 90), ('Status', 17)]
            pdf.table_head(cols)
            for i, url in enumerate(profiles[:100]):
                platform = _url_to_platform(url)
                pdf.table_row(
                    [platform, _s(username), url, 'Found'],
                    cols, alt=(i % 2 == 0), highlight=_GREEN_BG,
                )
            if len(profiles) > 100:
                pdf.note_box(f'... and {len(profiles) - 100} more. See JSON export.', 'info')
        else:
            pdf.note_box('Sherlock found no confirmed profiles.', 'info')
        pdf.ln(4)

    # ── Maigret Results ───────────────────────────────────────────────────
    maigret = payload.get('maigret_result')
    if isinstance(maigret, dict) and maigret.get('installed'):
        profiles = maigret.get('found_profiles', [])
        pdf.section_header('Maigret Username Deep Scan',
                           count_badge=f'{len(profiles)} profiles found')
        if profiles:
            cols = [('Platform', 45), ('Username', 30), ('Profile URL', 90), ('Status', 17)]
            pdf.table_head(cols)
            for i, url in enumerate(profiles[:100]):
                platform = _url_to_platform(url)
                pdf.table_row(
                    [platform, _s(username), url, 'Found'],
                    cols, alt=(i % 2 == 0), highlight=_GREEN_BG,
                )
            if len(profiles) > 100:
                pdf.note_box(f'... and {len(profiles) - 100} more. See JSON export.', 'info')
        else:
            pdf.note_box('Maigret found no confirmed profiles.', 'info')
        pdf.ln(4)

    # ── Combined Username Deep Scan ────────────────────────────────────────
    userdeep = payload.get('userdeep_result')
    if isinstance(userdeep, dict) and userdeep.get('profiles'):
        profiles = userdeep['profiles']
        pdf.section_header('Combined Username Deep Scan (Sherlock + Maigret)',
                           count_badge=f'{len(profiles)} unique profiles')
        cols = [('Platform', 45), ('Username', 30), ('Profile URL', 90), ('Status', 17)]
        pdf.table_head(cols)
        for i, url in enumerate(profiles[:100]):
            platform = _url_to_platform(url)
            pdf.table_row(
                [platform, _s(username), url, 'Found'],
                cols, alt=(i % 2 == 0), highlight=_GREEN_BG,
            )
        if len(profiles) > 100:
            pdf.note_box(f'... and {len(profiles) - 100} more. See JSON export.', 'info')
        pdf.ln(4)

    # ── Username Footprint ─────────────────────────────────────────────────
    uname_r = payload.get('username_result')
    if isinstance(uname_r, dict):
        plats = uname_r.get('platforms', [])
        if plats:
            pdf.section_header('Username Footprint Check',
                               count_badge=f'{len(plats)} platforms found')
            cols = [('Platform', 60), ('URL', 122)]
            pdf.table_head(cols)
            for i, p in enumerate(plats):
                pdf.table_row([p.get('name', ''), p.get('url', '')],
                              cols, alt=(i % 2 == 1))
            pdf.ln(4)

    # ── Closing note ──────────────────────────────────────────────────────
    pdf.divider()
    pdf.note_box(
        'RESTRICTED — For law enforcement use only. '
        'All findings are based on open-source intelligence gathered at the '
        'time of this scan and should be independently verified before use '
        'in any legal proceeding.',
        'warning'
    )

    return pdf.to_bytes()


# ─────────────────────────────────────────────────────────────────────────────

def generate_infra_pdf(result: dict,
                        query: str = '',
                        officer_email: str = '',
                        officer_role: str = '') -> bytes:
    """
    Generate a professional Infrastructure Intelligence PDF.
    result = parsed Shodan data from _parse_shodan()
    """
    h   = result.get('host_info', {})
    geo = result.get('geo', {})

    pdf = _IntelReport(
        report_title  = 'Infrastructure Intelligence Report',
        module_name   = 'Infra Intel',
        officer_email = officer_email,
        officer_role  = officer_role,
    )
    pdf.add_page()

    # Cover
    target_label = f'{h.get("ip", "?")}' + (f' ({query})' if query and query != h.get('ip') else '')
    pdf.cover_block(
        title    = 'Infrastructure Intelligence Report',
        subtitle = 'Shodan-Powered Host Reconnaissance',
        target   = target_label,
    )

    # Meta strip
    meta = [
        ('IP Address', h.get('ip', '—')),
        ('Country',    h.get('country', '—')),
        ('Open Ports', str(result.get('total_ports', 0))),
        ('CVEs',       str(len(result.get('vulns', [])))),
        ('Scan Date',  datetime.now(dt_timezone.utc).strftime('%Y-%m-%d %H:%M UTC')),
    ]
    pdf.meta_strip(meta)

    # ── Host Information ──────────────────────────────────────────────────
    pdf.section_header('Host Information')
    kv_pairs = [
        ('IP Address',    h.get('ip', '—')),
        ('Query Target',  h.get('query', '—') if h.get('query') != h.get('ip') else None),
        ('Organization',  h.get('org', '—')),
        ('ISP',           h.get('isp', '—')),
        ('ASN',           h.get('asn', '—')),
        ('Country',       h.get('country', '—')),
        ('City',          h.get('city', '—')),
        ('Hostnames',     ', '.join(h.get('hostnames', [])) or '—'),
        ('Domains',       ', '.join(h.get('domains', [])) or '—'),
        ('Tags',          ', '.join(h.get('tags', [])) or 'None'),
        ('Last Indexed',  h.get('last_update', '—')[:10] if h.get('last_update') else '—'),
    ]
    for k, v in kv_pairs:
        if v is not None:
            pdf.kv(k, v)
    pdf.ln(4)

    # ── Geolocation ───────────────────────────────────────────────────────
    lat, lng = geo.get('lat'), geo.get('lng')
    if lat and lng:
        pdf.section_header('Geolocation')
        maps_url = f'https://www.google.com/maps/search/?api=1&query={lat:.6f},{lng:.6f}'
        pdf.kv('Latitude',        f'{lat:.6f}')
        pdf.kv('Longitude',       f'{lng:.6f}')
        pdf.kv('City',            h.get('city', '—'))
        pdf.kv('Country',         h.get('country', '—'))
        pdf.kv('Google Maps URL', maps_url)
        pdf.ln(4)

    # ── Open Ports & Services ─────────────────────────────────────────────
    services = result.get('services', [])
    if services:
        pdf.section_header('Open Ports & Services',
                           count_badge=f'{len(services)} services')
        cols = [('Port', 20), ('Proto', 18), ('Product / Service', 80), ('Version', 64)]
        pdf.table_head(cols)
        for i, svc in enumerate(services):
            pdf.table_row(
                [str(svc.get('port', '?')),
                 svc.get('transport', '').upper(),
                 svc.get('product') or svc.get('service') or '—',
                 svc.get('version') or '—'],
                cols, alt=(i % 2 == 1)
            )
        pdf.ln(4)

    # ── Technologies ──────────────────────────────────────────────────────
    technologies = result.get('technologies', [])
    if technologies:
        pdf.section_header('Detected Technologies',
                           count_badge=f'{len(technologies)} detected')
        tech_text = ', '.join(
            t['name'] + (f' {t["version"]}' if t.get('version') else '')
            for t in technologies
        )
        pdf.set_font('Arial', '', 8.5)
        pdf.set_text_color(*_TEXT)
        pdf.multi_cell(0, 6, _s(tech_text))
        pdf.ln(4)

    # ── SSL / TLS ─────────────────────────────────────────────────────────
    ssl = result.get('ssl_info')
    if ssl:
        pdf.section_header('SSL / TLS Certificate')
        ssl_kvs = [
            ('Subject CN',    ssl.get('subject_cn', '—')),
            ('Issuer',        ssl.get('issuer_cn', '—') + (f' ({ssl["issuer_org"]})' if ssl.get('issuer_org') else '')),
            ('Issued',        ssl.get('issued', '—')[:10]),
            ('Expires',       ssl.get('expires', '—')[:10]),
            ('Cipher',        ssl.get('cipher', '—')),
            ('TLS Versions',  ', '.join(ssl.get('tls_versions', [])) or '—'),
            ('SHA-256',       ssl.get('sha256', '—')[:48] + '...' if len(ssl.get('sha256', '')) > 48 else ssl.get('sha256', '—')),
        ]
        for k, v in ssl_kvs:
            if v:
                pdf.kv(k, v)
        san = ssl.get('san_domains', [])
        if san:
            pdf.kv('SAN Domains', f'{len(san)} domains: ' + ', '.join(san[:8]) + ('...' if len(san) > 8 else ''))
        pdf.ln(4)

    # ── Vulnerabilities ───────────────────────────────────────────────────
    vulns = result.get('vulns', [])
    if vulns:
        pdf.section_header('Known Vulnerabilities (CVEs)',
                           count_badge=f'{len(vulns)} CVEs')
        cols = [('CVE ID', 40), ('Severity', 24), ('CVSS', 16), ('Summary', 102)]
        pdf.table_head(cols)
        severity_colours = {
            'Critical': _RED_BG,
            'High':     _AMBER_BG,
            'Medium':   (219, 234, 254),   # blue-100
            'Low':      _SURFACE,
        }
        for i, v in enumerate(vulns):
            hl = severity_colours.get(v.get('severity', ''), None)
            pdf.table_row(
                [v.get('cve', ''),
                 v.get('severity', '—'),
                 f'{v.get("cvss", 0):.1f}',
                 (v.get('summary') or '')[:100]],
                cols, alt=(i % 2 == 1), highlight=hl,
            )
        pdf.ln(4)
    else:
        pdf.section_header('Known Vulnerabilities (CVEs)')
        pdf.note_box('No known CVEs indexed by Shodan for this host.', 'success')
        pdf.ln(4)

    # ── Closing note ──────────────────────────────────────────────────────
    pdf.divider()
    pdf.note_box(
        'RESTRICTED — Data sourced from Shodan public index. '
        'For law enforcement use only. Verify independently before legal use.',
        'warning'
    )

    return pdf.to_bytes()


# ─────────────────────────────────────────────────────────────────────────────

def generate_image_pdf(metadata: dict,
                        officer_email: str = '',
                        officer_role: str = '') -> bytes:
    """
    Generate a professional Image Intelligence PDF.
    metadata = session['last_image_analysis']
    """
    file_info = metadata.get('file', {})
    filename  = file_info.get('filename', 'Unknown')

    pdf = _IntelReport(
        report_title  = 'Image Metadata Intelligence Report',
        module_name   = 'Image Intel',
        officer_email = officer_email,
        officer_role  = officer_role,
    )
    pdf.add_page()

    # Cover
    pdf.cover_block(
        title    = 'Image Metadata Intelligence Report',
        subtitle = 'EXIF Forensic Analysis — Hyderabad City Police',
        target   = filename,
    )

    # Meta strip
    status_info = metadata.get('status', {})
    meta = [
        ('Filename',   filename),
        ('Format',     file_info.get('format', '—')),
        ('Resolution', file_info.get('resolution', '—')),
        ('Status',     status_info.get('text', '—')),
        ('Scan Date',  datetime.now(dt_timezone.utc).strftime('%Y-%m-%d %H:%M UTC')),
    ]
    pdf.meta_strip(meta)

    # ── Metadata Status ────────────────────────────────────────────────────
    pdf.section_header('Metadata Status')
    level = status_info.get('level', 'info')
    pdf.note_box(
        f'{status_info.get("text", "Unknown")} — {status_info.get("description", "")}',
        level
    )
    pdf.ln(2)

    # ── File Information ──────────────────────────────────────────────────
    pdf.section_header('File Information')
    file_kvs = [
        ('Original Filename', filename),
        ('File Size',         str(file_info.get('file_size', '—'))),
        ('MIME Type',         file_info.get('mime_type', '—')),
        ('Format',            file_info.get('format', '—')),
        ('Resolution',        file_info.get('resolution', '—')),
        ('Width (px)',        str(file_info.get('width', '—'))),
        ('Height (px)',       str(file_info.get('height', '—'))),
    ]
    for k, v in file_kvs:
        pdf.kv(k, v)
    pdf.ln(4)

    # ── Device / Camera Information ────────────────────────────────────────
    device = metadata.get('device', {})
    if device and any(v and v != 'Unknown' for v in device.values()):
        pdf.section_header('Device & Camera Information')
        device_kvs = [
            ('Manufacturer',  device.get('make', '—')),
            ('Model',         device.get('model', '—')),
            ('Camera Model',  device.get('camera_model', '—')),
            ('Lens',          device.get('lens_info', '—') or '—'),
            ('Software',      device.get('software', '—') or '—'),
            ('Firmware',      device.get('firmware', '—') or '—'),
        ]
        for k, v in device_kvs:
            if v and v not in ('—', 'None', 'Unknown'):
                pdf.kv(k, v)
        pdf.ln(4)

    # ── Timestamps ────────────────────────────────────────────────────────
    ts = metadata.get('timestamps', {})
    if ts and any(v and v != 'Unknown' for v in ts.values()):
        pdf.section_header('Timestamps')
        ts_kvs = [
            ('Date Taken',     ts.get('date_taken', '—')),
            ('Time Taken',     ts.get('time_taken', '—')),
            ('Timezone',       ts.get('timezone', '—')),
            ('Date Modified',  ts.get('date_modified', '—')),
            ('Date Created',   ts.get('date_created', '—')),
        ]
        for k, v in ts_kvs:
            if v and v != 'Unknown':
                pdf.kv(k, v)
        pdf.ln(4)

    # ── GPS Coordinates ───────────────────────────────────────────────────
    gps = metadata.get('gps')
    if gps:
        pdf.section_header('GPS Coordinates & Location')
        lat = gps.get('latitude')
        lng = gps.get('longitude')
        alt = gps.get('altitude')
        maps_url = gps.get('google_maps_url', '')
        pdf.kv('Latitude',        f'{lat:.6f}' if lat else '—')
        pdf.kv('Longitude',       f'{lng:.6f}' if lng else '—')
        if alt:
            pdf.kv('Altitude',    f'{alt:.1f} m')
        pdf.kv('Coordinates',     gps.get('coordinates', '—'))
        pdf.kv('Google Maps URL', maps_url)
        pdf.ln(2)
        pdf.note_box(
            f'GPS data embedded in this image places it at coordinates '
            f'{gps.get("coordinates", "?")}. '
            'Verify independently using the Google Maps link above.',
            'warning'
        )
        pdf.ln(4)
    else:
        pdf.section_header('GPS Coordinates')
        pdf.note_box('No GPS data found in this image.', 'info')
        pdf.ln(4)

    # ── Warnings ──────────────────────────────────────────────────────────
    warnings = metadata.get('warnings', [])
    if warnings:
        pdf.section_header('Forensic Warnings', count_badge=f'{len(warnings)}')
        for w in warnings:
            pdf.bullet_list([w])
        pdf.ln(4)

    # ── Reverse Image Intelligence (Google Lens) ──────────────────────────
    lens = metadata.get('lens')
    if isinstance(lens, dict) and not lens.get('error'):
        pdf.section_header('Reverse Image Intelligence (Google Lens)')

        summary = lens.get('summary', '')
        if summary:
            pdf.note_box(summary, 'info')
            pdf.ln(2)

        # Exact matches
        exact = lens.get('exact_matches', [])
        if exact:
            pdf.set_font('Arial', 'B', 8.5)
            pdf.set_text_color(*_NAVY)
            pdf.cell(0, 6, f'Exact Duplicates Found ({len(exact)})', 0, 1)
            cols = [('Title', 68), ('Source', 46), ('URL', 68)]
            pdf.table_head(cols)
            for i, m in enumerate(exact[:30]):
                pdf.table_row(
                    [m.get('title', '—'), m.get('source', '—'), m.get('link', '—')],
                    cols, alt=(i % 2 == 1), highlight=_GREEN_BG,
                )
            if len(exact) > 30:
                pdf.note_box(f'… and {len(exact) - 30} more duplicates.', 'info')
            pdf.ln(3)

        # Visual matches
        visual = lens.get('visual_matches', [])
        if visual:
            pdf.set_font('Arial', 'B', 8.5)
            pdf.set_text_color(*_NAVY)
            pdf.cell(0, 6, f'Visually Similar Images ({len(visual)})', 0, 1)
            cols = [('Title', 68), ('Source', 46), ('URL', 68)]
            pdf.table_head(cols)
            for i, m in enumerate(visual[:40]):
                pdf.table_row(
                    [m.get('title', '—'), m.get('source', '—'), m.get('link', '—')],
                    cols, alt=(i % 2 == 1),
                )
            if len(visual) > 40:
                pdf.note_box(f'… and {len(visual) - 40} more results.', 'info')
            pdf.ln(3)

        # Knowledge graph
        kg = lens.get('knowledge_graph')
        if kg and kg.get('title'):
            pdf.set_font('Arial', 'B', 8.5)
            pdf.set_text_color(*_NAVY)
            pdf.cell(0, 6, 'Entity Recognition (Knowledge Graph)', 0, 1)
            for label, val in [
                ('Entity',      kg.get('title', '')),
                ('Type',        kg.get('type', '')),
                ('Description', kg.get('description', '')),
                ('Source',      kg.get('source_name', '')),
            ]:
                if val:
                    pdf.kv(label, val[:200])
            pdf.ln(3)

        # Detected text
        text = lens.get('detected_text')
        if text and text.get('full_text'):
            pdf.set_font('Arial', 'B', 8.5)
            pdf.set_text_color(*_NAVY)
            pdf.cell(0, 6, 'Text Detected in Image', 0, 1)
            pdf.set_font('Arial', '', 8)
            pdf.set_text_color(*_TEXT)
            pdf.multi_cell(0, 5.5, _s(text['full_text'][:600]))
            pdf.ln(2)

        # Entities
        entities = lens.get('entities', [])
        if entities:
            pdf.set_font('Arial', 'B', 8.5)
            pdf.set_text_color(*_NAVY)
            pdf.cell(0, 6, f'Recognized Entities ({len(entities)})', 0, 1)
            parts = [f"{e.get('name', '')} ({e.get('type', '')})"
                     if e.get('type') else e.get('name', '')
                     for e in entities[:20]]
            pdf.set_font('Arial', '', 8.5)
            pdf.set_text_color(*_TEXT)
            pdf.multi_cell(0, 6, _s(', '.join(parts)))
            pdf.ln(2)

        # Products
        products = lens.get('products', [])
        if products:
            pdf.set_font('Arial', 'B', 8.5)
            pdf.set_text_color(*_NAVY)
            pdf.cell(0, 6, f'Product Matches ({len(products)})', 0, 1)
            cols = [('Product', 80), ('Source', 44), ('Price', 28), ('URL', 30)]
            pdf.table_head(cols)
            for i, p in enumerate(products[:20]):
                pdf.table_row(
                    [p.get('title', '—'), p.get('source', '—'),
                     p.get('price', '—') or '—', p.get('link', '—')],
                    cols, alt=(i % 2 == 1),
                )
            pdf.ln(3)

        # Related searches
        related = lens.get('related_searches', [])
        if related:
            pdf.set_font('Arial', 'B', 8.5)
            pdf.set_text_color(*_NAVY)
            pdf.cell(0, 6, 'Related Intelligence Queries', 0, 1)
            queries = [r.get('query', '') for r in related[:12] if r.get('query')]
            pdf.bullet_list(queries)
            pdf.ln(2)

        pdf.ln(2)

    # ── Closing note ──────────────────────────────────────────────────────
    pdf.divider()
    pdf.note_box(
        'RESTRICTED — Image forensics report. For law enforcement use only. '
        'EXIF data is embedded by the originating device and may have been '
        'modified. Independently verify GPS coordinates and timestamps.',
        'warning'
    )

    return pdf.to_bytes()


# ─────────────────────────────────────────────────────────────────────────────

def generate_ask_ai_pdf(query: str,
                         result: dict,
                         officer_email: str = '',
                         officer_role: str = '') -> bytes:
    """
    Generate a professional AI Investigation Report PDF.
    result = parsed JSON from /api/ask-ai
    """
    pdf = _IntelReport(
        report_title  = 'AI-Assisted Investigation Report',
        module_name   = 'Ask AI',
        officer_email = officer_email,
        officer_role  = officer_role,
    )
    pdf.add_page()

    # Cover
    pdf.cover_block(
        title    = 'AI-Assisted Investigation Report',
        subtitle = 'OSINT Copilot — Powered by OpenAI GPT',
    )

    # Meta strip
    meta = [
        ('Generated', datetime.now(dt_timezone.utc).strftime('%Y-%m-%d %H:%M UTC')),
        ('Tools', str(len(result.get('tools', [])))),
        ('Flow Steps', str(len(result.get('investigation_flow', [])))),
    ]
    pdf.meta_strip(meta)

    # ── Investigation Query ────────────────────────────────────────────────
    pdf.section_header('Investigation Query')
    pdf.set_font('Arial', '', 9)
    pdf.set_text_color(*_TEXT)
    pdf.set_fill_color(*_SURFACE)
    pdf.set_draw_color(190, 205, 225)
    pdf.set_line_width(0.3)
    pdf.multi_cell(0, 6, _s(query), border=1, fill=True)
    pdf.ln(4)

    # ── Investigation Overview ─────────────────────────────────────────────
    summary = result.get('summary', '')
    if summary:
        pdf.section_header('Investigation Overview')
        pdf.note_box(summary, 'info')
        pdf.ln(2)

    # ── Recommended Tools ──────────────────────────────────────────────────
    tools = result.get('tools', [])
    if tools:
        pdf.section_header('Recommended Tools', count_badge=f'{len(tools)} tools')
        cols = [('Tool', 44), ('Category', 40), ('Cost', 16), ('Input', 36), ('Expected Output', 46)]
        pdf.table_head(cols)
        for i, t in enumerate(tools):
            pdf.table_row(
                [t.get('name', ''),
                 t.get('category', ''),
                 t.get('free_paid', ''),
                 t.get('input', ''),
                 t.get('output', '')],
                cols, alt=(i % 2 == 1)
            )
        pdf.ln(3)

        # Tool URLs as a separate bullet list for readability
        pdf.set_font('Arial', 'B', 8)
        pdf.set_text_color(*_NAVY)
        pdf.cell(0, 6, 'Tool URLs:', 0, 1)
        for t in tools:
            pdf.set_font('Arial', '', 7.5)
            pdf.set_text_color(*_TEXT)
            pdf.set_x(18)
            pdf.multi_cell(0, 5, f'{_s(t.get("name", ""))}: {_s(t.get("url", ""))}')
        pdf.ln(4)

    # ── Investigation Flow ─────────────────────────────────────────────────
    flow = result.get('investigation_flow', [])
    if flow:
        pdf.section_header('Recommended Investigation Flow',
                           count_badge=f'{len(flow)} steps')
        for i, step in enumerate(flow, 1):
            # Strip any leading "Step N:" prefix the AI might have added
            clean = step
            if clean.lower().startswith(f'step {i}:'):
                clean = clean[len(f'step {i}:'):].strip()
            elif clean.lower().startswith(f'step {i}.'):
                clean = clean[len(f'step {i}.'):].strip()

            if pdf.get_y() > 260:
                pdf.add_page()

            # Step number circle (approximated with bold prefix)
            pdf.set_font('Arial', 'B', 9)
            pdf.set_text_color(*_NAVY)
            pdf.set_x(14)
            pdf.cell(10, 6, f'{i}.', 0, 0)
            pdf.set_font('Arial', '', 9)
            pdf.set_text_color(*_TEXT)
            pdf.multi_cell(0, 6, _s(clean))
        pdf.ln(4)

    # ── Notes / Caveats ────────────────────────────────────────────────────
    notes = result.get('notes', '').strip()
    if notes:
        pdf.section_header('Legal & Ethical Notes')
        pdf.note_box(notes, 'warning')
        pdf.ln(4)

    # ── Closing note ──────────────────────────────────────────────────────
    pdf.divider()
    pdf.note_box(
        'RESTRICTED — AI-generated investigation guidance. '
        'For law enforcement use only. All tool recommendations and '
        'investigation steps are advisory and must be validated by '
        'a qualified investigator before operational use.',
        'danger'
    )

    return pdf.to_bytes()
