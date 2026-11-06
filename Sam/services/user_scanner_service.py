"""
User-Scanner Service Layer
Handles execution of user-scanner CLI tool with proper security and error handling.
"""

import subprocess
import json
import re
import os
import sys
import tempfile
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import logging

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')

logger = logging.getLogger(__name__)


@dataclass
class PlatformResult:
    """Structured result for a single platform check."""
    platform: str
    site_name: str
    found: bool
    url: str
    category: str
    status: str  # "Registered", "Not Registered", "Found", "Not Found", "Error"
    confidence: str = "Medium"
    extra: Optional[str] = None
    reason: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Complete scan result for email or username."""
    query: str
    scan_type: str  # "email" or "username"
    platforms_found: int
    platforms_checked: int
    results: List[PlatformResult]
    timestamp: str
    scan_duration: float
    status: str = "success"
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "query": self.query,
            "scan_type": self.scan_type,
            "platforms_found": self.platforms_found,
            "platforms_checked": self.platforms_checked,
            "timestamp": self.timestamp,
            "scan_duration": self.scan_duration,
            "status": self.status,
            "error_message": self.error_message,
            "results": [r.to_dict() for r in self.results]
        }


class UserScannerService:
    """
    Service for executing user-scanner tool securely.
    
    This service handles:
    - Input validation and sanitization
    - Secure subprocess execution
    - Output parsing and normalization
    - Error handling and timeouts
    """
    
    # Platform category mapping for better organization
    CATEGORY_MAP = {
        # Social Media
        "instagram": "Social Media",
        "twitter": "Social Media",
        "facebook": "Social Media",
        "tiktok": "Social Media",
        "snapchat": "Social Media",
        "pinterest": "Social Media",
        "linkedin": "Social Media",
        "reddit": "Social Media",
        "tumblr": "Social Media",
        "flickr": "Social Media",
        "vsco": "Social Media",
        "imgur": "Social Media",
        "deviantart": "Social Media",
        "myspace": "Social Media",
        "parler": "Social Media",
        "tellonym": "Social Media",
        "wattpad": "Social Media",
        "fanpop": "Social Media",
        "xing": "Social Media",
        
        # Developer Platforms
        "github": "Developer",
        "gitlab": "Developer",
        "bitbucket": "Developer",
        "stackoverflow": "Developer",
        "replit": "Developer",
        "codepen": "Developer",
        "huggingface": "Developer",
        "docker": "Developer",
        "npm": "Developer",
        "pypi": "Developer",
        "rubygems": "Developer",
        "packagist": "Developer",
        "nuget": "Developer",
        "maven": "Developer",
        "gradle": "Developer",
        "jsfiddle": "Developer",
        "codesandbox": "Developer",
        "glitch": "Developer",
        "sourceforge": "Developer",
        "launchpad": "Developer",
        
        # Professional/Creator
        "medium": "Professional",
        "behance": "Professional",
        "dribbble": "Professional",
        "figma": "Professional",
        "notion": "Professional",
        "envato": "Professional",
        "creativemarket": "Professional",
        "artstation": "Professional",
        "coroflot": "Professional",
        
        # Forums/Community
        "discord": "Messaging",
        "telegram": "Messaging",
        "signal": "Messaging",
        "keybase": "Messaging",
        "slack": "Messaging",
        "xda": "Forum",
        "mybb": "Forum",
        "biotechnologyforums": "Forum",
        "nattyornot": "Forum",
        "blackworldforum": "Forum",
        "bluegrassrivals": "Forum",
        "cpaelites": "Forum",
        "cpahero": "Forum",
        "cracked_to": "Forum",
        "demonforums": "Forum",
        "biosmods": "Forum",
        
        # E-Commerce/Shopping
        "amazon": "E-Commerce",
        "ebay": "E-Commerce",
        "etsy": "E-Commerce",
        "shopify": "E-Commerce",
        "alibaba": "E-Commerce",
        "aliexpress": "E-Commerce",
        "flipkart": "E-Commerce",
        "snapdeal": "E-Commerce",
        "rakuten": "E-Commerce",
        "newegg": "E-Commerce",
        "bestbuy": "E-Commerce",
        "target": "E-Commerce",
        "walmart": "E-Commerce",
        "wayfair": "E-Commerce",
        
        # Gaming
        "steam": "Gaming",
        "epicgames": "Gaming",
        "origin": "Gaming",
        "uplay": "Gaming",
        "battle": "Gaming",
        "roblox": "Gaming",
        "minecraft": "Gaming",
        "twitch": "Gaming",
        
        # Learning/Education
        "coursera": "Learning",
        "udemy": "Learning",
        "edx": "Learning",
        "khanacademy": "Learning",
        "duolingo": "Learning",
        "codecademy": "Learning",
        "khan": "Learning",
        "vedantu": "Learning",
        
        # Productivity
        "trello": "Productivity",
        "asana": "Productivity",
        "monday": "Productivity",
        "clickup": "Productivity",
        "evernote": "Productivity",
        "anydo": "Productivity",
        
        # Content/Video
        "youtube": "Video",
        "vimeo": "Video",
        "dailymotion": "Video",
        "twitch": "Video",
        
        # Music/Audio
        "spotify": "Music",
        "soundcloud": "Music",
        "bandcamp": "Music",
        "lastfm": "Music",
        "pandora": "Music",
        "deezer": "Music",
        "blip": "Music",
        
        # Dating/Adult (High Risk)
        "badoo": "Dating/Adult",
        "tinder": "Dating/Adult",
        "okcupid": "Dating/Adult",
        "match": "Dating/Adult",
        "plentyoffish": "Dating/Adult",
        "adultfriendfinder": "Dating/Adult",
        "babeshows": "Dating/Adult",
        
        # Financial
        "paypal": "Financial",
        "venmo": "Financial",
        "cashapp": "Financial",
        
        # Photography
        "unsplash": "Photography",
        "pexels": "Photography",
        "pixabay": "Photography",
        "500px": "Photography",
        
        # News/Content
        "medium": "Publishing",
        "substack": "Publishing",
        "ghost": "Publishing",
        "wordpress": "Publishing",
    }
    
    # Default categories for unknown platforms
    DEFAULT_CATEGORIES = {
        "social": "Social Media",
        "dev": "Developer",
        "developer": "Developer",
        "shop": "E-Commerce",
        "shopping": "E-Commerce",
        "music": "Music",
        "video": "Video",
        "forum": "Forum",
        "messaging": "Messaging",
        "learning": "Learning",
        "productivity": "Productivity",
        "adult": "Dating/Adult",
        "dating": "Dating/Adult",
    }
    
    def __init__(self, timeout: int = 120):
        """
        Initialize the user-scanner service.
        
        Args:
            timeout: Maximum execution time in seconds
        """
        self.timeout = timeout
        self._check_installation()
    
    def _check_installation(self) -> bool:
        """Check if user-scanner is installed and disable its interactive update prompt."""
        try:
            result = subprocess.run(
                [sys.executable, "-m", "user_scanner", "--help"],
                capture_output=True,
                text=True,
                timeout=5,
                shell=False
            )
            installed = result.returncode in (0, 255)
            if installed:
                self._disable_auto_update()
            return installed
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning("user-scanner not found. Please install with: pip install user-scanner")
            return False

    def _disable_auto_update(self) -> None:
        """Disable user-scanner's interactive update prompt so it never blocks stdin."""
        try:
            import importlib.util, json as _json
            spec = importlib.util.find_spec("user_scanner")
            if spec and spec.origin:
                cfg = os.path.join(os.path.dirname(spec.origin), "config.json")
                with open(cfg, "r", encoding="utf-8") as f:
                    data = _json.load(f)
                if data.get("auto_update_status") or data.get("auto_hudson_prompt"):
                    data["auto_update_status"] = False
                    data["auto_hudson_prompt"] = False
                    with open(cfg, "w", encoding="utf-8") as f:
                        _json.dump(data, f, indent=2)
        except Exception as e:
            logger.debug(f"Could not patch user_scanner config: {e}")
    
    def _validate_email(self, email: str) -> bool:
        """Validate email format."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email)) and len(email) <= 254
    
    def _validate_username(self, username: str) -> bool:
        """Validate username format."""
        # Allow alphanumeric, dots, hyphens, underscores
        pattern = r'^[a-zA-Z0-9._-]+$'
        return bool(re.match(pattern, username)) and 1 <= len(username) <= 50
    
    def _sanitize_input(self, value: str) -> str:
        """Sanitize input to prevent command injection."""
        # Remove any shell metacharacters
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '{', '}', '<', '>', '\\', '\n', '\r']
        sanitized = value
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        return sanitized.strip()
    
    def _get_category(self, site_name: str, category_hint: Optional[str] = None) -> str:
        """Determine category for a platform."""
        site_lower = site_name.lower()
        
        # Direct mapping
        if site_lower in self.CATEGORY_MAP:
            return self.CATEGORY_MAP[site_lower]
        
        # Partial matching
        for key, category in self.CATEGORY_MAP.items():
            if key in site_lower or site_lower in key:
                return category
        
        # Category hint fallback
        if category_hint:
            hint_lower = category_hint.lower()
            if hint_lower in self.DEFAULT_CATEGORIES:
                return self.DEFAULT_CATEGORIES[hint_lower]
        
        return "Other"
    
    def _parse_console_output(self, output: str, scan_type: str) -> List[PlatformResult]:
        """
        Parse user-scanner console output into structured results.
        
        Expected formats:
        - Verbose: [✔] SiteName [URL] (query): Status
        - Simple: SiteName: Status
        """
        results = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Skip header/footer lines
            if any(skip in line.lower() for skip in ['scanning', 'completed', 'error', 'starting', 'total']):
                continue
            
            try:
                # Parse verbose format: [✔] SiteName [URL] (query): Status
                verbose_match = re.match(
                    r'\[([✔✓x✗])\]\s+(\w+)\s+\[([^\]]+)\]\s+\(([^)]+)\):\s*(.+)',
                    line
                )
                
                if verbose_match:
                    indicator, site_name, url, query, status = verbose_match.groups()
                    found = status.strip().lower() in ['registered', 'found', '✔', '✓']
                    
                    result = PlatformResult(
                        platform=site_name,
                        site_name=site_name,
                        found=found,
                        url=url.strip(),
                        category=self._get_category(site_name),
                        status=status.strip(),
                        confidence="High" if found else "Low"
                    )
                    results.append(result)
                    continue
                
                # Parse simple format: SiteName: Status
                simple_match = re.match(r'^(\w+)\s*:\s*(.+)$', line)
                if simple_match:
                    site_name, status = simple_match.groups()
                    found = status.strip().lower() in ['registered', 'found', '✔', '✓']
                    
                    result = PlatformResult(
                        platform=site_name,
                        site_name=site_name,
                        found=found,
                        url=f"https://{site_name.lower()}.com",
                        category=self._get_category(site_name),
                        status=status.strip(),
                        confidence="Medium" if found else "Low"
                    )
                    results.append(result)
                    
            except Exception as e:
                logger.warning(f"Failed to parse line: {line}. Error: {e}")
                continue
        
        return results
    
    def _run_scan(
        self, 
        scan_type: str, 
        value: str, 
        verbose: bool = True
    ) -> ScanResult:
        """
        Execute user-scanner subprocess securely.
        
        Args:
            scan_type: "email" or "username"
            value: The email or username to scan
            verbose: Enable verbose output for URL capture
            
        Returns:
            ScanResult with parsed and structured data
        """
        start_time = datetime.now()
        
        # Build command — use sys.executable so the venv's user_scanner is always found
        cmd = [sys.executable, "-m", "user_scanner"]

        if scan_type == "email":
            cmd.extend(["-e", value])
        else:
            cmd.extend(["-u", value])

        cmd.extend(["-s", "1"])  # no permutations — scan exact target only

        if verbose:
            cmd.append("-v")
        
        logger.info(f"Executing user-scanner: {' '.join(cmd)}")
        
        try:
            # Execute with secure parameters
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                shell=False,  # CRITICAL: Never use shell=True
                encoding='utf-8',
                errors='replace'
            )
            
            duration = (datetime.now() - start_time).total_seconds()
            output = result.stdout + "\n" + result.stderr
            
            # Check for installation errors
            if "not found" in output.lower() or "not recognized" in output.lower():
                return ScanResult(
                    query=value,
                    scan_type=scan_type,
                    platforms_found=0,
                    platforms_checked=0,
                    results=[],
                    timestamp=start_time.isoformat(),
                    scan_duration=duration,
                    status="error",
                    error_message="user-scanner not installed. Run: pip install user-scanner"
                )
            
            # Parse results
            parsed_results = self._parse_console_output(output, scan_type)
            
            # Calculate metrics
            found_count = sum(1 for r in parsed_results if r.found)
            
            return ScanResult(
                query=value,
                scan_type=scan_type,
                platforms_found=found_count,
                platforms_checked=len(parsed_results),
                results=parsed_results,
                timestamp=start_time.isoformat(),
                scan_duration=duration,
                status="success"
            )
            
        except subprocess.TimeoutExpired:
            duration = (datetime.now() - start_time).total_seconds()
            logger.error(f"user-scanner timed out after {self.timeout}s")
            return ScanResult(
                query=value,
                scan_type=scan_type,
                platforms_found=0,
                platforms_checked=0,
                results=[],
                timestamp=start_time.isoformat(),
                scan_duration=duration,
                status="timeout",
                error_message=f"Scan timed out after {self.timeout} seconds"
            )
            
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            logger.error(f"user-scanner execution failed: {e}")
            return ScanResult(
                query=value,
                scan_type=scan_type,
                platforms_found=0,
                platforms_checked=0,
                results=[],
                timestamp=start_time.isoformat(),
                scan_duration=duration,
                status="error",
                error_message=str(e)
            )
    
    def scan_email(self, email: str) -> ScanResult:
        """
        Scan an email address across all platforms.
        
        Args:
            email: The email address to scan
            
        Returns:
            ScanResult with all platform findings
        """
        # Validate
        email = self._sanitize_input(email)
        if not self._validate_email(email):
            return ScanResult(
                query=email,
                scan_type="email",
                platforms_found=0,
                platforms_checked=0,
                results=[],
                timestamp=datetime.now().isoformat(),
                scan_duration=0,
                status="invalid",
                error_message="Invalid email format"
            )
        
        return self._run_scan("email", email)
    
    def scan_username(self, username: str) -> ScanResult:
        """
        Scan a username across all platforms.
        
        Args:
            username: The username to scan
            
        Returns:
            ScanResult with all platform findings
        """
        # Validate
        username = self._sanitize_input(username)
        if not self._validate_username(username):
            return ScanResult(
                query=username,
                scan_type="username",
                platforms_found=0,
                platforms_checked=0,
                results=[],
                timestamp=datetime.now().isoformat(),
                scan_duration=0,
                status="invalid",
                error_message="Invalid username format"
            )
        
        return self._run_scan("username", username)
    
    def scan_streaming(self, scan_type: str, value: str):
        """
        Scan with streaming results - yields each result as it's found.
        
        Args:
            scan_type: "email" or "username"
            value: The email or username to scan
            
        Yields:
            Dict with result info for each platform check
        """
        start_time = datetime.now()
        value = self._sanitize_input(value)
        
        # Validate
        if scan_type == "email" and not self._validate_email(value):
            yield {"type": "error", "message": "Invalid email format"}
            return
        if scan_type == "username" and not self._validate_username(value):
            yield {"type": "error", "message": "Invalid username format"}
            return
        
        # Build command — use sys.executable so the venv's user_scanner is always found
        cmd = [sys.executable, "-m", "user_scanner"]
        if scan_type == "email":
            cmd.extend(["-e", value])
        else:
            cmd.extend(["-u", value])
        cmd.extend(["-s", "1", "-v"])  # exact target only, verbose for URLs
        
        logger.info(f"Starting streaming scan: {' '.join(cmd)}")
        
        # Set environment to disable colors and fix encoding on Windows
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        env['PYTHONUTF8'] = '1'
        env['NO_COLOR'] = '1'
        env['FORCE_COLOR'] = '0'
        env['COLORAMA_INIT'] = 'False'

        try:
            # Start process with streaming output
            # stdin=DEVNULL prevents the update-check prompt from blocking
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                shell=False,
                encoding='utf-8',
                errors='replace',
                bufsize=1,
                universal_newlines=True,
                env=env
            )
            
            found_count = 0
            checked_count = 0
            
            # Stream output line by line
            for line in iter(process.stdout.readline, ''):
                line = _ANSI_RE.sub('', line).strip()  # strip ANSI color codes first
                if not line:
                    continue
                
                logger.debug(f"Raw line: {line[:100]}")
                
                # Parse the line for results
                result = self._parse_streaming_line(line, scan_type)
                if result:
                    checked_count += 1
                    if result.get('found'):
                        found_count += 1
                    
                    logger.info(f"Found result: {result['platform']} - Found: {result['found']}")
                    
                    yield {
                        "type": "result",
                        "data": result,
                        "found_count": found_count,
                        "checked_count": checked_count,
                        "elapsed": (datetime.now() - start_time).total_seconds()
                    }
                else:
                    # Yield progress updates for non-result lines
                    if 'checking' in line.lower() or 'scanning' in line.lower():
                        yield {
                            "type": "progress",
                            "message": line,
                            "found_count": found_count,
                            "checked_count": checked_count
                        }
            
            # Wait for process to complete with extended timeout (3 minutes for 195 platforms)
            process.wait(timeout=180)
            
            # Send completion
            duration = (datetime.now() - start_time).total_seconds()
            yield {
                "type": "complete",
                "found_count": found_count,
                "checked_count": checked_count,
                "duration": duration
            }
            
        except subprocess.TimeoutExpired:
            process.kill()
            yield {"type": "error", "message": "Scan timeout - partial results shown"}
        except Exception as e:
            logger.error(f"Streaming scan error: {e}")
            yield {"type": "error", "message": str(e)}
    
    def _parse_streaming_line(self, line: str, scan_type: str) -> Optional[Dict]:
        """Parse a single line from streaming output."""
        try:
            # Skip error messages and non-platform lines
            error_keywords = ['error', 'exception', 'traceback', 'failed']
            line_lower = line.lower()
            if any(kw in line_lower for kw in error_keywords):
                return None
            
            # Skip lines that don't look like platform results
            # user-scanner uses [✔] and [✘] for found/not found
            if not re.match(r'^(\[.?\]|\w+\s*\[)', line):
                return None
            
            # Pattern 1: [✔] SiteName [URL] (query): Status
            # This matches: [✔] Stremio [https://stremio.com] (test@gmail.com): Registered
            found_match = re.match(
                r'^\[[^\]]*\]\s+([A-Za-z0-9._-]+)\s+\[(https?://[^\]]+)\]\s*\([^)]+\):\s*(.+)$', 
                line
            )
            if found_match:
                site_name, url, status = found_match.groups()
                if any(kw in site_name.lower() for kw in error_keywords):
                    return None
                
                is_found = status.strip().lower() in ['registered', 'found', 'exists', 'valid', 'taken', 'yes']
                return {
                    "platform": site_name,
                    "site_name": site_name,
                    "found": is_found,
                    "url": url.strip(),
                    "category": self._get_category(site_name),
                    "status": status.strip(),
                    "confidence": "High"
                }
            
            # Pattern 2: Try alternate format without brackets around checkmark
            alt_match = re.match(
                r'^([✔✘])?\s*([A-Za-z0-9._-]+)\s+\[(https?://[^\]]+)\]\s*\([^)]+\):\s*(.+)$', 
                line
            )
            if alt_match:
                checkmark, site_name, url, status = alt_match.groups()
                if any(kw in site_name.lower() for kw in error_keywords):
                    return None
                
                is_found = checkmark == '✔' or status.strip().lower() in ['registered', 'found', 'exists', 'valid', 'taken', 'yes']
                return {
                    "platform": site_name,
                    "site_name": site_name,
                    "found": is_found,
                    "url": url.strip(),
                    "category": self._get_category(site_name),
                    "status": status.strip(),
                    "confidence": "High"
                }
            
        except Exception:
            pass
        return None
    
    def get_platform_categories(self, results: List[PlatformResult]) -> Dict[str, List[PlatformResult]]:
        """Group results by category for organized display."""
        categories = {}
        for result in results:
            cat = result.category
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(result)
        
        # Sort categories by priority
        priority = [
            "Social Media", "Developer", "Messaging", 
            "Professional", "E-Commerce", "Gaming",
            "Video", "Music", "Forum", "Learning",
            "Productivity", "Photography", "Dating/Adult", "Other"
        ]
        
        sorted_categories = {}
        for p in priority:
            if p in categories:
                sorted_categories[p] = categories[p]
        
        # Add any remaining categories
        for cat, items in categories.items():
            if cat not in sorted_categories:
                sorted_categories[cat] = items
        
        return sorted_categories


# Singleton instance
_scanner_service = None

def get_scanner_service() -> UserScannerService:
    """Get or create the scanner service singleton."""
    global _scanner_service
    if _scanner_service is None:
        _scanner_service = UserScannerService()
    return _scanner_service
