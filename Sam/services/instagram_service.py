"""
Instagram Private Account Sniffer Service
Mirrors the logic of Instagram Sniffer (github.com/obitouka/Instagram Sniffer)

API Endpoint: GET https://www.instagram.com/api/v1/users/web_profile_info/?username={username}
Required Header: X-IG-App-ID: 936619743392459

Uses curl_cffi for TLS fingerprinting to avoid Instagram bot-detection.
Falls back to httpx if curl_cffi is unavailable.
"""

import re

_IG_APP_ID  = "936619743392459"
_IG_API_URL = "https://www.instagram.com/api/v1/users/web_profile_info/"
_IG_HEADERS = {
    "X-IG-App-ID": _IG_APP_ID,
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://www.instagram.com/",
}
_USERNAME_RE = re.compile(r'^[a-zA-Z0-9._]{1,30}$')


def run_instagram_sniffer(username: str) -> dict:
    """
    Fetches Instagram profile data for a given username.
    Returns a structured dict with profile metadata and collaborated post intelligence.

    Mirrors accountDataFetcher.py from Instagram Sniffer:
      - Makes GET request to Instagram's web profile API
      - Extracts profile metadata (is_private, full_name, followers, etc.)
      - Extracts timeline posts and their tagged collaborators
      - Collaborated posts from private accounts are exposed via
        edge_media_to_tagged_user — this is the core OSINT insight

    Args:
        username: Instagram username (without @, max 30 chars, [a-zA-Z0-9._])

    Returns:
        dict with keys: profile, posts, total_posts_fetched,
                        posts_with_collaborators
        or: {"error": "..."}
    """
    username = username.strip().lstrip('@')
    if not _USERNAME_RE.match(username):
        return {"error": "Invalid Instagram username. Use only letters, numbers, dots and underscores (max 30 chars)."}

    try:
        data = _fetch_profile(username)
    except Exception as exc:
        return {"error": f"Request failed: {exc}"}

    if "error" in data:
        return data

    user = data.get("data", {}).get("user")
    if not user:
        return {"error": f"User '{username}' not found on Instagram or account does not exist."}

    profile = _extract_profile(user, username)
    posts   = _extract_posts(user, username)

    return {
        "profile": profile,
        "posts":   posts,
        "total_posts_fetched":       len(posts),
        "posts_with_collaborators":  sum(1 for p in posts if p["collaborators"]),
        "all_collaborators":         _dedupe_collaborators(posts),
    }


def _fetch_profile(username: str) -> dict:
    """Makes the HTTP request to Instagram's web profile API."""
    try:
        from curl_cffi.requests import Session
        with Session(impersonate="chrome120") as s:
            resp = s.get(
                _IG_API_URL,
                params={"username": username},
                headers=_IG_HEADERS,
                timeout=20,
            )
    except ImportError:
        import httpx
        with httpx.Client(timeout=20, follow_redirects=True) as client:
            resp = client.get(
                _IG_API_URL,
                params={"username": username},
                headers=_IG_HEADERS,
            )

    if resp.status_code == 404:
        return {"error": f"User '{username}' not found on Instagram."}
    if resp.status_code == 429:
        return {"error": "Instagram rate limit reached. Please wait a few minutes before scanning again."}
    if resp.status_code == 401:
        return {"error": "Instagram access denied (HTTP 401). The App ID may need updating."}
    if resp.status_code != 200:
        return {"error": f"Instagram API returned HTTP {resp.status_code}. Try again later."}

    try:
        return resp.json()
    except Exception:
        return {"error": "Failed to parse Instagram API response."}


def _extract_profile(user: dict, username: str) -> dict:
    """Extracts core profile metadata from the Instagram API user object."""
    return {
        "username":        user.get("username", username),
        "full_name":       user.get("full_name", ""),
        "is_private":      user.get("is_private", False),
        "is_verified":     user.get("is_verified", False),
        "biography":       user.get("biography", ""),
        "followers":       user.get("edge_followed_by", {}).get("count"),
        "following":       user.get("edge_follow", {}).get("count"),
        "posts_count":     user.get("edge_owner_to_timeline_media", {}).get("count"),
        "profile_pic_url": user.get("profile_pic_url_hd") or user.get("profile_pic_url", ""),
        "external_url":    user.get("external_url", ""),
        "category":        user.get("category_name", ""),
        "id":              user.get("id", ""),
        "profile_url":     f"https://www.instagram.com/{user.get('username', username)}/",
    }


def _extract_posts(user: dict, owner_username: str) -> list:
    """
    Extracts timeline posts and their collaborators.

    The OSINT insight: Instagram's edge_media_to_tagged_user field reveals
    accounts that collaborated on public posts. If a private account is
    tagged as a collaborator on a public post, its username becomes visible
    even though the profile itself is private.
    """
    posts  = []
    edges  = user.get("edge_owner_to_timeline_media", {}).get("edges", [])

    for edge in edges:
        node      = edge.get("node", {})
        shortcode = node.get("shortcode", "")
        is_video  = node.get("is_video", False)
        owner     = node.get("owner", {}).get("username", owner_username)
        post_type = "reel" if is_video else "p"

        collaborators = []
        for collab_edge in node.get("edge_media_to_tagged_user", {}).get("edges", []):
            collab_user = collab_edge.get("node", {}).get("user", {})
            collab_name = collab_user.get("username", "")
            if collab_name:
                collaborators.append({
                    "username":    collab_name,
                    "profile_url": f"https://www.instagram.com/{collab_name}/",
                    "is_private":  collab_user.get("is_private", False),
                    "is_verified": collab_user.get("is_verified", False),
                    "full_name":   collab_user.get("full_name", ""),
                    "profile_pic": collab_user.get("profile_pic_url", ""),
                })

        posts.append({
            "shortcode":     shortcode,
            "type":          "video" if is_video else "image",
            "url":           f"https://www.instagram.com/{owner}/{post_type}/{shortcode}/",
            "owner":         owner,
            "collaborators": collaborators,
            "thumbnail":     node.get("thumbnail_src") or node.get("display_url", ""),
            "timestamp":     node.get("taken_at_timestamp"),
            "likes":         node.get("edge_liked_by", {}).get("count"),
            "comments":      node.get("edge_media_to_comment", {}).get("count"),
        })

    return posts


def _dedupe_collaborators(posts: list) -> list:
    """Returns a deduplicated flat list of all collaborators across all posts."""
    seen   = set()
    result = []
    for post in posts:
        for collab in post.get("collaborators", []):
            uname = collab["username"]
            if uname not in seen:
                seen.add(uname)
                result.append(collab)
    return result
