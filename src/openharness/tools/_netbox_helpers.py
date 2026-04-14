"""Netbox IP ownership lookup helper.

Queries Netbox for IP-to-owner mappings. Used by the netbox_lookup_ip tool
to enrich SOC alert context with asset ownership information.

The lookup follows the same pattern as the existing netbox.py integration:
1. Query the exact IP first (ipam.ip_addresses)
2. Fall back to the containing /24 subnet description (ipam.prefixes)

No Redis caching — the SOC agent processes one alert at a time in fresh
conversations, so cross-session caching adds complexity without payoff.
An in-memory cache for the duration of one agent run is sufficient (the
same IP may appear as both source and destination).

Required env vars:
    NETBOX_API_URL     — Netbox base URL (e.g. https://10.121.56.31)
    NETBOX_API_TOKEN   — API token (read-only is sufficient)

Optional env vars:
    NETBOX_VERIFY_SSL  — verify TLS cert (default "false")

Fail-open: if Netbox is unconfigured, unreachable, or returns an error,
the lookup returns None. Alert processing is never blocked by Netbox.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

# In-memory cache for the duration of one agent run. Keyed by IP string.
_ip_cache: dict[str, dict[str, str] | None] = {}
_subnet_cache: dict[str, str | None] = {}


def get_netbox_config() -> dict[str, Any] | None:
    """Read Netbox connection config from environment.

    Returns None (not raises) if unconfigured — Netbox is fail-open.
    """
    url = os.environ.get("NETBOX_API_URL", "").strip()
    token = os.environ.get("NETBOX_API_TOKEN", "").strip()
    if not url or not token:
        return None
    verify_ssl = os.environ.get("NETBOX_VERIFY_SSL", "false").lower() in (
        "true", "1", "yes",
    )
    return {"url": url, "token": token, "verify_ssl": verify_ssl}


def lookup_ip(ip: str) -> dict[str, str] | None:
    """Look up an IP in Netbox. Returns a dict with ownership info or None.

    Return shape (when found):
        {
            "ip": "10.125.68.82",
            "description": "BIS Web Server - cloud-ops",
            "source": "exact" | "subnet",
        }

    Fail-open: returns None on any error, unconfigured Netbox, or not-found.
    """
    # Check in-memory cache first
    if ip in _ip_cache:
        return _ip_cache[ip]

    config = get_netbox_config()
    if config is None:
        return None

    try:
        import pynetbox
        import requests

        api = pynetbox.api(url=config["url"], token=config["token"])
        if not config["verify_ssl"]:
            session = requests.Session()
            session.verify = False
            api.http_session = session

        # 1. Query exact IP
        result = _lookup_exact_ip(api, ip)
        if result is not None:
            _ip_cache[ip] = result
            return result

        # 2. Fall back to /24 subnet description
        result = _lookup_subnet(api, ip)
        _ip_cache[ip] = result
        return result

    except Exception as exc:
        logger.warning(f"Netbox lookup failed for {ip}: {exc}")
        _ip_cache[ip] = None
        return None


def _lookup_exact_ip(api: Any, ip: str) -> dict[str, str] | None:
    """Query Netbox for an exact IP address match."""
    try:
        ip_obj = api.ipam.ip_addresses.get(address=ip)
        if ip_obj and ip_obj.description:
            return {
                "ip": ip,
                "description": str(ip_obj.description),
                "source": "exact",
            }
    except Exception as exc:
        logger.debug(f"Netbox exact IP lookup failed for {ip}: {exc}")
    return None


def _lookup_subnet(api: Any, ip: str) -> dict[str, str] | None:
    """Fall back to the containing /24 subnet description."""
    try:
        network = ipaddress.ip_network(f"{ip}/24", strict=False)
        subnet_key = str(network)
    except ValueError:
        return None

    # Check subnet cache
    if subnet_key in _subnet_cache:
        desc = _subnet_cache[subnet_key]
        if desc is None:
            return None
        return {"ip": ip, "description": desc, "source": "subnet"}

    try:
        prefixes = api.ipam.prefixes.filter(q=subnet_key)
        prefix_list = list(prefixes)
        if prefix_list:
            # Pick the most specific (deepest) prefix, same logic as existing
            # netbox.py integration
            count = len(prefix_list)
            for prefix in prefix_list:
                if getattr(prefix, '_depth', 0) == (count - 1):
                    desc = str(prefix.description) if prefix.description else None
                    _subnet_cache[subnet_key] = desc
                    if desc:
                        return {"ip": ip, "description": desc, "source": "subnet"}
                    return None
            # If depth logic didn't match, take the last one
            last = prefix_list[-1]
            desc = str(last.description) if last.description else None
            _subnet_cache[subnet_key] = desc
            if desc:
                return {"ip": ip, "description": desc, "source": "subnet"}

        _subnet_cache[subnet_key] = None
        return None

    except Exception as exc:
        logger.debug(f"Netbox subnet lookup failed for {subnet_key}: {exc}")
        _subnet_cache[subnet_key] = None
        return None


def clear_cache() -> None:
    """Clear the in-memory lookup caches. Called between agent runs if needed."""
    _ip_cache.clear()
    _subnet_cache.clear()
