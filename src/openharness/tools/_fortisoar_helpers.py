"""FortiSOAR REST API client with HMAC (CS) authentication.

FortiSOAR uses a custom HMAC scheme where:
    - The "public key" is an identifier string stored in a file
    - The "private key" is the HMAC secret stored in another file
    - Each request is signed by computing:
        raw = "sha256.METHOD.TIMESTAMP.FULL_URL.sha256(payload)"
        sig = HMAC-SHA256(private_key, raw)
        header = base64("sha256;timestamp;public_key;sig")
        Authorization: CS <header>
    - For GET requests, the payload used in the hash is the public_key itself
      (this is FortiSOAR's convention, not a typo)

Required env vars:
    FORTISOAR_URL                  — base URL (e.g. https://fortisoar.example.com, no trailing slash)
    FORTISOAR_PUBLIC_KEY_FILE      — path to public key file
    FORTISOAR_PRIVATE_KEY_FILE     — path to private key file

Required for multi-tenant FortiSOAR:
    FORTISOAR_TENANT               — tenant name. Queries are scoped to this tenant
                                     and get_alert rejects alerts from other tenants.
                                     This is REQUIRED — if unset, tools refuse to
                                     contact FortiSOAR to prevent accidental cross-tenant
                                     data access.
    FORTISOAR_SOURCE               — source-tool name (the alert.source field, e.g.
                                     'IS_FAZ_MIS_Cloud'). Queries are filtered to this
                                     source and get/resolve refuse alerts from other
                                     sources. REQUIRED for the same reason as TENANT:
                                     different alert sources need different SOC playbooks
                                     and we don't want the agent processing alerts from a
                                     source it hasn't been validated against.

Optional env vars:
    FORTISOAR_VERIFY_SSL           — verify TLS cert (default "false")
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from datetime import datetime, timezone
from typing import Any

import httpx

_ALGORITHM = "sha256"


def get_fsr_config() -> dict[str, Any]:
    """Resolve FortiSOAR connection config from environment variables."""
    url = os.environ.get("FORTISOAR_URL", "").strip()
    pub_file = os.environ.get("FORTISOAR_PUBLIC_KEY_FILE", "").strip()
    pri_file = os.environ.get("FORTISOAR_PRIVATE_KEY_FILE", "").strip()
    tenant = os.environ.get("FORTISOAR_TENANT", "").strip()
    source = os.environ.get("FORTISOAR_SOURCE", "").strip()

    missing = []
    if not url:
        missing.append("FORTISOAR_URL")
    if not pub_file:
        missing.append("FORTISOAR_PUBLIC_KEY_FILE")
    if not pri_file:
        missing.append("FORTISOAR_PRIVATE_KEY_FILE")
    if not tenant:
        missing.append("FORTISOAR_TENANT")
    if not source:
        missing.append("FORTISOAR_SOURCE")
    if missing:
        raise ValueError(
            f"FortiSOAR not configured. Set environment variables: {', '.join(missing)}. "
            f"FORTISOAR_TENANT and FORTISOAR_SOURCE are required to prevent the agent "
            f"from accidentally processing alerts outside its validated scope on shared "
            f"FortiSOAR instances."
        )

    try:
        public_key = _read_key_file(pub_file)
        private_key = _read_key_file(pri_file)
    except FileNotFoundError as exc:
        raise ValueError(f"FortiSOAR key file not found: {exc}") from exc

    verify_ssl = os.environ.get("FORTISOAR_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

    return {
        "url": url.rstrip("/"),
        "public_key": public_key,
        "private_key": private_key,
        "verify_ssl": verify_ssl,
        "tenant": tenant,
        "source": source,
    }


def _read_key_file(file_path: str) -> str:
    with open(file_path) as f:
        return f.read().strip()


def _generate_hmac_header(
    method: str,
    full_uri: str,
    payload: str,
    private_key: str,
    public_key: str,
) -> str:
    """Compute the FortiSOAR CS Authorization header.

    Matches the working implementation used by the existing BIS FortiSOAR client.
    Do not change this without verifying against a live FSR instance.
    """
    # For GET, FortiSOAR convention: payload hashed = public_key
    if method == "GET":
        payload = public_key

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    payload_bytes = payload.encode() if isinstance(payload, str) else payload

    digest = hashlib.new(_ALGORITHM)
    digest.update(payload_bytes)
    hashed_payload = digest.hexdigest()

    raw_fingerprint = f"{_ALGORITHM}.{method}.{timestamp}.{full_uri}.{hashed_payload}"

    signature = hmac.new(
        private_key.encode(),
        raw_fingerprint.encode(),
        hashlib.sha256,
    ).hexdigest()

    header_plain = f"{_ALGORITHM};{timestamp};{public_key};{signature}"
    header_b64 = base64.b64encode(header_plain.encode()).decode()
    return f"CS {header_b64}"


def _check_fsr_response(resp: httpx.Response, endpoint: str) -> None:
    """Translate FortiSOAR HTTP errors into RuntimeError with helpful messages."""
    if resp.status_code == 401:
        raise RuntimeError("FortiSOAR authentication failed (401). Check key files.")
    if resp.status_code == 403:
        raise RuntimeError("FortiSOAR access denied (403). User may lack permissions.")
    if resp.status_code == 404:
        raise RuntimeError(f"FortiSOAR endpoint not found (404): {endpoint}")
    if resp.status_code >= 400:
        raise RuntimeError(
            f"FortiSOAR returned {resp.status_code}: {resp.text[:300]}"
        )


async def fsr_get(config: dict[str, Any], endpoint: str) -> dict[str, Any]:
    """Perform an authenticated GET against a FortiSOAR endpoint.

    Args:
        config: Connection config from get_fsr_config()
        endpoint: API path including leading slash, e.g. "/api/3/alerts?$limit=10"

    Returns:
        Parsed JSON response.

    Raises:
        RuntimeError: On HTTP errors or JSON parse failures.
    """
    full_url = f"{config['url']}{endpoint}"
    auth = _generate_hmac_header(
        method="GET",
        full_uri=full_url,
        payload="",
        private_key=config["private_key"],
        public_key=config["public_key"],
    )
    headers = {"Authorization": auth}

    async with httpx.AsyncClient(verify=config["verify_ssl"], timeout=30.0) as client:
        try:
            resp = await client.get(full_url, headers=headers)
        except httpx.ConnectError as exc:
            raise RuntimeError(f"Cannot reach FortiSOAR at {config['url']}: {exc}") from exc
        except httpx.HTTPError as exc:
            raise RuntimeError(f"FortiSOAR HTTP error: {exc}") from exc

    _check_fsr_response(resp, endpoint)

    try:
        return resp.json()
    except ValueError as exc:
        raise RuntimeError(f"FortiSOAR returned invalid JSON: {exc}") from exc


async def fsr_put(
    config: dict[str, Any],
    endpoint: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Perform an authenticated PUT against a FortiSOAR endpoint.

    The HMAC signature must be computed over the exact JSON body that is sent.
    We serialise once with json.dumps using sort_keys=False, then both sign and
    transmit that exact byte string to avoid any mismatch.

    Args:
        config: Connection config from get_fsr_config()
        endpoint: API path including leading slash, e.g. "/api/3/alerts/<uuid>"
        payload: Dict to be JSON-encoded as the request body.

    Returns:
        Parsed JSON response from FortiSOAR.

    Raises:
        RuntimeError: On HTTP errors or JSON parse failures.
    """
    import json as _json

    full_url = f"{config['url']}{endpoint}"
    body = _json.dumps(payload)

    auth = _generate_hmac_header(
        method="PUT",
        full_uri=full_url,
        payload=body,
        private_key=config["private_key"],
        public_key=config["public_key"],
    )
    headers = {
        "Authorization": auth,
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(verify=config["verify_ssl"], timeout=30.0) as client:
        try:
            # Pass the pre-serialised body so the signature matches the bytes on the wire
            resp = await client.put(full_url, headers=headers, content=body)
        except httpx.ConnectError as exc:
            raise RuntimeError(f"Cannot reach FortiSOAR at {config['url']}: {exc}") from exc
        except httpx.HTTPError as exc:
            raise RuntimeError(f"FortiSOAR HTTP error: {exc}") from exc

    _check_fsr_response(resp, endpoint)

    try:
        return resp.json()
    except ValueError as exc:
        raise RuntimeError(f"FortiSOAR returned invalid JSON: {exc}") from exc
