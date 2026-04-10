import socket
import ssl
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple


@dataclass
class CertificateDetails:
    issuer: str
    sans: List[str]
    not_after: str
    days_remaining: Optional[int]
    hostname_valid: bool
    hostname_error: Optional[str]
    chain_ok: bool
    chain_verdict: str
    chain_error: Optional[str]


def inspect_certificate(hostname: str, timeout: float = 5.0) -> CertificateDetails:
    cert = _fetch_peer_certificate(hostname=hostname, timeout=timeout)
    issuer = _flatten_name(cert.get("issuer", ()))
    sans = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]

    not_after_raw = cert.get("notAfter", "")
    not_after_dt = _parse_not_after(not_after_raw)
    days_remaining = None
    if not_after_dt is not None:
        days_remaining = (not_after_dt - datetime.now(timezone.utc)).days

    hostname_valid, hostname_error = _validate_hostname(cert, hostname)
    chain_ok, chain_error = _validate_chain(hostname=hostname, timeout=timeout)

    if chain_ok:
        chain_verdict = "trusted"
    else:
        chain_verdict = "untrusted"

    return CertificateDetails(
        issuer=issuer or "-",
        sans=sans,
        not_after=not_after_dt.isoformat() if not_after_dt is not None else not_after_raw or "-",
        days_remaining=days_remaining,
        hostname_valid=hostname_valid,
        hostname_error=hostname_error,
        chain_ok=chain_ok,
        chain_verdict=chain_verdict,
        chain_error=chain_error,
    )


def _fetch_peer_certificate(hostname: str, timeout: float) -> Dict[str, object]:
    context = ssl._create_unverified_context()
    context.check_hostname = False

    with socket.create_connection((hostname, 443), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            der_bytes = tls_sock.getpeercert(binary_form=True)

    if not der_bytes:
        raise ssl.SSLError("Peer certificate was not returned by the server")

    pem_data = ssl.DER_cert_to_PEM_cert(der_bytes)
    with tempfile.NamedTemporaryFile("w+", suffix=".pem") as handle:
        handle.write(pem_data)
        handle.flush()
        return ssl._ssl._test_decode_cert(handle.name)


def _validate_chain(hostname: str, timeout: float) -> Tuple[bool, Optional[str]]:
    context = ssl.create_default_context()
    context.check_hostname = False

    try:
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return True, None
    except ssl.SSLCertVerificationError as exc:
        return False, str(exc)


def _validate_hostname(cert: Dict[str, object], hostname: str) -> Tuple[bool, Optional[str]]:
    try:
        ssl.match_hostname(cert, hostname)
        return True, None
    except ssl.CertificateError as exc:
        return False, str(exc)


def _flatten_name(items: tuple) -> str:
    parts = []
    for entry in items:
        for key, value in entry:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _parse_not_after(value: str) -> Optional[datetime]:
    if not value:
        return None

    try:
        parsed = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None

    return parsed.replace(tzinfo=timezone.utc)
