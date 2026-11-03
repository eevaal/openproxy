"""Build the TLS contexts for explicit, hostname-bound inspection."""

import ssl
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography import x509

from openproxy.rules.models import normalize_host

if TYPE_CHECKING:
    from openproxy.core.config import HTTPSInspectionConfig


class InspectionError(ValueError):
    """A configuration error without key material or local paths."""


def _file(value: str | None, label: str) -> Path:
    if value is None:
        raise InspectionError(f"{label} is required")
    path = Path(value)
    try:
        if path.is_file() and path.stat().st_size <= 1024 * 1024:
            return path
    except (OSError, ValueError):
        pass
    raise InspectionError(f"{label} must be a readable PEM file up to 1 MiB")


def build_contexts(
    settings: "HTTPSInspectionConfig",
) -> tuple[dict[str, ssl.SSLContext], ssl.SSLContext]:
    certificate = _file(settings.certificate_file, "Certificate")
    key = _file(settings.private_key_file, "Private key")
    try:
        if key.stat().st_mode & 0o077:
            raise InspectionError(
                "Private key must not be accessible to group or others"
            )
        leaf = x509.load_pem_x509_certificates(certificate.read_bytes())[0]
        now = datetime.now(UTC)
        if not leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc:
            raise InspectionError("Certificate is outside its validity period")
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = {
            name.lower() for name in san.value.get_values_for_type(x509.DNSName)
        }
        if not set(settings.hosts) <= dns_names:
            raise InspectionError(
                "Certificate needs an exact DNS SAN for each inspection host"
            )
        try:
            if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise InspectionError(
                    "Inspection requires a leaf certificate, not a CA"
                )
        except x509.ExtensionNotFound:
            pass
    except InspectionError:
        raise
    except (OSError, ValueError, x509.ExtensionNotFound, x509.DuplicateExtension):
        raise InspectionError("Cannot read certificate or its DNS SAN") from None

    contexts = {}
    for host in settings.hosts:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(["http/1.1"])
        try:
            # Explicit empty password prevents an interactive OpenSSL prompt.
            context.load_cert_chain(certificate, key, password=b"")
        except (OSError, ValueError):
            raise InspectionError(
                "Cannot load matching certificate and private key"
            ) from None
        context.sni_callback = _require_sni(host)
        contexts[host] = context

    # Construct directly so SSLKEYLOGFILE cannot enable TLS secret logging.
    upstream = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    upstream.minimum_version = ssl.TLSVersion.TLSv1_2
    upstream.hostname_checks_common_name = False
    upstream.set_alpn_protocols(["http/1.1"])
    try:
        upstream.load_default_certs()
        if settings.upstream_ca_file is not None:
            upstream.load_verify_locations(
                _file(settings.upstream_ca_file, "Upstream CA")
            )
    except (OSError, ValueError):
        raise InspectionError("Cannot load upstream trust certificates") from None
    return contexts, upstream


def _require_sni(
    expected: str,
) -> Callable[[ssl.SSLSocket | ssl.SSLObject, str | None, ssl.SSLContext], int | None]:
    def check(
        socket: ssl.SSLSocket | ssl.SSLObject,
        name: str | None,
        context: ssl.SSLContext,
    ) -> int | None:
        try:
            if name and normalize_host(name) == expected:
                return None
        except ValueError:
            pass
        return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME

    return check
