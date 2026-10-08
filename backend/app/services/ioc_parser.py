import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit


SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
TLD = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$", re.IGNORECASE)
EMAIL_LOCAL = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$")
URL_PREFIX = re.compile(r"^https?://", re.IGNORECASE)


def _normalize_domain(value: str) -> str:
    domain = value.rstrip(".").lower()
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid domain name") from exc

    labels = domain.split(".")
    if (
        len(domain) > 253
        or len(labels) < 2
        or not TLD.fullmatch(labels[-1])
        or any(len(label) > 63 or not DOMAIN_LABEL.fullmatch(label) for label in labels)
    ):
        raise ValueError("Invalid domain name")
    return domain


def normalize_ioc(value: str) -> str:
    """Normalize equivalent IOC text before validation, lookup, and persistence."""
    value = value.strip()
    if not value:
        return value

    if URL_PREFIX.match(value):
        if any(character.isspace() for character in value):
            raise ValueError("Invalid URL")
        try:
            parsed = urlsplit(value)
            scheme = parsed.scheme.lower()
            hostname = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise ValueError("Invalid URL") from exc

        if scheme not in {"http", "https"} or not hostname or parsed.username or parsed.password:
            raise ValueError("Invalid URL")

        try:
            host = str(ipaddress.ip_address(hostname))
        except ValueError:
            host = _normalize_domain(hostname)

        if ":" in host:
            host = f"[{host}]"
        if port == (80 if scheme == "http" else 443):
            port = None
        netloc = f"{host}:{port}" if port is not None else host
        return urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    if SHA256.fullmatch(value) or SHA1.fullmatch(value) or MD5.fullmatch(value):
        return value.lower()

    if "@" in value:
        local, domain = value.rsplit("@", 1)
        if EMAIL_LOCAL.fullmatch(local):
            return f"{local}@{_normalize_domain(domain)}"

    try:
        return _normalize_domain(value)
    except ValueError:
        return value


def identify_ioc(value: str) -> str:
    value = normalize_ioc(value)
    try:
        ip = ipaddress.ip_address(value)
        return "ipv4" if ip.version == 4 else "ipv6"
    except ValueError:
        pass

    if SHA256.fullmatch(value):
        return "sha256"
    if SHA1.fullmatch(value):
        return "sha1"
    if MD5.fullmatch(value):
        return "md5"

    if URL_PREFIX.match(value):
        try:
            parsed = urlsplit(value)
            if parsed.hostname and parsed.scheme.lower() in {"http", "https"}:
                parsed.port  # Accessing the property validates the port syntax/range.
                return "url"
        except ValueError:
            pass
        raise ValueError("Invalid URL")

    if "@" in value:
        local, domain = value.rsplit("@", 1)
        if EMAIL_LOCAL.fullmatch(local):
            try:
                _normalize_domain(domain)
                return "email"
            except ValueError:
                pass
        raise ValueError("Invalid email address")

    try:
        _normalize_domain(value)
        return "domain"
    except ValueError as exc:
        raise ValueError("Unsupported IOC format") from exc
