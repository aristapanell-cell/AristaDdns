import re
import ipaddress
from urllib.parse import urlparse, urlunparse
from typing import List, Dict, Any


class Normalizer:

    @classmethod
    def normalize(
        cls,
        data: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        normalized = []

        for entry in data:
            normalized_entry = cls._normalize_entry(entry)

            if normalized_entry:
                normalized.append(normalized_entry)

        return normalized

    @classmethod
    def _normalize_entry(
        cls,
        entry: Dict[str, Any]
    ) -> Dict[str, Any]:

        normalized = {}

        for key, value in entry.items():

            if isinstance(value, str):
                value = value.strip()
                value = re.sub(r"\s+", " ", value)

                key_lower = key.lower()

                if key_lower == "doh_url" or key_lower.endswith("_url"):
                    value = cls._normalize_url(value)

                elif key_lower in (
                    "hostname",
                    "name",
                    "provider"
                ):
                    value = value.lower()

                elif key_lower in (
                    "address",
                    "ip"
                ):
                    value = cls._normalize_address(value)

                elif key_lower == "dot":
                    value = value.lower()

            normalized[key] = value

        cls._complete_from_url(normalized)
        cls._complete_from_hostname(normalized)
        cls._normalize_type(normalized)

        if not normalized.get("source"):
            normalized["source"] = "unknown"

        return normalized

    @classmethod
    def _complete_from_url(
        cls,
        entry: Dict[str, Any]
    ) -> None:

        doh_url = entry.get("doh_url")

        if not doh_url:
            return

        try:
            parsed = urlparse(doh_url)

            hostname = parsed.hostname

            if not hostname:
                return

            hostname = hostname.lower()

            if not entry.get("hostname"):
                entry["hostname"] = hostname

            if not entry.get("address"):
                entry["address"] = hostname

            if not entry.get("path"):
                entry["path"] = parsed.path or "/dns-query"

            if not entry.get("port"):
                entry["port"] = parsed.port or (
                    443 if parsed.scheme == "https" else 80
                )

        except ValueError:
            return

    @classmethod
    def _complete_from_hostname(
        cls,
        entry: Dict[str, Any]
    ) -> None:

        hostname = entry.get("hostname")

        if not hostname:
            return

        hostname = str(hostname).strip().lower()

        entry["hostname"] = hostname

        if not entry.get("address"):
            entry["address"] = hostname

    @classmethod
    def _normalize_url(
        cls,
        url: str
    ) -> str:

        try:
            parsed = urlparse(url.strip())

            if not parsed.scheme or not parsed.hostname:
                return url.strip()

            hostname = parsed.hostname.lower()

            if ":" in hostname:
                hostname = f"[{hostname}]"

            netloc = hostname

            if parsed.port:
                default_port = (
                    443
                    if parsed.scheme.lower() == "https"
                    else 80
                )

                if parsed.port != default_port:
                    netloc = f"{hostname}:{parsed.port}"

            path = parsed.path or "/dns-query"

            normalized = urlunparse((
                parsed.scheme.lower(),
                netloc,
                path.rstrip("/") if path != "/" else path,
                "",
                parsed.query,
                ""
            ))

            return normalized

        except (ValueError, TypeError):
            return url.strip()

    @classmethod
    def _normalize_address(
        cls,
        address: str
    ) -> str:

        address = address.strip()

        if not address:
            return address

        try:
            return str(ipaddress.ip_address(address))
        except ValueError:
            return address.lower()

    @classmethod
    def _normalize_type(
        cls,
        entry: Dict[str, Any]
    ) -> None:

        address = str(
            entry.get("address", "")
        ).strip()

        if address:
            try:
                ip = ipaddress.ip_address(address)
                entry["type"] = (
                    "IPv4"
                    if ip.version == 4
                    else "IPv6"
                )
                return
            except ValueError:
                pass

        if entry.get("doh_url"):
            entry["type"] = "DoH"
            return

        if entry.get("dot"):
            entry["type"] = "DoT"
            return

        if entry.get("hostname"):
            entry["type"] = "Hostname"

    @classmethod
    def validate(
        cls,
        data: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:

        validated = []

        for entry in data:
            if cls._is_valid(entry):
                validated.append(entry)

        return validated

    @classmethod
    def _is_valid(
        cls,
        entry: Dict[str, Any]
    ) -> bool:

        name = str(
            entry.get("name", "")
        ).strip()

        if not name:
            return False

        address = str(
            entry.get("address", "")
        ).strip()

        hostname = str(
            entry.get("hostname", "")
        ).strip()

        doh_url = str(
            entry.get("doh_url", "")
        ).strip()

        dot = str(
            entry.get("dot", "")
        ).strip()

        if not any((
            address,
            hostname,
            doh_url,
            dot
        )):
            return False

        if doh_url:
            try:
                parsed = urlparse(doh_url)

                if parsed.scheme not in (
                    "http",
                    "https"
                ):
                    return False

                if not parsed.hostname:
                    return False

            except (ValueError, TypeError):
                return False

        if address:
            try:
                ipaddress.ip_address(address)
            except ValueError:
                if not cls._is_valid_hostname(address):
                    return False

        if hostname and not cls._is_valid_hostname(hostname):
            try:
                ipaddress.ip_address(hostname)
            except ValueError:
                return False

        return True

    @classmethod
    def _is_valid_hostname(
        cls,
        hostname: str
    ) -> bool:

        hostname = hostname.strip().rstrip(".")

        if not hostname or len(hostname) > 253:
            return False

        labels = hostname.split(".")

        for label in labels:

            if not label:
                return False

            if len(label) > 63:
                return False

            if (
                label.startswith("-")
                or label.endswith("-")
            ):
                return False

            if not re.fullmatch(
                r"[A-Za-z0-9-]+",
                label
            ):
                return False

        return "." in hostname
