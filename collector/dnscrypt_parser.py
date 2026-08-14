import requests
import base64
import re
import ipaddress
import os
from typing import List, Dict, Any, Optional, Tuple


class DNSCryptParser:
    SOURCE_NAME = "dnscrypt"

    PROTOCOLS = {
        0x00: "DNS",
        0x01: "DNSCrypt",
        0x02: "DoH",
        0x03: "DoT",
        0x04: "DoQ",
        0x05: "ObliviousDoH",
        0x81: "DNSCryptRelay",
        0x85: "ObliviousDoHRelay"
    }

    @classmethod
    def fetch(cls) -> List[Dict[str, Any]]:
        try:
            source_url = os.environ.get("DNSCRYPT_SOURCE_URL")

            if not source_url:
                print(
                    "ERROR: DNSCRYPT_SOURCE_URL environment variable not set"
                )
                return []

            response = requests.get(
                source_url,
                timeout=30,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 "
                        "(Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36"
                    )
                }
            )

            response.raise_for_status()

            return cls._parse_content(response.text)

        except Exception as e:
            print(f"Error fetching DNSCrypt data: {e}")
            return []

    @classmethod
    def _parse_content(cls, content: str) -> List[Dict[str, Any]]:
        dns_list = []
        seen = set()

        blocks = re.split(r"(?=^##\s+)", content, flags=re.MULTILINE)

        for block in blocks:
            block = block.strip()

            if not block.startswith("## "):
                continue

            name_match = re.match(
                r"^##\s+([^\s]+)",
                block
            )

            if not name_match:
                continue

            name = name_match.group(1).strip()

            description = cls._extract_description(block)
            sdns_entries = re.findall(
                r"sdns://[A-Za-z0-9_-]+",
                block
            )

            for sdns in dict.fromkeys(sdns_entries):
                result = cls._decode_sdns(sdns)

                if not result:
                    continue

                entry = cls._build_entry(
                    name=name,
                    description=description,
                    result=result
                )

                if not entry:
                    continue

                key = cls._entry_key(entry)

                if key in seen:
                    continue

                seen.add(key)
                dns_list.append(entry)

        print(
            f"Total DNSCrypt entries extracted: {len(dns_list)}"
        )

        return dns_list

    @classmethod
    def _extract_description(cls, block: str) -> str:
        lines = block.splitlines()
        description = []

        for line in lines[1:]:
            line = line.strip()

            if not line:
                continue

            if line.startswith("sdns://"):
                continue

            if line.startswith("## "):
                break

            description.append(line)

        return " ".join(description).strip()

    @classmethod
    def _decode_sdns(
        cls,
        sdns: str
    ) -> Optional[Dict[str, Any]]:
        try:
            if not sdns.startswith("sdns://"):
                return None

            encoded = sdns[7:]
            padding = "=" * (-len(encoded) % 4)

            raw = base64.urlsafe_b64decode(
                encoded + padding
            )

            if len(raw) < 9:
                return None

            protocol_id = raw[0]

            if protocol_id not in cls.PROTOCOLS:
                return None

            protocol = cls.PROTOCOLS[protocol_id]

            offset = 1

            props = int.from_bytes(
                raw[offset:offset + 8],
                "little"
            )

            offset += 8

            if protocol_id == 0x00:
                return cls._decode_plain_dns(
                    raw,
                    offset,
                    protocol,
                    props
                )

            if protocol_id == 0x01:
                return cls._decode_dnscrypt(
                    raw,
                    offset,
                    protocol,
                    props
                )

            if protocol_id in (0x02, 0x03, 0x04):
                return cls._decode_secure_dns(
                    raw,
                    offset,
                    protocol,
                    protocol_id,
                    props
                )

            if protocol_id == 0x05:
                return cls._decode_oblivious_doh(
                    raw,
                    offset,
                    protocol,
                    props
                )

            if protocol_id == 0x81:
                return cls._decode_relay(
                    raw,
                    offset,
                    protocol,
                    props=None
                )

            if protocol_id == 0x85:
                return cls._decode_oblivious_doh_relay(
                    raw,
                    offset,
                    protocol,
                    props
                )

        except Exception as e:
            print(f"Error decoding SDNS: {e}")

        return None

    @classmethod
    def _read_lp(
        cls,
        data: bytes,
        offset: int
    ) -> Optional[Tuple[bytes, int]]:
        if offset >= len(data):
            return None

        length = data[offset]
        offset += 1

        if offset + length > len(data):
            return None

        value = data[offset:offset + length]
        offset += length

        return value, offset

    @classmethod
    def _read_vlp(
        cls,
        data: bytes,
        offset: int
    ) -> Tuple[List[bytes], int]:
        values = []

        while offset < len(data):
            length_byte = data[offset]
            offset += 1

            length = length_byte & 0x7F

            if offset + length > len(data):
                return values, len(data)

            value = data[offset:offset + length]
            offset += length

            values.append(value)

            if not (length_byte & 0x80):
                break

        return values, offset

    @classmethod
    def _decode_plain_dns(
        cls,
        data: bytes,
        offset: int,
        protocol: str,
        props: int
    ) -> Optional[Dict[str, Any]]:
        result = cls._read_lp(data, offset)

        if not result:
            return None

        address_raw, offset = result
        address = address_raw.decode(
            "utf-8",
            errors="ignore"
        ).strip()

        host, port = cls._split_host_port(address)

        return {
            "protocol": protocol,
            "protocol_id": 0x00,
            "address": host,
            "hostname": host,
            "port": port or 53,
            "path": None,
            "properties": props
        }

    @classmethod
    def _decode_dnscrypt(
        cls,
        data: bytes,
        offset: int,
        protocol: str,
        props: int
    ) -> Optional[Dict[str, Any]]:
        addr_result = cls._read_lp(data, offset)

        if not addr_result:
            return None

        address_raw, offset = addr_result

        pk_result = cls._read_lp(data, offset)

        if not pk_result:
            return None

        _, offset = pk_result

        provider_result = cls._read_lp(data, offset)

        if not provider_result:
            return None

        provider_raw, offset = provider_result

        address = address_raw.decode(
            "utf-8",
            errors="ignore"
        ).strip()

        provider_name = provider_raw.decode(
            "utf-8",
            errors="ignore"
        ).strip()

        host, port = cls._split_host_port(address)

        return {
            "protocol": protocol,
            "protocol_id": 0x01,
            "address": host,
            "hostname": provider_name or None,
            "provider_name": provider_name,
            "port": port or 443,
            "path": None,
            "properties": props
        }

    @classmethod
    def _decode_secure_dns(
        cls,
        data: bytes,
        offset: int,
        protocol: str,
        protocol_id: int,
        props: int
    ) -> Optional[Dict[str, Any]]:
        addr_result = cls._read_lp(data, offset)

        if not addr_result:
            return None

        address_raw, offset = addr_result

        _, offset = cls._read_vlp(data, offset)

        hostname_result = cls._read_lp(data, offset)

        if not hostname_result:
            return None

        hostname_raw, offset = hostname_result

        hostname_port = hostname_raw.decode(
            "utf-8",
            errors="ignore"
        ).strip()

        hostname, port = cls._split_host_port(
            hostname_port
        )

        address = address_raw.decode(
            "utf-8",
            errors="ignore"
        ).strip()

        path = None

        if protocol_id == 0x02:
            path_result = cls._read_lp(data, offset)

            if not path_result:
                return None

            path_raw, offset = path_result

            path = path_raw.decode(
                "utf-8",
                errors="ignore"
            ).strip()

            if not path:
                path = "/dns-query"

        return {
            "protocol": protocol,
            "protocol_id": protocol_id,
            "address": address or hostname,
            "bootstrap_address": address or None,
            "hostname": hostname or None,
            "port": port or 443,
            "path": path,
            "properties": props
        }

    @classmethod
    def _decode_oblivious_doh(
        cls,
        data: bytes,
        offset: int,
        protocol: str,
        props: int
    ) -> Optional[Dict[str, Any]]:
        hostname_result = cls._read_lp(data, offset)

        if not hostname_result:
            return None

        hostname_raw, offset = hostname_result

        hostname_port = hostname_raw.decode(
            "utf-8",
            errors="ignore"
        ).strip()

        hostname, port = cls._split_host_port(
            hostname_port
        )

        path_result = cls._read_lp(data, offset)

        if not path_result:
            return None

        path_raw, offset = path_result

        path = path_raw.decode(
            "utf-8",
            errors="ignore"
        ).strip()

        return {
            "protocol": protocol,
            "protocol_id": 0x05,
            "address": hostname,
            "hostname": hostname,
            "port": port or 443,
            "path": path or "/dns-query",
            "properties": props
        }

    @classmethod
    def _decode_relay(
        cls,
        data: bytes,
        offset: int,
        protocol: str,
        props: Optional[int]
    ) -> Optional[Dict[str, Any]]:
        result = cls._read_lp(data, offset)

        if not result:
            return None

        address_raw, offset = result

        address = address_raw.decode(
            "utf-8",
            errors="ignore"
        ).strip()

        host, port = cls._split_host_port(address)

        return {
            "protocol": protocol,
            "protocol_id": 0x81,
            "address": host,
            "hostname": host,
            "port": port or 443,
            "path": None,
            "properties": props
        }

    @classmethod
    def _decode_oblivious_doh_relay(
        cls,
        data: bytes,
        offset: int,
        protocol: str,
        props: int
    ) -> Optional[Dict[str, Any]]:
        addr_result = cls._read_lp(data, offset)

        if not addr_result:
            return None

        address_raw, offset = addr_result

        _, offset = cls._read_vlp(data, offset)

        hostname_result = cls._read_lp(data, offset)

        if not hostname_result:
            return None

        hostname_raw, offset = hostname_result

        hostname_port = hostname_raw.decode(
            "utf-8",
            errors="ignore"
        ).strip()

        hostname, port = cls._split_host_port(
            hostname_port
        )

        path_result = cls._read_lp(data, offset)

        if not path_result:
            return None

        path_raw, offset = path_result

        address = address_raw.decode(
            "utf-8",
            errors="ignore"
        ).strip()

        path = path_raw.decode(
            "utf-8",
            errors="ignore"
        ).strip()

        return {
            "protocol": protocol,
            "protocol_id": 0x85,
            "address": address or hostname,
            "bootstrap_address": address or None,
            "hostname": hostname,
            "port": port or 443,
            "path": path or "/dns-query",
            "properties": props
        }

    @classmethod
    def _split_host_port(
        cls,
        value: str
    ) -> Tuple[str, Optional[int]]:
        value = value.strip()

        if not value:
            return "", None

        if value.startswith("["):
            match = re.match(
                r"^\[([0-9a-fA-F:]+)\](?::(\d+))?$",
                value
            )

            if match:
                host = match.group(1)
                port = (
                    int(match.group(2))
                    if match.group(2)
                    else None
                )
                return host, port

        try:
            ipaddress.ip_address(value)
            return value, None
        except ValueError:
            pass

        if ":" in value:
            host, port = value.rsplit(":", 1)

            if port.isdigit():
                return host, int(port)

        return value, None

    @classmethod
    def _build_entry(
        cls,
        name: str,
        description: str,
        result: Dict[str, Any]
    ) -> Dict[str, Any]:
        protocol = result.get("protocol", "Unknown")
        address = result.get("address") or ""
        hostname = result.get("hostname")
        port = result.get("port")
        path = result.get("path")

        entry = {
            "name": name,
            "provider": name,
            "description": description,
            "source": cls.SOURCE_NAME,
            "protocol": protocol,
            "protocol_id": result.get("protocol_id"),
            "address": address,
            "hostname": hostname,
            "port": port,
            "path": path,
            "properties": result.get("properties", 0)
        }

        try:
            if address:
                ip = ipaddress.ip_address(address)
                entry["type"] = (
                    "IPv4"
                    if ip.version == 4
                    else "IPv6"
                )
            elif hostname:
                entry["type"] = "Hostname"
            else:
                entry["type"] = "Unknown"
        except ValueError:
            entry["type"] = "Hostname" if hostname else "Unknown"

        if protocol == "DNSCrypt":
            entry["dnscrypt"] = True

        elif protocol == "DoH":
            entry["doh_url"] = (
                f"https://{hostname}"
                f":{port}" if port and port != 443
                else f"https://{hostname}"
            )

            entry["doh_url"] += (
                path or "/dns-query"
            )

        elif protocol == "DoT":
            entry["dot"] = hostname

        elif protocol == "DoQ":
            entry["doq"] = hostname

        return entry

    @classmethod
    def _entry_key(
        cls,
        entry: Dict[str, Any]
    ) -> str:
        return "|".join([
            str(entry.get("protocol", "")).lower(),
            str(entry.get("address", "")).lower(),
            str(entry.get("hostname", "")).lower(),
            str(entry.get("port", "")),
            str(entry.get("path", "")).lower()
        ])
