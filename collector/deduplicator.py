from typing import List, Dict, Any
import hashlib
import json


class Deduplicator:

    @classmethod
    def deduplicate(
        cls,
        data: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        unique_map: Dict[str, Dict[str, Any]] = {}

        for entry in data:
            key = cls._generate_key(entry)

            if key not in unique_map:
                item = dict(entry)
                item["sources"] = cls._collect_sources(entry)
                unique_map[key] = item
                continue

            existing = unique_map[key]

            cls._merge_sources(existing, entry)
            cls._merge_data(existing, entry)

        return list(unique_map.values())

    @classmethod
    def _generate_key(cls, entry: Dict[str, Any]) -> str:
        doh_url = cls._clean(
            entry.get("doh_url")
        )

        dot = cls._clean(
            entry.get("dot")
        )

        address = cls._clean(
            entry.get("address")
        )

        hostname = cls._clean(
            entry.get("hostname")
        )

        protocol = cls._clean(
            entry.get("protocol")
        )

        port = entry.get("port")

        if doh_url:
            return f"doh|{doh_url}"

        if dot:
            return f"dot|{dot}|{port or ''}"

        if protocol == "dnscrypt":
            if address and port:
                return f"dnscrypt|{address}|{port}"

            if hostname:
                return f"dnscrypt|{hostname}"

        if protocol == "doh":
            if address and port:
                return f"doh|{address}|{port}"

            if hostname:
                return f"doh|{hostname}|{port or ''}"

        if protocol == "dot":
            if address and port:
                return f"dot|{address}|{port}"

            if hostname:
                return f"dot|{hostname}|{port or ''}"

        if address:
            return f"address|{address}|{port or ''}"

        if hostname:
            return f"hostname|{hostname}|{port or ''}"

        name = cls._clean(
            entry.get("name")
        )

        if name:
            return f"name|{name}"

        payload = json.dumps(
            entry,
            ensure_ascii=False,
            sort_keys=True,
            default=str,
            separators=(",", ":")
        )

        return "unknown|" + hashlib.sha256(
            payload.encode("utf-8")
        ).hexdigest()

    @classmethod
    def _clean(cls, value: Any) -> str:
        if value is None:
            return ""

        return str(value).strip().lower().rstrip("/")

    @classmethod
    def _collect_sources(
        cls,
        entry: Dict[str, Any]
    ) -> List[str]:
        sources = []

        source = entry.get("source")

        if source:
            sources.append(str(source))

        entry_sources = entry.get("sources", [])

        if isinstance(entry_sources, str):
            entry_sources = [entry_sources]

        if isinstance(entry_sources, list):
            for item in entry_sources:
                if item and item not in sources:
                    sources.append(str(item))

        return sources

    @classmethod
    def _merge_sources(
        cls,
        existing: Dict[str, Any],
        new: Dict[str, Any]
    ) -> None:
        sources = cls._collect_sources(existing)

        for source in cls._collect_sources(new):
            if source not in sources:
                sources.append(source)

        existing["sources"] = sources

    @classmethod
    def _merge_data(
        cls,
        existing: Dict[str, Any],
        new: Dict[str, Any]
    ) -> None:
        for key, value in new.items():

            if key in ("source", "sources"):
                continue

            if value is None or value == "":
                continue

            if key not in existing or existing[key] in (
                None,
                ""
            ):
                existing[key] = value
                continue

            current = existing[key]

            if current == value:
                continue

            if isinstance(current, list):
                values = value if isinstance(value, list) else [value]

                for item in values:
                    if item not in current:
                        current.append(item)

                continue

            if isinstance(value, list):
                merged = [current]

                for item in value:
                    if item not in merged:
                        merged.append(item)

                existing[key] = merged
