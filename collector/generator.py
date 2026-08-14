import json
import os
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")


class Generator:

    def __init__(self, data: List[Dict[str, Any]]):
        self.data = data
        self.stats = {}

    def save(self):
        self._generate_stats()

        current_data = self._generate_output()

        dns_path = os.path.join(DATA_DIR, "dns.json")
        min_path = os.path.join(DATA_DIR, "dns.min.json")
        stats_path = os.path.join(DATA_DIR, "stats.json")

        old_data = None

        if os.path.exists(dns_path):
            try:
                with open(dns_path, "r", encoding="utf-8") as f:
                    old_data = json.load(f)
            except (OSError, json.JSONDecodeError):
                old_data = None

        if old_data:
            old_dns = old_data.get("dns", [])
            new_dns = current_data.get("dns", [])

            if self._hash_data(new_dns) == self._hash_data(old_dns):
                self._save_json(stats_path, self.stats)
                print("No DNS changes detected")
                return

        self._save_json(dns_path, current_data)

        minified_data = self._generate_minified(current_data)
        self._save_json(min_path, minified_data)

        self._save_json(stats_path, self.stats)

        print(f"Saved {len(self.data)} DNS entries")

    def _hash_data(self, data: List[Dict[str, Any]]) -> str:
        normalized = []

        for entry in data:
            item = dict(entry)
            item.pop("id", None)
            normalized.append(item)

        normalized.sort(
            key=lambda x: (
                str(x.get("address", "")),
                str(x.get("hostname", "")),
                str(x.get("doh_url", "")),
                str(x.get("dot", "")),
                str(x.get("name", ""))
            )
        )

        payload = json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":")
        )

        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _generate_output(self) -> Dict[str, Any]:
        return {
            "version": 1,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "total": len(self.data),
            "categories": self._get_category_counts(),
            "dns": self._prepare_dns_entries()
        }

    def _prepare_dns_entries(self) -> List[Dict[str, Any]]:
        entries = []

        for entry in self.data:
            dns_entry = {
                "id": self._generate_id(entry),
                "address": entry.get("address", ""),
                "type": entry.get("type", "Unknown"),
                "provider": entry.get("provider", ""),
                "name": entry.get("name", ""),
                "sources": entry.get(
                    "sources",
                    [entry.get("source", "unknown")]
                ),
                "categories": entry.get(
                    "categories",
                    ["Standard"]
                ),
                "protocols": entry.get(
                    "protocols",
                    ["DNS"]
                ),
                "status": "active"
            }

            optional_fields = [
                "doh_url",
                "dot",
                "dnscrypt",
                "country",
                "description",
                "hostname",
                "port",
                "path"
            ]

            for field in optional_fields:
                value = entry.get(field)

                if value is not None and value != "":
                    dns_entry[field] = value

            entries.append(dns_entry)

        return entries

    def _generate_id(self, entry: Dict[str, Any]) -> str:
        identity = {
            "address": entry.get("address", ""),
            "hostname": entry.get("hostname", ""),
            "doh_url": entry.get("doh_url", ""),
            "dot": entry.get("dot", ""),
            "name": entry.get("name", ""),
            "provider": entry.get("provider", "")
        }

        payload = json.dumps(
            identity,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":")
        )

        return hashlib.sha256(
            payload.encode("utf-8")
        ).hexdigest()[:32]

    def _generate_stats(self) -> None:
        sources = set()

        for entry in self.data:
            sources.update(
                entry.get(
                    "sources",
                    [entry.get("source", "unknown")]
                )
            )

        self.stats = {
            "total_dns": len(self.data),
            "total_ipv4": self._count_type("IPv4"),
            "total_ipv6": self._count_type("IPv6"),
            "total_doh": self._count_protocol("DoH"),
            "total_dot": self._count_protocol("DoT"),
            "total_dnscrypt": self._count_protocol("DNSCrypt"),
            "total_standard": self._count_category("Standard"),
            "total_private": self._count_category("Private"),
            "total_family": self._count_category("Family"),
            "total_adblock": self._count_category("AdBlock"),
            "total_security": self._count_category("Security"),
            "total_malware": self._count_category("Malware"),
            "total_freeshekan": self._count_category("FreeShekan"),
            "total_sources": len(sources),
            "last_updated": datetime.now(timezone.utc).isoformat()
        }

    def _count_type(self, type_name: str) -> int:
        return sum(
            1
            for entry in self.data
            if entry.get("type") == type_name
        )

    def _count_protocol(self, protocol: str) -> int:
        return sum(
            1
            for entry in self.data
            if protocol in entry.get("protocols", [])
        )

    def _count_category(self, category: str) -> int:
        return sum(
            1
            for entry in self.data
            if category in entry.get("categories", [])
        )

    def _get_category_counts(self) -> Dict[str, int]:
        counts = {}

        for entry in self.data:
            for category in entry.get("categories", []):
                counts[category] = counts.get(category, 0) + 1

        return dict(sorted(counts.items()))

    def _generate_minified(
        self,
        current_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        output = {
            "version": current_data.get("version", 1),
            "updated_at": current_data.get("updated_at"),
            "total": current_data.get("total", 0),
            "categories": current_data.get("categories", {}),
            "dns": []
        }

        for dns in current_data.get("dns", []):
            item = dict(dns)

            for key in (
                "description",
                "source",
                "path",
                "port"
            ):
                item.pop(key, None)

            output["dns"].append(item)

        return output

    def _save_json(
        self,
        filepath: str,
        data: Dict[str, Any]
    ) -> None:
        os.makedirs(
            os.path.dirname(filepath),
            exist_ok=True
        )

        temp_path = f"{filepath}.tmp"

        with open(
            temp_path,
            "w",
            encoding="utf-8"
        ) as f:
            json.dump(
                data,
                f,
                indent=2,
                ensure_ascii=False
            )

        os.replace(temp_path, filepath)
