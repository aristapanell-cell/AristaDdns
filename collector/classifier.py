import ipaddress
from typing import List, Dict, Any


class Classifier:

    CATEGORIES = {
        "AdBlock": [
            "adblock",
            "ad block",
            "ad-filter",
            "ad filter",
            "ad filtering",
            "ads",
            "advertising",
            "tracker",
            "tracking",
            "adguard"
        ],

        "Family": [
            "family",
            "parental",
            "kids",
            "children",
            "safe family"
        ],

        "Adult Filter": [
            "adult",
            "porn",
            "nsfw",
            "mature",
            "adult content"
        ],

        "Security": [
            "security",
            "threat",
            "phishing",
            "protect",
            "protection",
            "malicious",
            "malicious domains",
            "safe browsing"
        ],

        "Malware": [
            "malware",
            "virus",
            "ransomware",
            "botnet"
        ],

        "Private": [
            "private",
            "local",
            "internal"
        ],

        "Unfiltered": [
            "unfiltered",
            "non-filtering",
            "non filtering",
            "no filter",
            "no filtering",
            "does not block",
            "doesn't block",
            "does not rewrite"
        ]
    }

    @classmethod
    def classify(
        cls,
        data: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:

        for entry in data:
            entry["categories"] = cls._determine_categories(entry)
            entry["protocols"] = cls._determine_protocols(entry)
            entry["type"] = cls._determine_type(entry)

        return data

    @classmethod
    def _build_text(
        cls,
        entry: Dict[str, Any]
    ) -> str:

        values = [
            entry.get("name", ""),
            entry.get("provider", ""),
            entry.get("description", ""),
            entry.get("tags", ""),
            entry.get("hostname", ""),
            entry.get("doh_url", "")
        ]

        return " ".join(
            str(value)
            for value in values
            if value is not None
        ).lower()

    @classmethod
    def _determine_categories(
        cls,
        entry: Dict[str, Any]
    ) -> List[str]:

        text = cls._build_text(entry)
        categories = []

        is_unfiltered = any(
            keyword in text
            for keyword in cls.CATEGORIES["Unfiltered"]
        )

        for category, keywords in cls.CATEGORIES.items():

            if category == "Unfiltered":
                continue

            if category == "AdBlock":
                if is_unfiltered:
                    if any(
                        keyword in text
                        for keyword in (
                            "adguard-dns-unfiltered",
                            "unfiltered.adguard",
                            "non-filtering"
                        )
                    ):
                        continue

            if any(
                keyword in text
                for keyword in keywords
            ):
                categories.append(category)

        if is_unfiltered and "Unfiltered" not in categories:
            categories.append("Unfiltered")

        if "FreeShekan" in categories:
            return categories

        if (
            "free shekan" in text
            or "freeshekan" in text
            or "free-shekan" in text
        ):
            categories.append("FreeShekan")

        if not categories:
            categories.append("Standard")

        return categories

    @classmethod
    def _determine_protocols(
        cls,
        entry: Dict[str, Any]
    ) -> List[str]:

        protocols = ["DNS"]

        if entry.get("doh_url"):
            protocols.append("DoH")

        if entry.get("dot"):
            protocols.append("DoT")

        if entry.get("dnscrypt"):
            protocols.append("DNSCrypt")

        protocol = str(
            entry.get("protocol", "")
        ).strip()

        if protocol:
            normalized_protocol = protocol.lower()

            protocol_map = {
                "doh": "DoH",
                "dot": "DoT",
                "dnscrypt": "DNSCrypt",
                "dns": "DNS"
            }

            mapped = protocol_map.get(
                normalized_protocol
            )

            if mapped and mapped not in protocols:
                protocols.append(mapped)

        return protocols

    @classmethod
    def _determine_type(
        cls,
        entry: Dict[str, Any]
    ) -> str:

        address = str(
            entry.get("address", "")
        ).strip()

        if address:
            try:
                ip = ipaddress.ip_address(address)

                if ip.version == 4:
                    return "IPv4"

                if ip.version == 6:
                    return "IPv6"

            except ValueError:
                pass

        if entry.get("doh_url"):
            return "DoH"

        if entry.get("dot"):
            return "DoT"

        if entry.get("hostname"):
            return "Hostname"

        return "Unknown"
