import re
import requests
import os
import ipaddress
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup
from urllib.parse import urlparse


class DOHParser:
    SOURCE_NAME = "curl"

    URL_PATTERN = re.compile(
        r'https?://[^\s<>"\'\)\]\}]+',
        re.IGNORECASE
    )

    DOT_URL_PATTERN = re.compile(
        r'\btls://'
        r'(?P<host>'
        r'\[[0-9a-fA-F:]+\]'
        r'|'
        r'(?:[a-zA-Z0-9]'
        r'(?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?)'
        r'|'
        r'(?:\d{1,3}\.){3}\d{1,3}'
        r')'
        r'(?::\d{1,5})?',
        re.IGNORECASE
    )

    DOT_HOST_PATTERN = re.compile(
        r'(?<![A-Za-z0-9._/-])'
        r'(?P<host>'
        r'\[[0-9a-fA-F:]+\]'
        r'|'
        r'(?:[a-zA-Z0-9]'
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
        r'\.)+'
        r'[a-zA-Z]{2,63}'
        r'|'
        r'(?:\d{1,3}\.){3}\d{1,3}'
        r')'
        r'(?::\d{1,5})?',
        re.IGNORECASE
    )

    DOT_LABEL_PATTERN = re.compile(
        r'(?:'
        r'\bdns\s*[- ]?\s*over\s*tls\b'
        r'|'
        r'\bdns\s*over\s*transport\s*layer\s*security\b'
        r'|'
        r'\bsupports?\s+dot\b'
        r'|'
        r'\bdot\s+support\b'
        r'|'
        r'\bdot\b'
        r')',
        re.IGNORECASE
    )

    DOT_LABELED_HOST_PATTERN = re.compile(
        r'(?:'
        r'\bdns\s*[- ]?\s*over\s*tls\b'
        r'|'
        r'\bdot\b'
        r')'
        r'\s*'
        r'(?:'
        r'endpoint'
        r'|server'
        r'|resolver'
        r'|address'
        r')?'
        r'\s*[:=\-]?\s*'
        r'(?P<endpoint>'
        r'\[[0-9a-fA-F:]+\]'
        r'|'
        r'(?:[a-zA-Z0-9]'
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
        r'\.)+'
        r'[a-zA-Z]{2,63}'
        r'|'
        r'(?:\d{1,3}\.){3}\d{1,3}'
        r')'
        r'(?::\d{1,5})?',
        re.IGNORECASE
    )

    DNS_PATHS = (
        "/dns-query",
        "/resolve",
        "/doh",
        "/query",
    )

    DNS_HOSTS = (
        "dns.google",
        "cloudflare-dns.com",
        "cloudflare-dns.net",
        "adguard-dns.com",
        "adguard.com",
        "nextdns.io",
        "quad9.net",
        "quad9.org",
    )

    PROVIDER_PATTERNS = (
        "run by",
        "who runs",
        "operator",
        "provider",
        "company",
        "organization",
        "organisation",
        "operated by",
    )

    PROVIDER_NOISE = re.compile(
        r'\b(?:standard|adblock|family|security|malware|adult|'
        r'unfiltered|free|shekan|private|ipv4|ipv6|doh|dot|'
        r'dns|active|copy)\b',
        re.IGNORECASE
    )

    @classmethod
    def fetch(cls) -> List[Dict[str, Any]]:
        try:
            source_url = os.environ.get("DOH_SOURCE_URL")

            if not source_url:
                print(
                    "ERROR: DOH_SOURCE_URL environment variable not set"
                )
                return []

            response = requests.get(
                source_url,
                timeout=30,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 "
                        "(KHTML, like Gecko) "
                        "Chrome/120.0 Safari/537.36"
                    )
                }
            )

            response.raise_for_status()

            soup = BeautifulSoup(
                response.text,
                "html.parser"
            )

            dns_list = cls._parse_content(soup)

            doh_count = sum(
                1
                for entry in dns_list
                if entry.get("protocol") == "DoH"
            )

            dot_count = sum(
                1
                for entry in dns_list
                if entry.get("protocol") == "DoT"
            )

            print(
                f"Total DoH/DoT entries extracted: "
                f"{len(dns_list)} "
                f"(DoH: {doh_count}, DoT: {dot_count})"
            )

            return dns_list

        except requests.RequestException as e:
            print(f"Error fetching DoH/DoT data: {e}")
            return []

        except Exception as e:
            print(f"Unexpected parser error: {e}")
            return []

    @classmethod
    def _parse_content(
        cls,
        soup: BeautifulSoup
    ) -> List[Dict[str, Any]]:
        dns_list = []
        seen_doh = set()
        seen_dot = set()

        def add_entry(entry):
            if not entry:
                return

            protocol = entry.get("protocol")

            if protocol == "DoH":
                key = cls._doh_key(entry)

                if key in seen_doh:
                    return

                seen_doh.add(key)
                dns_list.append(entry)

            elif protocol == "DoT":
                key = cls._dot_key(entry)

                if key in seen_dot:
                    return

                seen_dot.add(key)
                dns_list.append(entry)

        for table in soup.find_all("table"):
            rows = table.find_all("tr")

            if not rows:
                continue

            headers = cls._extract_headers(rows[0])

            provider_idx = cls._find_provider_column(headers)
            url_idx = cls._find_url_column(headers)

            for row in rows[1:]:
                cells = row.find_all(["td", "th"])

                if not cells:
                    continue

                row_text = cls._clean_text(
                    row.get_text(" ", strip=True)
                )

                provider = cls._extract_provider_from_row(
                    row,
                    cells,
                    provider_idx,
                    url_idx
                )

                urls = []

                for cell in cls._get_url_cells(
                    cells,
                    url_idx
                ):
                    urls.extend(
                        cls._extract_urls(cell)
                    )

                if not urls:
                    urls = cls._extract_urls(row)

                for url in urls:
                    if not cls._is_dns_url(url):
                        continue

                    add_entry(
                        cls._build_entry(
                            url,
                            provider
                        )
                    )

                for dot_entry in cls._extract_dot_entries(
                    row,
                    row_text,
                    provider
                ):
                    add_entry(dot_entry)

        for element in cls._get_generic_containers(soup):
            text = cls._clean_text(
                element.get_text(" ", strip=True)
            )

            if not text:
                continue

            provider = cls._extract_provider_from_element(
                element
            )

            urls = cls._extract_urls(element)

            for url in urls:
                if not cls._is_dns_url(url):
                    continue

                add_entry(
                    cls._build_entry(
                        url,
                        provider
                    )
                )

            for dot_entry in cls._extract_dot_entries(
                element,
                text,
                provider
            ):
                add_entry(dot_entry)

        full_text = cls._clean_text(
            soup.get_text(" ", strip=True)
        )

        if full_text:
            provider = cls._extract_provider_from_element(
                soup
            )

            for dot_entry in cls._extract_dot_entries(
                soup,
                full_text,
                provider
            ):
                add_entry(dot_entry)

        if dns_list:
            return dns_list

        return cls._parse_fallback(soup)

    @classmethod
    def _get_generic_containers(
        cls,
        soup: BeautifulSoup
    ) -> List[Any]:
        containers = []

        for element in soup.find_all(
            [
                "article",
                "li",
                "section",
                "div",
                "pre",
                "code"
            ]
        ):
            if element.find_parent("table"):
                continue

            text = cls._clean_text(
                element.get_text(" ", strip=True)
            )

            if not text:
                continue

            has_dns_signal = (
                cls._contains_url(text)
                or cls._contains_dot_endpoint(text)
                or cls._supports_dot(text)
                or "dns" in text.lower()
                or "tls://" in text.lower()
            )

            if has_dns_signal:
                containers.append(element)

        return containers

    @classmethod
    def _extract_provider_from_element(
        cls,
        element
    ) -> str:
        links = element.find_all(
            "a",
            href=True
        )

        candidates = []

        for child in element.find_all(
            ["span", "strong", "b", "small"]
        ):
            text = cls._clean_text(
                child.get_text(" ", strip=True)
            )

            if not text:
                continue

            if cls._contains_url(text):
                continue

            if cls._contains_dot_endpoint(text):
                continue

            cleaned = cls._clean_provider(text)

            if cleaned:
                candidates.append(cleaned)

        for link in links:
            text = cls._clean_text(
                link.get_text(" ", strip=True)
            )

            if not text:
                continue

            if cls._is_http_url(
                link.get("href", "")
            ):
                continue

            if cls._contains_dot_endpoint(text):
                continue

            cleaned = cls._clean_provider(text)

            if cleaned:
                candidates.append(cleaned)

        for candidate in candidates:
            if (
                candidate.lower()
                not in (
                    "standard",
                    "adblock",
                    "family",
                    "security",
                    "malware",
                    "adult",
                    "unfiltered",
                    "free",
                    "shekan",
                    "private",
                    "ipv4",
                    "ipv6",
                    "doh",
                    "dot",
                    "dns",
                    "active",
                    "copy",
                )
            ):
                return candidate

        return "Unknown"

    @classmethod
    def _extract_headers(
        cls,
        row
    ) -> List[str]:
        return [
            cls._clean_text(
                cell.get_text(" ", strip=True).lower()
            )
            for cell in row.find_all(["th", "td"])
        ]

    @classmethod
    def _find_provider_column(
        cls,
        headers: List[str]
    ) -> Optional[int]:
        for index, header in enumerate(headers):
            if any(
                pattern in header
                for pattern in cls.PROVIDER_PATTERNS
            ):
                return index

        return None

    @classmethod
    def _find_url_column(
        cls,
        headers: List[str]
    ) -> Optional[int]:
        patterns = (
            "base url",
            "url",
            "endpoint",
            "server",
            "resolver",
            "dns endpoint",
            "doh",
            "dns over https",
            "dot",
            "dns over tls",
        )

        for index, header in enumerate(headers):
            if any(
                pattern in header
                for pattern in patterns
            ):
                return index

        return None

    @classmethod
    def _get_url_cells(
        cls,
        cells,
        url_idx: Optional[int]
    ) -> List[Any]:
        if (
            url_idx is not None
            and url_idx < len(cells)
        ):
            return [cells[url_idx]]

        candidates = []

        for cell in cells:
            text = cell.get_text(
                " ",
                strip=True
            )

            if (
                cell.find("a", href=True)
                or cls._contains_url(text)
                or cls._contains_dot_endpoint(text)
            ):
                candidates.append(cell)

        return candidates or cells

    @classmethod
    def _extract_provider_from_row(
        cls,
        row,
        cells,
        provider_idx: Optional[int],
        url_idx: Optional[int]
    ) -> str:
        if (
            provider_idx is not None
            and provider_idx < len(cells)
        ):
            provider = cells[
                provider_idx
            ].get_text(
                " ",
                strip=True
            )

            provider = cls._clean_provider(provider)

            if provider:
                return provider

        candidates = []

        for index, cell in enumerate(cells):
            if (
                url_idx is not None
                and index == url_idx
            ):
                continue

            text = cls._clean_text(
                cell.get_text(" ", strip=True)
            )

            if not text:
                continue

            if cls._contains_url(text):
                continue

            if cls._contains_dot_endpoint(text):
                continue

            if len(text) > 200:
                continue

            cleaned = cls._clean_provider(text)

            if not cleaned:
                continue

            if cls._is_ui_value(cleaned):
                continue

            candidates.append(cleaned)

        if candidates:
            return candidates[0]

        return "Unknown"

    @classmethod
    def _extract_urls(
        cls,
        element
    ) -> List[str]:
        urls = []

        for link in element.find_all(
            "a",
            href=True
        ):
            href = link.get(
                "href",
                ""
            ).strip()

            if cls._is_http_url(href):
                urls.append(
                    cls._clean_url(href)
                )

        text = element.get_text(
            " ",
            strip=True
        )

        urls.extend(
            cls.URL_PATTERN.findall(text)
        )

        result = []

        for url in urls:
            url = cls._clean_url(url)

            if (
                url
                and cls._is_http_url(url)
            ):
                result.append(url)

        return list(dict.fromkeys(result))

    @classmethod
    def _extract_dot_entries(
        cls,
        element,
        row_text: str,
        provider: str
    ) -> List[Dict[str, Any]]:
        candidates = []

        for link in element.find_all(
            "a",
            href=True
        ):
            href = link.get(
                "href",
                ""
            ).strip()

            if href.lower().startswith("tls://"):
                endpoint = cls._clean_dot_endpoint(href)

                if endpoint:
                    candidates.append(endpoint)

        for match in cls.DOT_URL_PATTERN.finditer(row_text):
            endpoint = cls._clean_dot_endpoint(
                match.group(0)
            )

            if endpoint:
                candidates.append(endpoint)

        for match in cls.DOT_LABELED_HOST_PATTERN.finditer(
            row_text
        ):
            endpoint = cls._clean_dot_endpoint(
                match.group("endpoint")
            )

            if endpoint:
                candidates.append(endpoint)

        for match in cls.DOT_HOST_PATTERN.finditer(row_text):
            endpoint = cls._clean_dot_endpoint(
                match.group(0)
            )

            if endpoint:
                candidates.append(endpoint)

        result = []
        local_seen = set()

        for endpoint in candidates:
            entry = cls._build_dot_entry(
                endpoint,
                provider
            )

            if not entry:
                continue

            key = cls._dot_key(entry)

            if key in local_seen:
                continue

            local_seen.add(key)
            result.append(entry)

        return result

    @classmethod
    def _clean_dot_endpoint(
        cls,
        endpoint: str
    ) -> Optional[str]:
        endpoint = str(
            endpoint or ""
        ).strip()

        if not endpoint:
            return None

        endpoint = endpoint.rstrip(
            ".,;)]}\"'"
        )

        if endpoint.lower().startswith("tls://"):
            match = cls.DOT_URL_PATTERN.fullmatch(endpoint)

            if not match:
                return None

            return endpoint

        match = cls.DOT_HOST_PATTERN.fullmatch(endpoint)

        if not match:
            return None

        return endpoint

    @classmethod
    def _parse_dot_endpoint(
        cls,
        endpoint: str
    ) -> Optional[str]:
        endpoint = cls._clean_dot_endpoint(endpoint)

        if not endpoint:
            return None

        if not endpoint.lower().startswith("tls://"):
            return endpoint

        try:
            parsed = urlparse(endpoint)

            if parsed.scheme.lower() != "tls":
                return None

            if not parsed.hostname:
                return None

            return endpoint

        except (
            ValueError,
            TypeError
        ):
            return None

    @classmethod
    def _build_dot_entry(
        cls,
        endpoint: str,
        provider: str
    ) -> Dict[str, Any]:
        try:
            endpoint = str(
                endpoint
            ).strip()

            if not endpoint:
                return {}

            original_endpoint = endpoint

            if endpoint.lower().startswith("tls://"):
                parsed = urlparse(endpoint)

                if parsed.scheme.lower() != "tls":
                    return {}

                hostname = parsed.hostname

                if not hostname:
                    return {}

            else:
                raw_endpoint = endpoint.rstrip("/")

                if raw_endpoint.startswith("["):
                    end = raw_endpoint.find("]")

                    if end == -1:
                        return {}

                    hostname = raw_endpoint[
                        1:end
                    ]

                else:
                    hostname = raw_endpoint

                    if (
                        re.match(
                            r"^\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}$",
                            raw_endpoint
                        )
                    ):
                        hostname = raw_endpoint.rsplit(
                            ":",
                            1
                        )[0]

                    elif (
                        re.match(
                            r"^[A-Za-z0-9.-]+:\d{1,5}$",
                            raw_endpoint
                        )
                    ):
                        hostname = raw_endpoint.rsplit(
                            ":",
                            1
                        )[0]

                hostname = hostname.strip()

                if not hostname:
                    return {}

            try:
                ipaddress.ip_address(hostname)

            except ValueError:
                if not re.match(
                    r"^(?=.{1,253}$)"
                    r"[a-zA-Z0-9]"
                    r"(?:[a-zA-Z0-9.-]*"
                    r"[a-zA-Z0-9])?$",
                    hostname
                ):
                    return {}

                labels = hostname.split(".")

                if any(
                    not label
                    or len(label) > 63
                    or label.startswith("-")
                    or label.endswith("-")
                    for label in labels
                ):
                    return {}

            provider = str(
                provider or ""
            ).strip()

            if not provider:
                provider = hostname

            return {
                "provider": provider,
                "address": hostname,
                "name": provider,
                "source": cls.SOURCE_NAME,
                "type": "DoT",
                "hostname": hostname,
                "protocol": "DoT",
                "dot": original_endpoint,
                "description": (
                    f"DoT server provided by "
                    f"{provider}"
                ),
            }

        except (
            ValueError,
            TypeError
        ):
            return {}

    @classmethod
    def _parse_fallback(
        cls,
        soup: BeautifulSoup
    ) -> List[Dict[str, Any]]:
        dns_list = []
        seen_doh = set()
        seen_dot = set()

        def add_entry(entry):
            if not entry:
                return

            protocol = entry.get("protocol")

            if protocol == "DoH":
                key = cls._doh_key(entry)

                if key in seen_doh:
                    return

                seen_doh.add(key)
                dns_list.append(entry)

            elif protocol == "DoT":
                key = cls._dot_key(entry)

                if key in seen_dot:
                    return

                seen_dot.add(key)
                dns_list.append(entry)

        for element in soup.find_all(
            [
                "table",
                "article",
                "li",
                "section",
                "div",
                "pre",
                "code"
            ]
        ):
            row_text = cls._clean_text(
                element.get_text(
                    " ",
                    strip=True
                )
            )

            if not row_text:
                continue

            cells = element.find_all(
                ["td", "th"]
            )

            urls = cls._extract_urls(element)

            if cells:
                provider = cls._extract_provider_from_row(
                    element,
                    cells,
                    None,
                    None
                )
            else:
                provider = cls._extract_provider_from_element(
                    element
                )

            for url in urls:
                if not cls._is_dns_url(url):
                    continue

                add_entry(
                    cls._build_entry(
                        url,
                        provider
                    )
                )

            for entry in cls._extract_dot_entries(
                element,
                row_text,
                provider
            ):
                add_entry(entry)

        if dns_list:
            return dns_list

        full_text = cls._clean_text(
            soup.get_text(
                " ",
                strip=True
            )
        )

        provider = cls._extract_provider_from_element(
            soup
        )

        for entry in cls._extract_dot_entries(
            soup,
            full_text,
            provider
        ):
            add_entry(entry)

        for link in soup.find_all(
            "a",
            href=True
        ):
            href = link.get(
                "href",
                ""
            ).strip()

            if cls._is_http_url(href):
                if cls._is_dns_url(href):
                    provider = cls._find_provider(link)

                    add_entry(
                        cls._build_entry(
                            cls._clean_url(href),
                            provider
                        )
                    )

            elif href.lower().startswith("tls://"):
                endpoint = cls._parse_dot_endpoint(href)

                if endpoint:
                    provider = cls._find_provider(link)

                    add_entry(
                        cls._build_dot_entry(
                            endpoint,
                            provider
                        )
                    )

        return dns_list

    @classmethod
    def _build_entry(
        cls,
        url: str,
        provider: str
    ) -> Dict[str, Any]:
        try:
            url = cls._clean_url(url)

            parsed = urlparse(url)

            scheme = parsed.scheme.lower()

            if (
                scheme not in (
                    "https",
                    "http"
                )
                or not parsed.hostname
            ):
                return {}

            hostname = parsed.hostname

            path = parsed.path or "/dns-query"

            provider = cls._clean_provider(provider)

            if not provider:
                provider = hostname

            return {
                "provider": provider,
                "doh_url": url,
                "address": hostname,
                "name": provider,
                "source": cls.SOURCE_NAME,
                "type": "DoH",
                "hostname": hostname,
                "path": path,
                "protocol": "DoH",
                "description": (
                    f"DoH server provided by "
                    f"{provider}"
                ),
            }

        except (
            ValueError,
            TypeError
        ):
            return {}

    @classmethod
    def _supports_dot(
        cls,
        text: str
    ) -> bool:
        return bool(
            cls.DOT_LABEL_PATTERN.search(
                cls._clean_text(text)
            )
        )

    @classmethod
    def _contains_dot_endpoint(
        cls,
        text: str
    ) -> bool:
        return bool(
            cls.DOT_URL_PATTERN.search(text)
            or cls.DOT_HOST_PATTERN.search(text)
            or cls.DOT_LABELED_HOST_PATTERN.search(text)
        )

    @classmethod
    def _find_provider(
        cls,
        link
    ) -> str:
        for parent in link.parents:
            if parent.name == "tr":
                cells = parent.find_all(
                    ["td", "th"]
                )

                for cell in cells:
                    text = cls._clean_text(
                        cell.get_text(
                            " ",
                            strip=True
                        )
                    )

                    if not text:
                        continue

                    if cls._contains_url(text):
                        continue

                    if cls._contains_dot_endpoint(text):
                        continue

                    if cls._is_ui_value(text):
                        continue

                    if len(text) <= 200:
                        return cls._clean_provider(text)

                break

            if parent.name in (
                "section",
                "article",
                "li",
            ):
                candidates = []

                for child in parent.find_all(
                    ["span", "strong", "b"]
                ):
                    text = cls._clean_text(
                        child.get_text(
                            " ",
                            strip=True
                        )
                    )

                    if not text:
                        continue

                    if cls._contains_url(text):
                        continue

                    if cls._contains_dot_endpoint(text):
                        continue

                    if cls._is_ui_value(text):
                        continue

                    cleaned = cls._clean_provider(text)

                    if cleaned:
                        candidates.append(cleaned)

                if candidates:
                    return candidates[0]

        return "Unknown"

    @classmethod
    def _get_link_context(
        cls,
        link
    ) -> str:
        parts = []

        if link.parent:
            parts.append(
                link.parent.get_text(
                    " ",
                    strip=True
                )
            )

        for parent in link.parents:
            if parent.name in (
                "tr",
                "li",
                "section",
                "article",
                "div"
            ):
                text = parent.get_text(
                    " ",
                    strip=True
                )

                if text:
                    parts.append(text)

                if parent.name in (
                    "tr",
                    "section",
                    "article"
                ):
                    break

        return " ".join(parts)

    @classmethod
    def _doh_key(
        cls,
        entry: Dict[str, Any]
    ) -> str:
        return (
            "doh|"
            + cls._normalize_url(
                entry.get(
                    "doh_url",
                    ""
                )
            )
        )

    @classmethod
    def _dot_key(
        cls,
        entry: Dict[str, Any]
    ) -> str:
        return (
            "dot|"
            + str(
                entry.get(
                    "dot",
                    entry.get(
                        "hostname",
                        entry.get(
                            "address",
                            ""
                        )
                    )
                )
            ).lower()
        )

    @classmethod
    def _extract_hostname(
        cls,
        url: str
    ) -> Optional[str]:
        try:
            parsed = urlparse(url)

            if parsed.hostname:
                return parsed.hostname

        except (
            ValueError,
            TypeError
        ):
            pass

        return None

    @classmethod
    def _is_dns_url(
        cls,
        url: str
    ) -> bool:
        try:
            parsed = urlparse(url)

            if (
                parsed.scheme.lower()
                not in (
                    "https",
                    "http"
                )
                or not parsed.hostname
            ):
                return False

            host = parsed.hostname.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()

            if any(
                dns_host == host
                or host.endswith("." + dns_host)
                for dns_host in cls.DNS_HOSTS
            ):
                return True

            if any(
                dns_path in path
                for dns_path in cls.DNS_PATHS
            ):
                return True

            if (
                "dns" in query
                or "dns" in path
                or "doh" in host
            ):
                return True

            return False

        except (
            ValueError,
            TypeError
        ):
            return False

    @classmethod
    def _is_http_url(
        cls,
        url: str
    ) -> bool:
        try:
            parsed = urlparse(url)

            return (
                parsed.scheme.lower()
                in (
                    "https",
                    "http"
                )
                and bool(parsed.hostname)
            )

        except (
            ValueError,
            TypeError
        ):
            return False

    @classmethod
    def _contains_url(
        cls,
        text: str
    ) -> bool:
        return bool(
            cls.URL_PATTERN.search(text)
        )

    @classmethod
    def _contains_dot_port(
        cls,
        text: str
    ) -> bool:
        return bool(
            cls.DOT_HOST_PATTERN.search(text)
        )

    @classmethod
    def _is_ui_value(
        cls,
        text: str
    ) -> bool:
        normalized = re.sub(
            r"\s+",
            "",
            str(text or "")
        )

        return bool(
            normalized
            and cls.PROVIDER_NOISE.fullmatch(
                normalized
            )
        )

    @classmethod
    def _clean_url(
        cls,
        url: str
    ) -> str:
        return str(url).strip().rstrip(
            ".,;:)]}\"'"
        )

    @classmethod
    def _normalize_url(
        cls,
        url: str
    ) -> str:
        try:
            parsed = urlparse(url)

            scheme = parsed.scheme.lower()

            hostname = (
                parsed.hostname or ""
            ).lower()

            netloc = hostname

            if parsed.port is not None:
                netloc = f"{hostname}:{parsed.port}"

            path = (
                parsed.path
                or "/dns-query"
            )

            return (
                f"{scheme}://"
                f"{netloc}"
                f"{path}"
                f"?{parsed.query}"
            ).rstrip("?")

        except (
            ValueError,
            TypeError
        ):
            return str(
                url
            ).lower().rstrip("/")

    @classmethod
    def _clean_text(
        cls,
        text: str
    ) -> str:
        text = str(text or "")

        text = re.sub(
            r"\s+",
            " ",
            text
        )

        return text.strip()

    @classmethod
    def _clean_provider(
        cls,
        provider: str
    ) -> str:
        provider = cls._clean_text(provider)

        provider = re.sub(
            r"https?://\S+",
            "",
            provider,
            flags=re.IGNORECASE
        )

        provider = cls.PROVIDER_NOISE.sub(
            " ",
            provider
        )

        provider = re.sub(
            r"\s+",
            " ",
            provider
        ).strip()

        return provider
