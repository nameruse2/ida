import requests
import ipaddress


class RDAPIPClient:
    IPV4_BOOTSTRAP_URL = "https://data.iana.org/rdap/ipv4.json"
    IPV6_BOOTSTRAP_URL = "https://data.iana.org/rdap/ipv6.json"

    def __init__(self):
        self.session = requests.Session()
        self.bootstrap_v4 = self._load_bootstrap(self.IPV4_BOOTSTRAP_URL)
        self.bootstrap_v6 = self._load_bootstrap(self.IPV6_BOOTSTRAP_URL)
        self.rdap_map = self._build_rdap_map()

    def _load_bootstrap(self, url: str) -> dict:
        try:
            r = self.session.get(url, timeout=10)
            r.raise_for_status()
            return r.json()
        except requests.Timeout:
            raise RuntimeError("RDAP request timed out")
        except requests.RequestException as e:
            raise RuntimeError(f"RDAP request failed: {e}")

    def _build_rdap_map(self) -> list:
        """
        Build a list of RDAP mappings.
        Each entry is either:
          - (ip_network, rdap_url)
          - (start_ip, end_ip, rdap_url)
        """
        rdap_ranges = []

        for bootstrap in (self.bootstrap_v4, self.bootstrap_v6):
            for service in bootstrap.get("services", []):
                ranges = service[0]
                urls = service[1]
                if not urls:
                    continue

                for entry in ranges:
                    # CIDR block
                    if "/" in entry:
                        network = ipaddress.ip_network(entry, strict=False)
                        rdap_ranges.append((network, urls[0]))

                    # Explicit range
                    elif "-" in entry:
                        start, end = entry.split("-")
                        rdap_ranges.append((
                            ipaddress.ip_address(start),
                            ipaddress.ip_address(end),
                            urls[0],
                        ))

        return rdap_ranges

    def _find_rdap_url(self, ip: str) -> str | None:
        ip_obj = ipaddress.ip_address(ip)

        for entry in self.rdap_map:
            # CIDR case
            if isinstance(entry[0], ipaddress._BaseNetwork):
                network, url = entry
                if ip_obj in network:
                    return url

            # Range case
            else:
                start, end, url = entry
                if start <= ip_obj <= end:
                    return url

        print(f"[DEBUG] No RDAP match for IP: {ip}")
        return None

    def _fetch_rdap(self, ip: str) -> dict | None:
        rdap_url = self._find_rdap_url(ip)
        if not rdap_url:
            return None

        url = f"{rdap_url.rstrip('/')}/ip/{ip}"
        print(f"[DEBUG] RDAP URL: {url}")

        try:
            r = self.session.get(url, timeout=10)
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r.json()
        except requests.RequestException as e:
            print(f"[DEBUG] Request failed: {e}")
            return None

    def _parse_rdap(self, ip: str, rdap_json: dict) -> dict:
        data = {
            "ip": ip,
            "network": rdap_json.get("handle", ""),
            "name": rdap_json.get("name", ""),
            "type": rdap_json.get("type", ""),
            "country": rdap_json.get("country", ""),
            "status": rdap_json.get("status", []),
            "start_address": rdap_json.get("startAddress", ""),
            "end_address": rdap_json.get("endAddress", ""),
            "cidr": [],
            "entities": [],
        }

        # CIDR blocks
        for c in rdap_json.get("cidr0_cidrs", []):
            prefix = c.get("v4prefix") or c.get("v6prefix")
            length = c.get("length")
            if prefix and length is not None:
                data["cidr"].append(f"{prefix}/{length}")

        # Entities (org, abuse, etc.)
        for entity in rdap_json.get("entities", []):
            roles = entity.get("roles", [])
            name = ""

            vcard = entity.get("vcardArray", [])
            if isinstance(vcard, list) and len(vcard) == 2:
                for item in vcard[1]:
                    if item[0] == "fn":
                        name = item[3]
                        break

            data["entities"].append({
                "roles": roles,
                "name": name,
            })

        return data

    def lookup(self, ip: str) -> dict:
        try:
            rdap_json = self._fetch_rdap(ip)
        except ValueError:
            return {"ip": ip, "error": "Invalid IP address"}

        if not rdap_json:
            return {"ip": ip, "error": "RDAP lookup failed"}

        return self._parse_rdap(ip, rdap_json)
