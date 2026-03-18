import requests

class RDAPDomainClient:
    BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
    def __init__(self):
        self.session = requests.Session()
        self.bootstrap: dict = self._load_bootstrap()
        self.rdap_map:dict = self._build_rdap_map()


    def _load_bootstrap(self) -> dict:
        """
        Get the bootstrap data from the BOOTSTRAP_URL 
        """
        try:
            r = self.session.get(self.BOOTSTRAP_URL, timeout=10)
            r.raise_for_status()
            return r.json()
        except requests.Timeout:
            raise RuntimeError("RDAP request timed out")
        except requests.RequestException as e:
            raise RuntimeError(f"RDAP request failed: {e}")


    def _build_rdap_map(self) -> dict:
        '''
        Builds a dict of data from the bootstrap in format TLD:URL.
        '''        
        rdap_map: dict = {}
        for service in self.bootstrap.get("services", []):
            tlds: str = service[0]
            urls: str = service[1]
            if not urls:
                continue
            for tld in tlds:
                rdap_map[tld] = urls[0]
        return rdap_map


    def _fetch_rdap(self, domain: str) -> dict | None:
        """
        Fetches an RDAP object for a domain.    
        """
        tld: str = domain.split(".")[-1].lower()
        # tld: str = tldextract.extract(domain).suffix
        rdap_url: str|None = self.rdap_map.get(tld)
        if not rdap_url:
            return None
        url = f"{rdap_url.rstrip('/')}/domain/{domain}"
        try:
            r = self.session.get(url, timeout=10)
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r.json()
        except requests.RequestException:
            return None


    def _parse_rdap(self, domain: str, rdap_json: dict) -> dict:
        """
        Parse the RDAP data that has been fetched. 
        """
        data: dict = {
            "domain": domain,
            "registrar": "",
            "status": rdap_json.get("status", []),
            "expiration_date": "",
            "last_changed_date": "",
            "registration_date": "",
            "nameservers": "",
        }

        events: dict = {
            e.get("eventAction"): e.get("eventDate")
            for e in rdap_json.get("events", [])
        }

        data["expiration_date"] = events.get("expiration", "")
        data["last_changed_date"] = events.get("last changed", "")
        data["registration_date"] = events.get("registration", "")

        for entity in rdap_json.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [])
                if len(vcard) == 2:
                    for item in vcard[1]:
                        if item[0] == "fn":
                            data["registrar"] = item[3]
                            break
                        
        nameservers = []
        for ns in rdap_json.get("nameservers", []):
            if isinstance(ns, dict):
                name = ns.get("ldhName") or ns.get("handle") or ns.get("name")
                if name:
                    nameservers.append(name.lower())
            elif isinstance(ns, str):
                nameservers.append(ns.lower())

        # optionally dedupe & sort
        nameservers = sorted(set(nameservers))
        data["nameservers"] = nameservers

        return data

    
    def lookup(self, domain: str) -> dict:
        rdap_json: dict|None = self._fetch_rdap(domain)
        if not rdap_json:
            return {"domain": domain, "error": "RDAP lookup failed"}
        return self._parse_rdap(domain, rdap_json)
