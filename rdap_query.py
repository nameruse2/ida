#!/usr/bin/env -S uv run --script

# /// script
# requires-python = ">=3.13"
# dependencies = ["requests", "whois"]
# ///

"""
Description: RDAP Query - A tool to query Registration Data Access Protocol (RDAP) for domain information. Falls back on WHOIS.
RDAP is a more structured replacement for the traditional WHOIS protocol.
"""

import json
import csv
import argparse
import requests
import whois
from pprint import pprint


def write_to_csv(dict_list: dict, filename: str):
    """
    Output the extracted information to a CSV file.
    Args:
        dict_list (list): List of dictionaries containing extracted information
        filename (str): The name of the output CSV file
    Returns:
        dict: Extracted information in a structured format
    """
    if not dict_list:
        print("The list is empty. No CSV file created.")
        return

    # Get the fieldnames from the keys of the first dictionary
    fieldnames = dict_list[0].keys()

    try:
        with open(filename, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(dict_list)
        print(f"CSV file '{filename}' written successfully.")
    except Exception as e:
        print(f"Error writing CSV file: {e}")


def get_whois_info(domain):
    """
    Get WHOIS information for a domain using python-whois.

    Args:
        domain (str): The domain name to look up

    Returns:
        dict: Dictionary containing WHOIS information
    """
    try:
        # Get WHOIS information
        w = whois.whois(domain)
        # Extract relevant information
        whois_info = {
            "domain": domain,
            "Errors": "",
            "registrar": "",
            "status": "",
            "expiration_date": "",
            "last_changed_date": "",
            "registration_date": "",
        }

        # Extract registrar information
        if hasattr(w, "registrar") and w.registrar:
            whois_info["registrar"] = w.registrar

        # Extract dates
        if hasattr(w, "creation_date") and w.creation_date:
            if isinstance(w.creation_date, list):
                whois_info["registration_date"] = str(w.creation_date[0])
            else:
                whois_info["registration_date"] = str(w.creation_date)

        if hasattr(w, "updated_date") and w.updated_date:
            if isinstance(w.updated_date, list):
                whois_info["last_changed_date"] = str(w.updated_date[0])
            else:
                whois_info["last_changed_date"] = str(w.updated_date)

        if hasattr(w, "expiration_date") and w.expiration_date:
            if isinstance(w.expiration_date, list):
                whois_info["expiration_date"] = str(w.expiration_date[0])
            else:
                whois_info["expiration_date"] = str(w.expiration_date)

        # Extract status
        if hasattr(w, "status") and w.status:
            if isinstance(w.status, list):
                whois_info["status"] = ", ".join(w.status)
            else:
                whois_info["status"] = w.status

        return whois_info
    except Exception as e:
        print(f"Error getting WHOIS information for {domain}: {e}")
        return {"domain": domain, "error": str(e)}


class RDAPClient:
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
        return data

    
    def lookup(self, domain: str) -> dict:
        rdap_json: dict|None = self._fetch_rdap(domain)
        if not rdap_json:
            return {"domain": domain, "error": "RDAP lookup failed"}
        return self._parse_rdap(domain, rdap_json)
    
def main():
    parser = argparse.ArgumentParser(
        description="RDAP Query - Retrieve domain registration data using RDAP protocol"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Single domain to query")
    group.add_argument("-f", "--file", help="File containing domains (one per line)")
    parser.add_argument("-o", "--output", help="Output to CSV file")

    args = parser.parse_args()

    # Process based on input type
    if args.domain:
        # Query a single domain
        client = RDAPClient()
        results: list[dict] = [client.lookup(args.domain)]
        pprint(results)

    else:
        # Process domains from file
        client = RDAPClient()
        with open(args.file, mode="r", encoding="utf-8") as txtfile:
            data: list = [line.strip() for line in txtfile if line.strip()]
       
        results: list[dict] = [client.lookup(domain=i) for i in data]
        pprint(results)

    if args.output:
        write_to_csv(results, args.output)


if __name__ == "__main__":
    main()
