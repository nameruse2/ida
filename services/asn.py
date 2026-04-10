import dns.resolver
import ipaddress

def ip_version(ip: str) -> int:
    return ipaddress.ip_address(ip).version


def cymru_ipv4_to_asn(ip: str) -> str:
    reversed_ip = ".".join(reversed(ip.split(".")))
    query = f"{reversed_ip}.origin.asn.cymru.com"
    answer = dns.resolver.resolve(query, "TXT")[0]
    txt = answer.to_text().strip('"')
    parts = txt.split(" | ")
    return f"AS{parts[0]}"


def cymru_ipv6_to_asn(ip: str):
    expanded = ipaddress.ip_address(ip).exploded.replace(":", "")
    reversed_ip = ".".join(reversed(expanded))
    query = f"{reversed_ip}.origin6.asn.cymru.com"
    answer = dns.resolver.resolve(query, "TXT")[0]
    txt = answer.to_text().strip('"')
    parts = txt.split(" | ")
    return f"AS{parts[0]}"


def cymru_asn(asn: str) -> dict:
    query = f"{asn}.asn.cymru.com"
    answer = dns.resolver.resolve(query, "TXT")[0]
    txt = answer.to_text().strip('"')
    parts = txt.split(" | ")

    return {
        "asn": int(parts[0]),
        "asn_country": parts[1],
        "asn_registry": parts[2],
        "asn_date": parts[3],
        "asn_allocated": parts[4],
    }


def cymru(ip):
    if ipaddress.ip_address(ip).version == 4:
        asn = cymru_ipv4_to_asn(ip)
    else:
        asn = cymru_ipv6_to_asn(ip)
    return cymru_asn(asn)
