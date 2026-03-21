import dns.resolver


def _query(domain: str, record_type: str) -> list:
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers: list[str] = ['1.1.1.1']
        answers = resolver.resolve(domain, record_type)
        return [r.to_text() for r in answers]
    except Exception:
        return []


def dns_lookup(domain: str) -> dict:
    return {
        "A": _query(domain, "A"),
        "AAAA": _query(domain, "AAAA"),
        "CNAME": _query(domain, "CNAME"),
        "TXT": _query(domain, "TXT"),
        "MX": _query(domain, "MX"),
        "NS": _query(domain, "NS"),
        "SOA": _query(domain, "SOA"),
    }
