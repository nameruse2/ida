import dns.resolver


def _query(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [r.to_text() for r in answers]
    except Exception:
        return []


def dns_lookup(domain):
    return {
        "A": _query(domain, "A"),
        "AAAA": _query(domain, "AAAA"),
        "CNAME": _query(domain, "CNAME"),
        "TXT": _query(domain, "TXT"),
        "MX": _query(domain, "MX"),
        "NS": _query(domain, "NS"),
        "SOA": _query(domain, "SOA"),
    }
