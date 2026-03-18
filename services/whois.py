
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
