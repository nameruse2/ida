import requests
import json

def ipThcRdns(ip_address):
    """
    Return a set of domains hosted on a given IP address
    """
    url = "https://ip.thc.org/api/v1/lookup"
    payload = {"ip_address": ip_address}
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    response = requests.post(url, json=payload, headers=headers).json()

    return set(i['domain'] for i in response['domains'])

def ipThcSubdomain(domain):
    url = "https://ip.thc.org/api/v1/lookup/subdomains"
    payload = json.dumps({ "domain": "hector.su",})
    headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    return response.json()['domains']
    
print(ipThcSubdomain("hector.su"))
