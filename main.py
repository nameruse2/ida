import argparse
import json
import pprint
import ipaddress
from services.rdapdomain import RDAPDomainClient
from services.rdapip import RDAPIPClient
from services.asn import cymru
from utils.io import load_input

def parse_args():
    parser = argparse.ArgumentParser(
        description="IDA - IP and Domain analysis"
    )

    parser.add_argument("input")
    parser.add_argument("--rdap", action="store_true")
    parser.add_argument("--asn", action="store_true")
    parser.add_argument("--all", action="store_true")

    parser.add_argument("-o", "--output", help="Output to CSV file")

    return parser.parse_args()


def resolve_features(args):
    if args.all:
        return ["rdap", "asn", "dns", "ip", "tor"]

    selected = []
    if args.rdap:
        selected.append("rdap")
    if args.asn:
        selected.append("asn")

    return selected or ["rdap"]  # default


def main():
    args = parse_args()
    features = resolve_features(args)
    selectors = load_input(args.input)
    results = []

    try:
        ipaddress.ip_address(selectors[0])
        rdap = RDAPIPClient()
        identity = "ip"
    except ValueError:
        rdap = RDAPDomainClient()
        identity = "domain"
        
    for item in selectors:
        row = {"domain": item}

        if "rdap" in features:
            row.update(rdap.lookup(item))

        if "asn" in features and identity == "ip":
            row.update(cymru(item))
            
        results.append(row)

    for r in results:
        pprint.pprint(r)

    # if args.csv:
        # save_csv(results, args.csv)



if __name__ == "__main__":
    main()
