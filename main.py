import argparse
import json
import pprint
import ipaddress
from services.rdapdomain import RDAPDomainClient
from services.rdapip import RDAPIPClient
from utils.io import load_input

def parse_args():
    parser = argparse.ArgumentParser(
        description="IDA - IP and Domain analysis"
    )

    parser.add_argument("input")
    parser.add_argument("--rdap", action="store_true")
    parser.add_argument("--all", action="store_true")

    parser.add_argument("-o", "--output", help="Output to CSV file")

    return parser.parse_args()


def resolve_features(args):
    if args.all:
        return ["rdap", "dns", "ip", "tor"]

    selected = []
    if args.rdap:
        selected.append("rdap")

    return selected or ["rdap"]  # default


def main():
    args = parse_args()
    features = resolve_features(args)
    selectors = load_input(args.input)
    results = []

    try:
        ipaddress.ip_address(selectors[0])
        rdap = RDAPIPClient()
    except ValueError:
        rdap = RDAPDomainClient()

    for domain in selectors:
        row = {"domain": domain}

        if "rdap" in features:
            row.update(rdap.lookup(domain))

        results.append(row)

    for r in results:
        pprint.pprint(r)

    # if args.csv:
        # save_csv(results, args.csv)



if __name__ == "__main__":
    main()
