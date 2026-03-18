import argparse
import json
import pprint
from services.rdapdomain import RDAPClient
from utils.io import load_input

def parse_args():
    parser = argparse.ArgumentParser(
        description="RDAP Query - Retrieve domain registration data using RDAP protocol"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Single domain to query")
    parser.add_argument("input", action="store_true")
    parser.add_argument("--rdap", action="store_true")
    parser.add_argument("--all", action="store_true")
    group.add_argument("-f", "--file", help="File containing domains (one per line)")
    parser.add_argument("-o", "--output", help="Output to CSV file")

    return parser.parse_args()

def main():
    args = parse_args()
    # Process based on input type
    if args.domain:
        # Query a single domain
        client = RDAPClient()
        results: list[dict] = [client.lookup(args.domain)]
        pprint.pprint(results)

    else:
        # Process domains from file
        client = RDAPClient()
        with open(args.file, mode="r", encoding="utf-8") as txtfile:
            data: list = [line.strip() for line in txtfile if line.strip()]
       
        results: list[dict] = [client.lookup(domain=i) for i in data]
        pprint.pprint(results)

    if args.output:
        write_to_csv(results, args.output)



if __name__ == "__main__":
    main()
