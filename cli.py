import argparse
import json

from gen import gen_reproduce, scan_version
from pprint import pprint


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.formatter_class = argparse.RawTextHelpFormatter
    parser.description = "A CLI interface for vulhub"
    subparsers = parser.add_subparsers(
        dest="command", help="commands to run", required=True
    )

    reproduce = subparsers.add_parser("reproduce", help="reproduce a vulnerability")
    reproduce.add_argument("-C", "--CVE", help="the CVE to reproduce", required=True)


    scan = subparsers.add_parser("scan", help="scan the vulnerability version")
    scan.add_argument("-C", "--CVE", help="the CVE to scan", required=True)
    # customizing the scan target
    # eg. some distro only support some versions
    scan.add_argument(
        "-t",
        help="specify the tag to scan, None means scan all available tags",
        default=None,
        dest="tags",
        action="append",
    )

    args = parser.parse_args()
    if args.command == "reproduce":
        with open(f"./user_cve/{args.CVE}.json", "r") as f:
            schema = json.loads(f.read())
        dockerfile = gen_reproduce(schema)
        with open(f"./Dockerfile/{args.CVE}", "w") as f:
            f.write(dockerfile)
    elif args.command == "scan":
        with open(f"./user_cve/{args.CVE}.json", "r") as f:
            schema = json.loads(f.read())

        if args.tags is None:
            scan_version(schema)
        else:
            scan_version(schema, args.tags)