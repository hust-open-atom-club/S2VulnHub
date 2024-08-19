import argparse
import json
from pprint import pprint

from gen import gen_reproduce, scan_version
from info_gen import get_build_arch, get_depend, get_raw
from inspect_gen import list_all_tags_for_remote_git_repo

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

    inspect = subparsers.add_parser("inspect", help="list app repo tags")
    inspect.add_argument("-A", "--app", help="app name", required=True)

    info = subparsers.add_parser("info", help="get build and depend info")
    info.add_argument("-A", "--app", help="app name", required=True)
    info.add_argument("--raw", action="store_true", help="get raw info")
    info.add_argument("--building", action="store_true", help="get build info")
    info.add_argument("--dependency", action="store_true", help="get dependency info")

    args = parser.parse_args()
    if args.command == "reproduce":
        with open(f"../data/user_cve/{args.CVE}.json", "r") as f:
            schema = json.loads(f.read())
        dockerfile = gen_reproduce(schema)
        with open(f"../data/user_dockerfile/{args.CVE}", "w") as f:
            f.write(dockerfile)
    elif args.command == "scan":
        with open(f"../data/user_cve/{args.CVE}.json", "r") as f:
            schema = json.loads(f.read())

        if args.tags is None:
            scan_version(schema)
        else:
            scan_version(schema, args.tags)
    elif args.command == "inspect":
        with open(f"../data/apps/{args.app}.json", "r") as f:
            schema = json.loads(f.read())
        pprint(
            list_all_tags_for_remote_git_repo(
                f'https://github.com/{schema["software"]["user"]}/{schema["software"]["repo"]}'
            )
        )
    elif args.command == "info":
        if args.raw:
            get_raw(args.app)
        elif args.building:
            get_build_arch(args.app)
        elif args.dependency:
            get_depend(args.app)
        else:
            get_raw(args.app)
