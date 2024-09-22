#!/bin/env python3

import argparse
import json
from pprint import pprint

from info_cmd import get_build_arch, get_depend, get_raw, list_tags
from repro_cmd import gen_kernel_reproduce, gen_user_reproduce, get_template
from scan_cmd import scan_version, kernel_scan_version
from utils import logger
from validate_cmd import validate_software, validate_vuln

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.formatter_class = argparse.RawTextHelpFormatter
    parser.description = "A CLI interface for vulhub"
    subparsers = parser.add_subparsers(
        dest="command", help="commands to run", required=True
    )

    # subcommand reproduce
    reproduce = subparsers.add_parser(
        "reproduce", help="generate Dockerfile for a vulnerability"
    )
    reproduce.add_argument("CVE", help="the CVE to generate Dockerfile")
    reproduce.add_argument(
        "-k", "--kernel", action="store_true", help="generate kernel Dockerfile"
    )

    # subcommand scan
    scan = subparsers.add_parser("scan", help="scan if the app version is vulnerable")
    scan.add_argument("CVE", help="the CVE to scan")
    # customizing the scan target
    # eg. some distro only support some versions
    scan.add_argument(
        "-t",
        help="specify the tag to scan, None means scan all available tags",
        default=None,
        dest="target_tags",
        action="append",
    )

    scan.add_argument(
        "-k", "--kernel", action="store_true", help="scan Linux kernel vulnerability"
    )

    scan.add_argument(
        "-p",
        "--path",
        dest="kpath",
        help="local linux source code path, required if no bzImage",
    )
    # subcommand info
    info = subparsers.add_parser(
        "info",
        help="get software build and depend info, print raw info if no option is specified",
    )
    info.add_argument("app", help="app name")
    info.add_argument("--raw", action="store_true", help="get raw info")
    info.add_argument("--building", action="store_true", help="get build info")
    info.add_argument("--dependency", action="store_true", help="get dependency info")
    info.add_argument("--tags", action="store_true", help="get all app repo tags")

    # subcommand validate
    validate = subparsers.add_parser(
        "validate", help="validate the vulnerability and software schema"
    )
    validate.add_argument(
        "-c", "--CVE", help="the CVE id to validate", default=None, dest="CVE"
    )
    validate.add_argument(
        "-a", "--app", help="the app name to validate", default=None, dest="app"
    )

    # parse the args
    args = parser.parse_args()
    if args.command == "reproduce":
        if args.kernel:
            vuln_schema_dir = "../data/kernel_bug/"
            dockerfile_dir = "../data/kernel_dockerfile/"
        else:
            vuln_schema_dir = "../data/user_cve/"
            dockerfile_dir = "../data/user_dockerfile/"
        try:
            with open(vuln_schema_dir + f"{args.CVE}.json", "r") as f:
                schema = json.loads(f.read())
            if args.kernel:
                dockerfile = gen_kernel_reproduce(schema)
            else:
                dockerfile = gen_user_reproduce(schema)
            with open(dockerfile_dir + f"{args.CVE}", "w") as f:
                f.write(dockerfile)
        except FileNotFoundError as e:
            logger.error(e)

    elif args.command == "scan":
        if args.kernel:
            with open(f"../data/kernel_bug/{args.CVE}.json", "r") as f:
                schema = json.loads(f.read())
            # TODO: 检查 path 是否合法
            kernel_scan_version(
                schema, args.target_tags if args.target_tags else None, args.kpath
            )

        else:
            with open(f"../data/user_cve/{args.CVE}.json", "r") as f:
                schema = json.loads(f.read())
            scan_version(schema, args.target_tags if args.target_tags else None)
    elif args.command == "info":
        if args.raw:
            get_raw(args.app)
        elif args.building:
            get_build_arch(args.app)
        elif args.dependency:
            get_depend(args.app)
        elif args.tags:
            with open(f"../data/apps/{args.app}.json", "r") as f:
                schema = json.loads(f.read())
            pprint(
                list_tags(
                    f'https://github.com/{schema["software"]["user"]}/{schema["software"]["repo"]}'
                )
            )
        else:
            get_raw(args.app)
    elif args.command == "validate":
        if args.CVE is not None:
            try:
                with open(f"../data/user_cve/{args.CVE}.json", "r") as f:
                    schema = json.loads(f.read())
            except Exception as e:
                logger.warning(e)
                exit(1)
            validate_vuln(schema)
        if args.app is not None:
            app_template = get_template(args.app)
            validate_software(app_template)
