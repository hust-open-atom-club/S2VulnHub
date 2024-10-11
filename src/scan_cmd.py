import subprocess

from rich.console import Console

from info_cmd import list_tags
from repro_cmd import gen_user_reproduce
from utils import (
    add_user_to_docker_group,
    check_docker_permission,
    get_template,
    logger,
)


def build_and_run(vuln_schema: dict, version: str = None) -> bool:
    """
    build and run the CVE docker image

    Args:
        vuln_schema (dict): CVE json file
        version (str, optional): Commit id required for git repo, version number optional for released package.

    Returns:
        bool: if the commit or package is vulnerable. True means vulnerable.
    """
    if not check_docker_permission():
        add_user_to_docker_group()
        exit(1)

    if version:
        # revise version info
        vuln_schema["version"] = version
    out_file = gen_user_reproduce(vuln_schema)
    out_file = out_file.replace('CMD ["/bin/bash"]', 'CMD ["bash", "trigger.sh"]')

    with open("../data/user_dockerfile/Dockerfile", "w") as f:
        f.write(out_file)

    build_ret = subprocess.run(
        ["docker", "build", "-t", "testrepo", "."],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd="../data/user_dockerfile",
    )
    if build_ret.returncode != 0:
        logger.warning("docker build failed")
        logger.warning("\n".join(build_ret.stderr.split("\n")[-30:]))
        exit(1)

    run_ret = subprocess.Popen(
        ["docker", "run", "--rm", "-i", "--ulimit", "cpu=10", "testrepo"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    run_ret.wait(500)  # wait a little for docker to complete
    errstr = run_ret.stderr.read()

    # returncode == 137 means exceed ulimit
    if (
        run_ret.returncode != 0
        and run_ret.returncode != 1
        and run_ret.returncode != 137
    ):
        return True
    elif run_ret.returncode == 1 and errstr.find("Sanitizer") != -1:
        return True
    else:
        return False


def scan_version(vuln_schema: dict, input_tags: list = None):
    """
    scan target_tags of a git repo

    scan the given package in CVE schema

    show result in console

    Args:
        vuln_schema (dict): CVE json file
        target_tags (list, optional): tag name list. Defaults to None. None means scan all tags.
    """
    console = Console()
    app_template = get_template(vuln_schema["category"])
    target_tags = []

    # get valid tags first
    if app_template["software"]["source"] == "tarball":
        _ = []
        all_tags = []
        for pkg in app_template["software"]["packages"]:
            if "version" in pkg:
                all_tags.append(pkg["version"])
        if not all_tags:
            _.append("default")
            logger.info("the package only has default version")
        elif input_tags:
            _ = list(set(all_tags) & set(input_tags))
        else:
            _ = all_tags
        target_tags = [[item, item] for item in _]
    else:
        all_tags = list_tags(
            f'https://github.com/{app_template["software"]["user"]}/{app_template["software"]["repo"]}'
        )
        all_tags.reverse()
        for tag in all_tags:
            if input_tags is None or tag[1] in input_tags:
                target_tags.append(tag)

    if not target_tags:
        logger.warning("no valid version to scan")
        return

    # scan valid tags
    i = 0
    with console.status(
        f'[bold blue]reproducing {vuln_schema["id"]} in {vuln_schema["category"]} version {target_tags[i][1]}...'
    ) as status:
        for i in range(len(target_tags)):
            vul_status = build_and_run(
                vuln_schema,
                None if target_tags[i][0] == "default" else target_tags[i][0],
            )
            if vul_status:
                console.log(
                    f'[bold red]:pile_of_poo: {vuln_schema["category"]} version {target_tags[i][1]} is vulnerable'
                )
            else:
                console.log(
                    f'[green]:thumbs_up: {vuln_schema["category"]} version {target_tags[i][1]} is safe'
                )

            if i + 1 < len(target_tags):
                status.update(
                    f'[bold blue]reproducing {vuln_schema["id"]} in {vuln_schema["category"]} version {target_tags[i+1][1]}...'
                )
