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


def build_and_run(vuln_schema: dict, commit_tag: list = None) -> bool:
    """
    build and run the CVE docker image

    Args:
        vuln_schema (dict): CVE json file
        commit_tag (list, optional): [commit, tag]. required for git repo. Defaults to None for released package.

    Returns:
        bool: if the commit or package is vulnerable. True means vulnerable.
    """
    if not check_docker_permission():
        add_user_to_docker_group()
        exit(1)

    if commit_tag:
        vuln_schema["version"] = commit_tag[0]
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


def scan_version(vuln_schema: dict, target_tags: list = None):
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
    if app_template["software"]["source"] == "tarball":
        logger.info(
            f'This software source is tarball, only the package in {vuln_schema["category"]}.json will be scanned and -t option will be ignored'
        )
        with console.status(
            f'[bold blue]reproducing {vuln_schema["id"]} in {vuln_schema["category"]}...'
        ) as status:
            vul_status = build_and_run(vuln_schema)
            if vul_status:
                console.log(f"[bold red]:pile_of_poo: package is vulnerable")
            else:
                console.log(f"[green]:thumbs_up: package is safe")
            return

    all_tags = list_tags(
        f'https://github.com/{app_template["software"]["user"]}/{app_template["software"]["repo"]}'
    )
    all_tags.reverse()
    ultimate_tags = []
    for tag in all_tags:
        if target_tags is None or tag[1] in target_tags:
            ultimate_tags.append(tag)

    ultimate_tags_idx = 0
    with console.status(
        f'[bold blue]reproducing {app_template["software"]["user"]}/{app_template["software"]["repo"]} version {ultimate_tags[ultimate_tags_idx][1]}...'
    ) as status:
        for tag in ultimate_tags:
            vul_status = build_and_run(vuln_schema, tag)
            if vul_status:
                console.log(f"[bold red]:pile_of_poo: {tag[1]} is vulnerable")
            else:
                console.log(f"[green]:thumbs_up: {tag[1]} is safe")
            ultimate_tags_idx += 1
            if ultimate_tags_idx == len(ultimate_tags):
                break
            status.update(
                f'[bold blue]reproducing {app_template["software"]["user"]}/{app_template["software"]["repo"]} version {ultimate_tags[ultimate_tags_idx][1]}...'
            )
