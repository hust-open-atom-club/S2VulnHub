import subprocess
import time
import docker
import git

from rich.console import Console

from info_cmd import list_tags
from repro_cmd import gen_user_reproduce, gen_kernel_reproduce
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


def build_bzImage(container, commit_id: str) -> bool:
    """
    run build.sh to build bzImage in container and copy it to root dir

    print building log

    Args:
        container (_type_): kernel container
        commit_id (str): build bzImage for which commit

    Returns:
        bool: if build success
    """
    commands = [
        "cp build.sh linux",
        "cd /root/linux",
        "git config --global --add safe.directory /root/linux",  # fatal: detected dubious ownership in repository at '/root/linux'
        f"git checkout {commit_id}",
        "bash build.sh",
    ]

    full_command = " && ".join(commands)
    build_log = container.exec_run(f"/bin/bash -c '{full_command}'", stream=True)

    # block till build finish
    for line in build_log.output:
        print(line.decode("utf-8"), end="")
        if "Kernel: arch/x86/boot/bzImage is ready" in line.decode("utf-8"):
            container.exec_run("cp /root/linux/arch/x86_64/boot/bzImage /root")
            return True
    logger.warning("build bzImage failed")
    return False


def kernel_build_and_run(
    vuln_schema: dict, commit_id: str = None, linux_path: str = None
) -> bool:
    """
    build docker image (-> build kernel bzImage) -> start vm -> run poc

    Args:
        vuln_schema (dict): bug json file
        commit_id (str, optional): Required if no existing bzImage.
        linux_path (str, optional): Required if no existing bzImage. local linux source code path.

    Returns:
        bool: if the commit or package is vulnerable. True means vulnerable.
    """
    if not check_docker_permission():
        add_user_to_docker_group()
        exit(1)

    if commit_id and "configfile" not in vuln_schema["trigger"]:
        logger.warning(
            "specify commit id is not supported for this vulnerability since configfile is not provided"
        )
        exit(1)

    # generate dockerfile and build docker image
    out_file = gen_kernel_reproduce(vuln_schema, True if commit_id else False)
    with open("../data/kernel_dockerfile/Dockerfile", "w") as f:
        f.write(out_file)
    build_ret = subprocess.run(
        ["docker", "build", "-t", "testrepo", "."],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd="../data/kernel_dockerfile",
    )
    if build_ret.returncode != 0:
        logger.warning("docker build failed")
        logger.warning("\n".join(build_ret.stderr.split("\n")[-30:]))
        exit(1)

    # start container and get the container
    if commit_id or "bzImage" not in vuln_schema["trigger"]:
        if not linux_path:
            raise Exception(
                "please use -kpath {dir} to set local linux source code path"
            )
        subprocess.Popen(
            f"docker run -i --device=/dev/kvm --rm -v {linux_path}:/root/linux:Z testrepo",
            shell=True,
        )
    else:
        subprocess.Popen(
            f"docker run -i --device=/dev/kvm --rm testrepo",
            shell=True,
        )

    time.sleep(1)  # wait a little for docker start
    client = docker.from_env()
    containers = client.containers.list(all=True)
    for c in containers:
        if "testrepo" in c.image.tags[0]:
            kernel_container = c
            break

    # build bzImage from local source code if necessary
    if commit_id or "bzImage" not in vuln_schema["trigger"]:
        logger.info("building bzImage in docker...")
        if not build_bzImage(kernel_container, commit_id):
            exit(1)

    logger.info("starting qemu in docker...")
    # if tty = False, line will not be a complete line
    # lead to docker log empty
    vm_log = kernel_container.exec_run("./startvm", stream=True, tty=True)
    # XXX: 每个漏洞的err_msg不一样
    err_msg = "BUG: "
    for line in vm_log.output:
        decode_line = line.decode("utf-8", errors="ignore")
        # logger.info(decode_line)
        print(decode_line, end="")
        # XXX: 输出有可能被截断导致字符串检测失败
        if "login:" in decode_line:
            logger.info("running poc...")
            # TODO: use docker-py
            subprocess.Popen(
                "docker exec -it `docker ps -a --filter ancestor=testrepo -q | head -n 1` bash trigger.sh",
                shell=True,
            )
            time.sleep(5)  # wait a little to print more crash info
        # TODO: how to test if kernel is not vulnerable
        if err_msg in decode_line:
            logger.info("This version is vulnerable")
            kernel_container.stop()
            return True


def kernel_scan_version(
    vuln_schema: dict, target_tags: list = None, linux_path: str = None
):
    """
    scan target_tags of a git repo

    scan the given package in CVE schema

    show result in console

    Args:
        vuln_schema (dict): CVE json file
        target_tags (list, optional): tag name list. Defaults to None. None means scan all tags.
        linux_path (str, optional): Local linux source code path.
    """

    def if_commit_valid(commit_id: str) -> bool:
        repo = git.Repo(linux_path)
        try:
            repo.commit(vuln_schema["version"])
        except git.exc.BadName:
            logger.warning(
                f'Commit {vuln_schema["version"]} does not exist in local repo'
            )
            exit(1)
        return True

    if not target_tags:
        if_commit_valid(vuln_schema["version"])
        vul_status = kernel_build_and_run(vuln_schema, None, linux_path)
    else:
        for tag in target_tags:
            if_commit_valid(tag)
            vul_status = kernel_build_and_run(vuln_schema, tag, linux_path)
            if vul_status:
                logger.info(f"version {tag} is vulnerable")
            else:
                logger.info(f"version {tag} is safe")
