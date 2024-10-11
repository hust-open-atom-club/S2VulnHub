import os
import re
import subprocess
import time

import docker
import git
from rich.console import Console

from info_cmd import list_tags
from repro_cmd import gen_kernel_reproduce
from utils import (
    add_user_to_docker_group,
    check_docker_permission,
    get_template,
    logger,
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
        "cd /root/linux",
        # "git clean -fdx",
        "git config --global --add safe.directory /root/linux",  # fatal: detected dubious ownership in repository at '/root/linux'
        "cp ../build.sh .",
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


def read_vm_log(container) -> str:
    """read vm.log from container

    Args:
        container (_type_): kernel container

    Returns:
        str: content of vm.log
    """
    bits, _ = container.get_archive("/root/vm.log")
    with open("./tmp.tar", "wb") as f:
        for chunk in bits:
            f.write(chunk)
    subprocess.Popen(["tar", "-xf", "tmp.tar"])
    time.sleep(1)  # wait a little for tar finish

    with open("vm.log", "r") as f:
        content = f.read()
        return content


def check_bug(container) -> bool:
    """check if the kernel has bug by reading vm.log

    Args:
        container (_type_): kernel container

    Returns:
        bool: True means the kernel has bug
    """

    def compile_regex(pattern):
        pattern = pattern.replace("{{ADDR}}", "0x[0-9a-f]+")
        pattern = pattern.replace("{{PC}}", "\\[\\<?(?:0x)?[0-9a-f]+\\>?\\]")
        pattern = pattern.replace("{{FUNC}}", "([a-zA-Z0-9_]+)(?:\\.|\\+)")
        pattern = pattern.replace("{{SRC}}", "([a-zA-Z0-9-_/.]+\\.[a-z]+:[0-9]+)")
        return re.compile(pattern)

    patterns = [
        compile_regex(
            r"BUG: KASAN: ([a-z\\-]+) in {{FUNC}}(?:.*\\n)+?.*(Read|Write) (?:of size|at addr) (?:[0-9a-f]+)"
        ),
        compile_regex(
            r"BUG: KASAN: ([a-z\\-]+) in {{FUNC}}(?:.*\\n)+?.*(Read|Write) (?:of size|at addr) (?:[0-9a-f]+)"
        ),
        compile_regex(
            r"BUG: KASAN: (?:double-free or invalid-free|double-free|invalid-free) in {{FUNC}}"
        ),
        compile_regex(
            r"BUG: KASAN: ([a-z\\-]+) on address(?:.*\\n)+?.*(Read|Write) of size ([0-9]+)"
        ),
        compile_regex(r"BUG: KASAN: (.*)"),
        compile_regex(r"BUG: KASAN:	"),
        compile_regex(r"BUG: KMSAN: (.*)"),
        compile_regex(r"BUG: KFENCE: (.*)"),
        compile_regex(
            r"BUG: (?:unable to handle kernel NULL pointer dereference|kernel NULL pointer dereference|Kernel NULL pointer dereference)"
        ),
        compile_regex(r"KASAN: (.*)"),
        re.compile(r"BUG: KASAN: (.*)"),
        re.compile(r": Permission denied"),
        re.compile(
            r"^([a-zA-Z0-9_\-/.]+):[0-9]+:([0-9]+:)?.*(error|invalid|fatal|wrong)"
        ),
        re.compile(r"FAILED unresolved symbol"),
        re.compile(r"No rule to make target"),
        re.compile(r": not found"),
        re.compile(r": final link failed: "),
        re.compile(r"collect2: error: "),
        re.compile(r"(ERROR|FAILED): Build did NOT complete"),
        # WARNING: CPU: 0 PID: 6148 at net/sched/sch_qfq.c:1003 qfq_dequeue+0x3bc/0x790
        re.compile(
            r"WARNING: CPU: [0-9]+ PID: [0-9]+ at ([a-zA-Z0-9_\-/.]+):[0-9]+ ([a-zA-Z0-9_]+)\+0x[0-9a-f]+/0x[0-9a-f]+"
        ),
        # kernel BUG at net/core/skbuff.c:2812!
        re.compile(r"kernel BUG at ([a-zA-Z0-9_\-/.]+):[0-9]+"),
        re.compile(r"WARNING: possible circular locking dependency detected"),
        re.compile(r"UBSAN: array-index-out-of-bounds in"),
        re.compile(r"UBSAN: Undefined behaviour in"),
        re.compile(r"UBSAN:"),
        re.compile(r"BUG: .*stack guard page was hit at"),
        re.compile(r"WARNING: .*lib/debugobjects\\.c.* (?:debug_print|debug_check)"),
        # WARNING: possible circular locking dependency detected
        re.compile(r"WARNING: possible circular locking dependency detected"),
        re.compile(r"FAULT_INJECTION: forcing a failure"),
        re.compile(r"WARNING: held lock freed!"),
        re.compile(r": error: "),
        re.compile(r"Error: "),
        re.compile(r"ERROR: "),
        re.compile(r": fatal error: "),
        re.compile(r": undefined reference to"),
        re.compile(r": multiple definition of"),
    ]

    for i in range(20):
        # test if vm finish start every 2+1 seconds for 20 times
        time.sleep(2)
        try:
            content = read_vm_log(container)
            for pattern in patterns:
                res = pattern.search(content)
                if res:
                    return True
        except FileNotFoundError:
            return False
    return False


def kernel_build_and_run(
    vuln_schema: dict, commit_id: str = None, linux_path: str = None
) -> bool:
    """
    build docker image (-> build kernel bzImage) -> start vm -> run poc

    Args:
        vuln_schema (dict): bug json file
        commit_id (str, optional): None means use existing bzImage.
        linux_path (str, optional): Required if commit_id is not None. local linux source code path.

    Returns:
        bool: if the commit or package is vulnerable. True means vulnerable.
    """

    def check_parameters(vuln_schema: dict, commit_id: str, kpath: str) -> bool:
        """
        check if given linux source code path exists and if commit_id is valid in the repo

        check if bzImage or version and configfile is provided

        Args:
            commit_id (str): commit id
            kpath (str): linux source code path

        Returns:
            bool: if pass check
        """
        if not commit_id:
            if "bzImage" in vuln_schema["trigger"]:
                return True
            else:
                raise Exception("please provide bzImage or version and configfile")

        if "configfile" not in vuln_schema["trigger"]:
            raise Exception(
                "specify commit id is not supported for this vulnerability since configfile is not provided"
            )
        if not kpath:
            raise Exception(
                "please use -kpath {dir} to set local linux source code path"
            )
        if not os.path.exists(kpath):
            raise Exception("local linux source code path does not exist")

        repo = git.Repo(kpath)
        try:
            repo.commit(commit_id)
        except git.exc.BadName:
            logger.warning(f"Commit {commit_id} does not exist in local repo")
            exit(1)
        return True

    # do some check
    check_parameters(vuln_schema, commit_id, linux_path)
    if not check_docker_permission():
        add_user_to_docker_group()
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
    if commit_id:
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
    if commit_id:
        logger.info("building bzImage in docker...")
        if not build_bzImage(kernel_container, commit_id):
            exit(1)

    logger.info("starting qemu in docker...")
    # lead to docker log empty
    subprocess.Popen(["docker", "exec", "-it", kernel_container.id, "./startvm"])
    success_start = False
    for i in range(20):
        # test if vm finish start every 5+1 seconds for 20 times
        time.sleep(5)
        content = read_vm_log(kernel_container)
        if "login:" in content:
            subprocess.Popen(
                ["docker", "exec", "-it", kernel_container.id, "bash", "trigger.sh"]
            )
            success_start = True
            break
    if not success_start:
        logger.warning("start vm failed")
        exit(1)

    return check_bug(kernel_container)


def kernel_scan_version(
    vuln_schema: dict, target_tags: list = None, linux_path: str = None
):
    """
    scan target_tags of a git repo

    scan the given package in CVE schema

    show result in console

    Args:
        vuln_schema (dict): CVE json file
        target_tags (list, optional): tag name list. Defaults to None. None means scan bzImage or (configfile + version).
        linux_path (str, optional): Local linux source code path.
    """

    if not target_tags:
        if "bzImage" in vuln_schema["trigger"]:
            vul_status = kernel_build_and_run(vuln_schema)
        else:
            vul_status = kernel_build_and_run(
                vuln_schema, vuln_schema["version"], linux_path
            )

        if vul_status:
            logger.info(f"version is vulnerable")
        else:
            logger.info(f"version is safe")

    for tag in target_tags:
        vul_status = kernel_build_and_run(vuln_schema, tag, linux_path)
        if vul_status:
            logger.info(f"version {tag} is vulnerable")
        else:
            logger.info(f"version {tag} is safe")
