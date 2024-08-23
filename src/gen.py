import json

from rich.console import Console
from utils import *
from build_gen import *
from inspect_gen import *
from json_validate import *
from os_gen import *
from poc_gen import *
from soft_gen import *
from logger import logger


def get_template(app_name):
    try:
        with open(f"../data/apps/{app_name}.json", "r") as f:
            schema = json.loads(f.read())
        return schema
    except Exception as e:
        logger.warning(e)
        exit(1)


def gen_reproduce(schema):
    # validate the schema
    if not validate_vuln(schema):
        exit(1)
    app_template = get_template(schema["category"])
    if not validate_software(app_template):
        exit(1)

    out_file = ""
    out_file += gen_os(app_template["environment"], schema["id"])
    out_file += "WORKDIR /root\n"
    if "version" in schema:
        out_file += gen_soft(app_template["software"], schema["version"])
    else:
        # tarball need not have version
        out_file += gen_soft(app_template["software"], None)
    out_file += gen_build(app_template, schema)
    out_file += gen_poc(schema["trigger"])
    out_file += "RUN bash build.sh || true\n"
    out_file += 'CMD ["/bin/bash"]\n'

    return out_file


# line: [commit, tag]
def build_and_run(schema, line):
    if not check_docker_permission():
        add_user_to_docker_group()
        exit(1)

    schema["version"] = line[0]
    out_file = ""
    app_template = get_template(schema["category"])
    out_file += gen_os(app_template["environment"], schema["id"])
    out_file += "WORKDIR /root\n"
    out_file += gen_soft(app_template["software"], schema["version"])
    out_file += gen_build(app_template, schema)
    out_file += gen_poc(schema["trigger"])
    out_file += "RUN bash build.sh || true\n"
    out_file += 'CMD ["bash", "trigger.sh"]\n'

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
        return True  # True means vulnerable
    elif run_ret.returncode == 1 and errstr.find("Sanitizer") != -1:
        return True
    else:
        return False  # False means safe


def scan_version(schema, target_tags=None):
    app_template = get_template(schema["category"])

    if app_template["software"]["source"] == "tarball":
        raise Exception("tarball package scan is not supported")

    tags = list_all_tags_for_remote_git_repo(
        f'https://github.com/{app_template["software"]["user"]}/{app_template["software"]["repo"]}'
    )
    tags.reverse()
    ultimate_tags = []

    console = Console()

    for tag in tags:
        if target_tags is None or tag[1] in target_tags:
            ultimate_tags.append(tag)

    ultimate_tags_idx = 0
    with console.status(
        f'[bold blue]reproducing {app_template["software"]["user"]}/{app_template["software"]["repo"]} version {ultimate_tags[ultimate_tags_idx][1]}...'
    ) as status:
        for tag in ultimate_tags:
            vul_status = build_and_run(schema, tag)
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
