import json
from os_gen import *
from soft_gen import *
from build_gen import *
from poc_gen import *
from inspect_gen import *
from rich.console import Console


def get_template(app_name):
    with open(f"./apps/{app_name}.json", "r") as f:
        schema = json.loads(f.read())
    return schema


def gen_reproduce(schema):
    out_file = ""
    app_template = get_template(schema["category"])
    out_file += gen_os(app_template["environment"])
    out_file += "WORKDIR /root\n"
    if "version" in schema:
        out_file += gen_soft(app_template["software"], schema["version"])
    else:
        # tarball need not have version
        out_file += gen_soft(app_template["software"], None)
    out_file += gen_build(app_template, schema)
    out_file += gen_poc(schema["trigger"])
    out_file += 'CMD ["/bin/bash"]\n'

    return out_file


# line: [commit, tag]
def build_and_run(schema, line):
    schema["version"] = line[0]
    out_file = ""
    app_template = get_template(schema["category"])
    out_file += gen_os(app_template["environment"])
    out_file += "WORKDIR /root\n"
    out_file += gen_soft(app_template["software"], schema["version"])
    out_file += gen_build(app_template)
    out_file += gen_poc(schema["trigger"])
    out_file += "RUN bash build.sh\n"
    out_file += 'CMD ["bash", "poc.sh"]\n'

    with open("Dockerfile", "w") as f:
        f.write(out_file)

    subprocess.run(
        ["sudo", "docker", "build", "-t", "testrepo", "."],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    ret = subprocess.run(
        ["sudo", "docker", "run", "--rm", "-it", "--ulimit", "cpu=10", "testrepo"],
        capture_output=True,
        text=True,
    )

    # returncode == 137 means exceed ulimit
    if ret.returncode != 0 and ret.returncode != 1 and ret.returncode != 137:
        return True  # True means vulnerable
    elif ret.returncode == 1 and ret.stdout.find("Sanitizer") != -1:
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


if __name__ == "__main__":
    cve_id = "CVE-2016-9560"
    with open(f"./user_cve/{cve_id}.json", "r") as f:
        schema = json.loads(f.read())
    out_file = gen_reproduce(schema)
    with open("Dockerfile", "w") as f:
        f.write(out_file)
