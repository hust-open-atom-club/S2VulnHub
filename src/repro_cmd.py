import base64
import json

from os_gen import *
from soft_gen import *
from utils import get_template
from validate_cmd import validate_software, validate_vuln


def gen_build(app_template: dict, vuln_schema: dict = None) -> str:
    """
    generate app build dockerfile snippet

    'build' in CVE schema has higher priority

    Args:
        app_template (dict): app json file.
        vuln_schema (dict, optional): bug json file. Defaults to None.

    Returns:
        str: app build dockerfile snippet
    """
    if vuln_schema and "build" in vuln_schema:
        build = vuln_schema["build"]
    elif "build" in app_template:
        build = app_template["build"]
    else:
        build = "make -j\n"

    build = f"RUN echo -n {base64.b64encode(str.encode(build)).decode()} | base64 -d > build.sh\n"
    return build


def gen_poc(trigger: dict, kernel: bool = False) -> str:
    """
    generate poc dockerfile snippet

    poc = poc file + trigger.sh

    trigger.sh = command to compile and run poc

    Args:
        trigger (dict): trigger info in the vulnerability schema
        kernel (bool, optional): be true when it is a kernel bug. defaults to false.

    Returns:
        str: poc dockerfile snippet
    """
    poc = ""
    if "poc" in trigger:
        if kernel:
            poc += f"RUN wget -O poc.c '{trigger['poc']}'\n"
        else:
            poc += f"RUN wget '{trigger['poc']}'\n"
    poc += f'RUN echo -n {base64.b64encode(str.encode(trigger["guide"])).decode()} | base64 -d > trigger.sh\n'
    return poc


def gen_user_reproduce(vuln_schema: dict) -> str:
    """
    generate complete user CVE dockerfile

    Args:
        vuln_schema (dict): CVE json file

    Returns:
        str: complete user CVE dockerfile
    """

    if not validate_vuln(vuln_schema):
        exit(1)
    app_template = get_template(vuln_schema["category"])
    if not validate_software(app_template):
        exit(1)

    out_file = ""
    out_file += gen_os(
        app_template["environment"] if "environment" in app_template else None,
        vuln_schema["id"],
    )
    out_file += "WORKDIR /root\n"
    if "version" in vuln_schema:
        out_file += gen_soft(app_template["software"], vuln_schema["version"])
    else:
        # tarball need not have version
        out_file += gen_soft(app_template["software"])
    out_file += gen_build(app_template, vuln_schema)
    out_file += gen_poc(vuln_schema["trigger"])
    out_file += "RUN bash build.sh || true\n"
    out_file += 'CMD ["/bin/bash"]\n'

    return out_file


def gen_bzImage(kernel_template: dict, vuln: dict) -> str:
    """
    generate bzImage dockerfile snippet

    bzImage = (source + config) | existing bzImage

    Args:
        kernel_template (dict): info about kernel
        trigger (dict): info about vulnerability trigger

    Returns:
        str: dockerfile snippet for bzImage
    """
    img = ""
    trigger = vuln["trigger"]
    if "bzImage" in trigger:
        img += f"RUN wget -O bzImage.xz '{trigger['bzImage']}'\n"
        img += "RUN unxz bzImage.xz\n"
    else:
        img += f"RUN wget -O .config '{trigger['configfile']}'\n"
        img += gen_soft(kernel_template["software"], vuln["version"])
        img += gen_build(kernel_template)
    return img


# root
# ├── image
# ├── bzImage
# ├── poc
# ├── scripts
# ├── .config
# ├── linux
# │   ├── source
# │   ├── build.sh


def gen_kernel_reproduce(vuln):
    """generate kernel dockerfile = rootfs + bzImage + poc

        rootfs = jingyisong/kernel_bug_reproduce:bullseye

        bzImage = (source + config) | existing bzImage

        poc = poc.c + trigger.sh

    Args:
        vuln: kernel vulnerability schema

    Returns:
        full kernel dockerfile
    """
    with open(f"../data/apps/kernel.json", "r") as f:
        kernel_template = json.loads(f.read())

    out_file = ""
    out_file += "FROM jingyisong/kernel_bug_reproduce:bullseye\n"
    out_file += "WORKDIR /root\n"
    out_file += gen_bzImage(kernel_template, vuln)
    out_file += gen_poc(vuln["trigger"], True)
    out_file += 'CMD ["./startvm"]\n'

    return out_file
