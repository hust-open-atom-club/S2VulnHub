import json
import sys

from build_gen import *
from poc_gen import *
from soft_gen import *


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


if __name__ == "__main__":
    with open(f"../data/kernel_bug/{sys.argv[1]}.json", "r") as f:
        vuln = json.loads(f.read())
    with open(f"../data/kernel_dockerfile/{sys.argv[1]}", "w") as f:
        f.write(gen_kernel_reproduce(vuln))
