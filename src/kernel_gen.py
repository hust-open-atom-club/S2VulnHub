import json
import sys

from build_gen import *
from poc_gen import *
from soft_gen import *


def gen_bzImage(kernel_template, trigger):
    img = ""
    if "bzImage" in trigger:
        img += f"RUN wget -O bzImage.xz '{trigger['bzImage']}'\n"
        img += "RUN unxz bzImage.xz\n"
    else:
        img += f"RUN wget -O .config '{trigger['configfile']}'\n"
        img += gen_soft(kernel_template["software"], trigger["version"])
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


def gen_reproduce(vuln):
    # rootfs + bzImage + poc
    # bzImage = source + config
    # poc = compile poc.c
    with open(f"../data/apps/kernel.json", "r") as f:
        kernel_template = json.loads(f.read())

    out_file = ""
    out_file += "FROM jingyisong/kernel_bug_reproduce:bullseye\n"
    out_file += "WORKDIR /root\n"
    out_file += gen_bzImage(kernel_template, vuln["trigger"])
    out_file += f"RUN wget -O poc.c '{vuln['trigger']['poc']}'\n"
    out_file += "RUN gcc poc.c -lpthread -static -o poc\n"
    out_file += 'CMD ["./startvm"]\n'

    return out_file


if __name__ == "__main__":
    with open(f"../data/kernel_bug/{sys.argv[1]}.json", "r") as f:
        vuln = json.loads(f.read())
    with open(f"../data/kernel_dockerfile/{sys.argv[1]}", "w") as f:
        f.write(gen_reproduce(vuln))
