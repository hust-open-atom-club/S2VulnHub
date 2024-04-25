import json
from os_gen import *
from soft_gen import *
from build_gen import *
from poc_gen import *


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
    out_file += gen_build(app_template)
    out_file += gen_poc(schema["trigger"])
    out_file += 'CMD ["/bin/bash"]\n'

    return out_file


if __name__ == "__main__":
    cve_id = "CVE-2016-9560"
    with open(f"./user_cve/{cve_id}.json", "r") as f:
        schema = json.loads(f.read())
    out_file = gen_reproduce(schema)
    with open("Dockerfile", "w") as f:
        f.write(out_file)
