import base64


def gen_build(app_template, schecma):
    # build in CVE schema has higher priority
    if "build" in schecma:
        build = schecma["build"]
    elif "build" in app_template:
        build = app_template["build"]
    else:
        build = "make -j\n"

    build = f"RUN echo -n {base64.b64encode(str.encode(build)).decode()} | base64 -d > build.sh\n"
    return build
