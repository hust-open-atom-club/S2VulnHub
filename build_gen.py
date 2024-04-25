import base64


def gen_build(app_template):
    # default build command
    if "build" not in app_template:
        build = "make -j\n"
    else:
        build = app_template["build"]

    build = f"RUN echo -n {base64.b64encode(str.encode(build)).decode()} | base64 -d > build.sh\n"
    return build
