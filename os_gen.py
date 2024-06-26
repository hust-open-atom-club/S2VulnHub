import re

# this is the fallback template
# and we install common build depend for it
# hopefully it works for most of the cases


def gen_default():
    env = f"FROM ubuntu:20.04\n"
    env += 'RUN sed -i "s@http://.*archive.ubuntu.com@http://mirrors.ustc.edu.cn/@g" /etc/apt/sources.list\n'
    env += 'RUN sed -i "s@http://.*security.ubuntu.com@http://mirrors.ustc.edu.cn/@g" /etc/apt/sources.list\n'
    env += "ARG DEBIAN_FRONTEND=noninteractive\n"

    dev_package = [
        "iputils-ping",
        "wget",
        "git",
        "vim",
        "build-essential",
        "cmake",
        "libreadline-dev",
        "tclsh",
        "unzip",
    ]
    env += f'RUN apt update && apt install -y {" ".join(dev_package)}\n'
    return env


def gen_ubuntu(environment, version):
    if version not in ["14.04", "16.04", "18.04", "20.04", "22.04"]:
        raise Exception(f"version {version} not supported")

    env = f"FROM ubuntu:{version}\n"
    env += 'RUN sed -i "s@http://.*archive.ubuntu.com@http://mirrors.ustc.edu.cn/@g" /etc/apt/sources.list\n'
    env += 'RUN sed -i "s@http://.*security.ubuntu.com@http://mirrors.ustc.edu.cn/@g" /etc/apt/sources.list\n'
    env += "ARG DEBIAN_FRONTEND=noninteractive\n"

    dev_package = [
        "iputils-ping",
        "wget",
        "git",
        "vim",
        "build-essential",
        "cmake",
        "unzip",
    ]
    env += f'RUN apt update && apt install -y {" ".join(dev_package)}\n'

    if "dependencies" in environment:
        env += f'RUN apt install -y {" ".join(environment["dependencies"])}\n'

    return env


def gen_arch(environment):
    env = f"FROM archlinux:latest\n"
    env += "RUN yes | pacman -Syyu\n"

    dev_package = [
        "wget",
        "git",
        "vim",
        "base-devel",
        "cmake",
    ]
    env += f'RUN yes | pacman -S {" ".join(dev_package)}\n'

    if "dependencies" in environment:
        env += f'RUN yes | pacman -S {" ".join(environment["dependencies"])}\n'

    return env


def gen_os(environment, cve_id):
    env = ""
    if "distro" not in environment and "dependencies" in environment:
        raise Exception("dependencies must be used with distro")

    if "distro" not in environment:
        env = gen_default()
    elif environment["distro"] == "ubuntu":
        # infer version from cve_id
        # https://ubuntu.com/about/release-cycle
        match = re.search(r"CVE-(\d+)-\d+", cve_id)
        year = int(match.group(1))
        if year < 2016:
            version = "14.04"
        elif year < 2018:
            version = "16.04"
        elif year < 2020:
            version = "18.04"
        else:
            version = "20.04"
        env = gen_ubuntu(environment, version)
    elif environment["distro"] == "arch":
        env = gen_arch(environment)

    return env
