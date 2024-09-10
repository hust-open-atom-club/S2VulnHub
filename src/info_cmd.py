import re
import subprocess

import requests


def get_raw_arch(app_name):
    resp = requests.get(
        f"https://gitlab.archlinux.org/archlinux/packaging/packages/{app_name}/-/raw/main/PKGBUILD?ref_type=heads"
    )
    if resp.status_code == 200:
        return resp.text
    else:
        return None


def get_raw_fedora(app_name):
    resp = requests.get(
        f"https://src.fedoraproject.org/rpms/{app_name}/raw/rawhide/f/{app_name}.spec"
    )
    if resp.status_code == 200:
        return resp.text
    else:
        return None


def get_raw(app_name):
    arch_info = get_raw_arch(app_name)
    if arch_info is not None:
        print("Arch info raw:")
        print(arch_info)
    else:
        print("No arch info, please use a different app name")
    print("-----     -----     -----     -----     -----     -----")
    fedora_info = get_raw_fedora(app_name)
    if fedora_info is not None:
        print("Fedora info raw:")
        print(fedora_info)
    else:
        print("No fedora info, please use a different app name")


def get_depend_arch(app_name):
    raw = get_raw_arch(app_name)
    if raw is None:
        print("No arch info, please use a different app name")
        return
    matches = re.findall(r"depends=\(.*?\)", raw, re.DOTALL)

    depends = []
    for match in matches:
        depend_list = re.findall(r"'([^']*)'", match, re.DOTALL)
        depends.extend(depend_list)
    depends = sorted(set(depends))
    print("Arch info depend:")
    print(depends)


def get_depend_fedora(app_name):
    raw = get_raw_fedora(app_name)
    if raw is None:
        print("No fedora info, please use a different app name")
        return
    matches = re.findall(r"^BuildRequires:\s+(.*)$", raw, re.MULTILINE)

    depends = []
    for match in matches:
        depends.extend(match.split())
    depends = sorted(set(depends))
    print("Fedora info depend:")
    print(depends)


def get_depend(app_name):
    get_depend_arch(app_name)
    print("-----     -----     -----     -----     -----     -----")
    get_depend_fedora(app_name)


def get_build_arch(app_name):
    raw = get_raw_arch(app_name)
    if raw is None:
        print("No arch info, please use a different app name")
        return
    start_marker = "\nbuild() {\n"
    end_marker = "\n}\n"

    start_index = raw.find(start_marker)
    end_index = raw.find(end_marker, start_index)

    if start_index != -1 and end_index != -1:
        start_index += len(start_marker)
        captured_lines = raw[start_index:end_index]
        lines = captured_lines.split("\n")

        for line in lines:
            print(line)


def get_cxx(app_name, path):
    url = f'https://api.github.com/repos/{app_name}/contents/{path if path is not None else ""}'

    resp = requests.get(url)
    if resp.status_code != 200:
        print("ERROR: No such repo or path, please check your input")
        return

    resp = resp.json()
    for item in resp:
        if "makefile" in item["name"].lower():
            print("Makefile is detected!")
        elif "cmake" in item["name"].lower():
            print("CMake is detected!")
        elif "meson" in item["name"].lower():
            print("Meson is detected!")
        elif "configure" in item["name"].lower():
            print("Autotools is detected!")
        elif "bazel" in item["name"].lower():
            print("Bazel is detected!")
        elif ".gn" in item["name"].lower():
            print("GN is detected!")
        elif "conan" in item["name"].lower():
            print("Conan is detected!")
        elif "scons" in item["name"].lower():
            print("Scons is detected!")
        elif "buck" in item["name"].lower():
            print("Buck is detected!")
        elif (
            "moz.build" in item["name"].lower()
            or "moz.configure" in item["name"].lower()
        ):
            print("mozbuild is detected!")


def list_tags(url):
    """
    Given a repository URL, list all tags for that repository without cloning it.
    This function use "git ls-remote", so the "git" command line program must be available.
    """
    # Run the 'git' command to fetch and list remote tags
    result = subprocess.run(
        ["git", "ls-remote", "--tags", url], stdout=subprocess.PIPE, text=True
    )
    # Process the output to extract tag names
    output_lines = result.stdout.splitlines()
    tags = [
        line.split("\trefs/tags/")
        for line in output_lines
        if "refs/tags/" in line and "^{}" not in line
    ]
    return tags
