import os
from typing import Tuple
from urllib.parse import urlparse
from utils import logger


def extract_name_and_ext(url: str) -> Tuple[str, str]:
    """
    extract filename and extension from url

    https://github.com/mudongliang/source-packages/raw/master/CVE-2017-5854/podofo-0.9.4.tar.gz

    -> [podofo-0.9.4.tar.gz, .tar.gz]
    """
    parsed_url = urlparse(url)
    filename = os.path.basename(parsed_url.path)
    _, ext = os.path.splitext(filename)

    if ext in [".gz"] and filename.count(".") > 1:
        ext = os.path.splitext(filename[: -(len(ext))])[1] + ext

    return filename, ext


def gen_soft(software: dict, version: str = None) -> str:
    """
    generate vulnerable software dockerfile snippet

    set workdir and checkout to the vulnerable commit id if version is not None

    Args:
        software (dict): software value in app template
        version (str, optional): software commit id or version number. Defaults to None.

    Returns:
        str: software dockerfile snippet
    """
    soft = ""
    source = software["source"]
    if source == "github":
        soft += (
            f'RUN git clone https://github.com/{software["user"]}/{software["repo"]}\n'
        )
        soft += f'WORKDIR /root/{software["repo"]}\n'
        if version:
            soft += f"RUN git checkout {version}\n"
        else:
            raise Exception("commit id is not provided")
    else:
        # get url for tarball
        if not version:
            url = software["packages"][0]["url"]
            logger.warning(f"software version not provided, using default version")
        else:
            flag = False
            for pkg in software["packages"]:
                if "version" in pkg and pkg["version"] == version:
                    flag = True
                    url = pkg["url"]
                    break
            if not flag:
                raise Exception(f"version {version} not found in software packages")
        soft += f"RUN wget {url}\n"

        fname, ext = extract_name_and_ext(url)
        if ext == ".tar.gz":
            soft += f"RUN tar -xzvf {fname}\n"
        elif ext == ".zip":
            soft += f"RUN unzip {fname}\n"
        else:
            soft += f"RUN tar -xvf {fname}\n"

        fname = fname.replace(ext, "")
        soft += f"WORKDIR /root/{fname}\n"

    return soft
