import os
from typing import Tuple
from urllib.parse import urlparse


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
        software (dict): software schema
        version (str, optional): vulnerable software commit id. Defaults to None.

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
        if version is not None:
            soft += f"RUN git checkout {version}\n"
    else:
        url = software["url"]
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
