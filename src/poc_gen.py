import base64


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
    if kernel:
        poc += "RUN chmod +x trigger.sh\n"
    return poc
