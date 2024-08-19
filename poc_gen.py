import base64


def gen_poc(trigger):
    poc = ""
    if "poc" in trigger:
        poc += f'RUN wget {trigger["poc"]}\n'
    poc += f'RUN echo -n {base64.b64encode(str.encode(trigger["guide"])).decode()} | base64 -d > trigger.sh\n'
    return poc
