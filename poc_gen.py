def gen_poc(trigger):
    poc = ""
    if "poc" in trigger:
        poc += f'RUN wget {trigger["poc"]}\n'
    poc += f'RUN echo -n {trigger["guide"]} | base64 -d > poc.sh\n'
    return poc
