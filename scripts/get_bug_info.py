#!/usr/bin/env python3

# refer to: https://github.com/HUSTSeclab/reproduce_kernel_bugs/blob/main/Scripts/get_bug_info.py

import sys
import os
import urllib.request
from bs4 import BeautifulSoup

syzbot = "https://syzkaller.appspot.com"

kernel_map = {
    'upstream': 'linux',
    #    'net':'net',
    #    'net-next':'net-next',
    #    'linux-next':'linux-next-history',
    #    'bpf':'bpf',
    #    'bpf-next':'bpf-next',
    #    "https://github.com/google/kmsan.git master":"kmsan",
    #    "https://github.com/google/ktsan.git kcsan":"ktsan",
    #    "https://git.kernel.org/pub/scm/linux/kernel/git/gregkh/usb.git usb-testing":"usb"
}

close_kernel = [
    #    "mmots"
]


def write_conf(bug_extid, k_id, poc_url, bz_url, config_url):
    schema = '''
{
    "schema_version": "1.0",
    "id": "%s",
    "category": "kernel",
    "version": "%s",
    "trigger": {
        "poc": "%s",
        "bzImage": "%s",
        "configfile":"%s"
    }
}
'''
    content = schema % (bug_extid, k_id, poc_url, bz_url, config_url)
    print(content)
    open(f"../kernel_bug/{bug_extid}.json", 'w').write(content)


def get_if_has(tag, key='href'):
    if tag.a and key in tag.a.attrs.keys():
        return tag.a[key]
    return None


def get_bug_info(table):
    trs = table.find_all('tr')
    for tr in trs[1:]:
        info = tr
        if not info:
            continue

        # set kernel_repro
        # kernel_repro = info.find(class_='kernel').contents[0]
        # if kernel_repro in close_kernel:
        #     continue
        # if kernel_repro not in kernel_map:
        #     print("    WARN: %s is not cloned in the local workspace" %
        #           kernel_repro)
        #     continue

        # set bz_url
        bz_url = ''
        if info.find('a', string='kernel image') is None:
            continue
        else:
            bz_url = info.find('a', string='kernel image')['href']

        # set commit_id
        href = info.find_all(class_='tag')[0].a['href']
        commit_id = ''
        if "id=" in href:
            commit_id = href.split('id=')[1]
        else:
            commit_id = href.split('/')[-1]

        # set poc_url
        poc_url = ''
        if get_if_has(info.find_all(class_='repro')[3]):
            poc_url = syzbot + get_if_has(info.find_all(class_='repro')[3])

        # set config_url
        config_url = syzbot + info.find(class_='config').a['href']

        # set syz_url
        # syz_url = ''
        # if get_if_has(info.find_all(class_='repro')[2]):
        #     syz_url = syzbot + get_if_has(info.find_all(class_='repro')[2])

        if poc_url and bz_url and config_url:
            write_conf(bug_extid, commit_id, poc_url, bz_url, config_url)
            return True

    return False


def main(bug_extid):
    # id or extid: https://github.com/google/syzkaller/pull/3891/files
    target = 'https://syzkaller.appspot.com/bug?extid='+str(bug_extid)
    content = urllib.request.urlopen(target).read()
    soup = BeautifulSoup(content, 'html.parser')
    list_tables = soup.find_all(class_='list_table')
    for table in list_tables:
        caption = table.contents[1].string
        if caption is None:
            continue
        if "Crash" in caption:
            return get_bug_info(table)


if __name__ == '__main__':
    if len(sys.argv) >= 1:
        bug_extid = sys.argv[1]
    else:
        sys.exit(-1)
    if main(bug_extid):
        print(f'Success : {bug_extid} info has been written into schema')
    else:
        print(f"Failed  : {bug_extid} do not have all necessary info")
