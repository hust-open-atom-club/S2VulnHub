#!/usr/bin/env python3
import os
import requests
import argparse
import json
import re

from collections import defaultdict
# configs
storage_dir = "./kernel_bug"
local_extid = "./extids.txt"
store=defaultdict(dict)

def get_syzbot_extid():
    # find all the extid from the fixed page
    extids = []
    # if os.path.exists(local_extid):
    # # file exists, read lines
    #     with open(local_extid, 'r') as file:
    #         extids = file.readlines()
    #         return extids

    # check if stored locally
    #wholepage = requests.get("https://syzkaller.appspot.com/upstream/fixed").text
    # 从本地html文件读取
    with open("./syzbot.html", 'r') as file:
        wholepage = file.read()
    alltitle = wholepage.split('<td class="title">')
    print("total number of bugs: ", len(alltitle))


    with open(local_extid, 'w') as file:
        for title in alltitle[:1000] :
            # /bug?id=  /bug?extid=
            # print(title)
            id_extid = title.split('https://syzkaller.appspot.com/bug?extid=')
            if len(id_extid)==1 :
                continue
            extid = id_extid[1].split('"')[0].strip()
            file.write(extid+'\n')
            extids.append(extid)
    
    return extids

def compare_unmini_syz(syzid):
    syzlink = "https://syzkaller.appspot.com/bug?extid=" + syzid
    try:
        syzinfo = requests.get(syzlink).text
        syzlog = "https://syzkaller.appspot.com/" + syzinfo.split('<td class="repro">')[3].split('<a href="')[2].split('"')[0].replace("&amp;" , "&")
        syzpoc = "https://syzkaller.appspot.com/" + syzinfo.split('<td class="repro">')[3].split('<a href="')[1].split('"')[0].replace("&amp;" , "&")
    except:
        print("error occurs while parsing syzlog or syzpoc")
        return
    syz_n=count_poc(syzpoc)
    unm_n=count_unm(syzlog)
    if unm_n == None or syz_n == None or syz_n == 0 or unm_n == 0 : 
        print("error occurs while counting the number of syscalls")
        return
    print(syz_n, unm_n)
    store[syzlink]["unminimized"] = unm_n
    store[syzlink]["minimized"] = syz_n
    store[syzlink]["percentage"] = round((syz_n)/unm_n*100, 2)
    #print(store)

    return

def count_unm(link):
    # "found reproducer with 30 syscalls" 截取出来30
    pattern = r"found reproducer with (\d+) syscalls"
    try:
        syzinfo = requests.get(link).text
        # filter
        if "syz_mount_image" in syzinfo:
            return 0
        number = re.findall(pattern, syzinfo)
        if len(number) > 0:
            return int(number[0])
    except:
        print("error occurs while counting syscalls in {}".format(link))
        return 0

    return


def count_poc(link):
    # count the number of lines in the poc
    try:
        syzinfo = requests.get(link).text
        syzinfo = syzinfo.strip()
        # 晒去以#开头的行
        syzinfo = '\n'.join([line for line in syzinfo.split('\n') if not line.startswith('#')])
        return len(syzinfo.split('\n'))
    except:
        print("error occurs while counting lines in {}".format(link))
        return 0

def turn_to_excel(dicts):
    # convert the dict to a pandas dataframe
    import pandas as pd
    df = pd.DataFrame(dicts).T
    # save to excel
    df.to_excel("syzbot.xlsx")
    print("save to syzbot.xlsx")
    return

def crawl_information(syzid):
    syzinfo = requests.get("https://syzkaller.appspot.com/bug?extid=" + syzid).text
    
    # C POC
    cpoc = ""
    cpoc_exist = syzinfo.split('<td class="repro">')[4].split('<a href="')
    
    if len(cpoc_exist)>1 :
        cpoc = "https://syzkaller.appspot.com/" + cpoc_exist[1].split('"')[0].replace("&amp;" , "&")
    
    # config
    config = ""
    config_exist = syzinfo.split('<td class="config">')[1].split('<a href="')
    if len(config_exist)>1 :
        config = "https://syzkaller.appspot.com/" + config_exist[1].split('"')[0].replace("&amp;" , "&")

    # commit id
    commit = ""
    commit_exist = syzinfo.split('<td class="tag')[1].split('<a href="')
    if len(commit_exist)>1 :
        commit = commit_exist[1].split('"')[0].split("?id=")[1]

    # bzImage
    bzimage = ""
    bzimage_exist = syzinfo.split('<td class="assets">')[1].split('<a href="')
    if len(bzimage_exist)>1:
        bzimage = bzimage_exist[3].split('"')[0]


    # print(commit, cpoc, config, bzimage)
    return commit, cpoc, config, bzimage

def build_syzbot_json():
    # build the json config file
    extids = get_syzbot_extid()
    for extid in extids :
        extid=extid.strip()
        print(extid)
        print("{}/{}.json".format(storage_dir, extid))
        if os.path.exists("{}/{}.json".format(storage_dir, extid)) :
            print("{}/{}.json".format(storage_dir, extid))
            continue
        try :
            commitid, cpoc, config, bzimage = crawl_information(extid)
        except :
            print("error occurs while generating {}.json".format(extid))
            continue
        dict_ = {
                "schema_version": "1.0",
                "id": extid,
                "category": "kernel",
                "version": commitid,
                "trigger": {
                    "poc": cpoc,
                    "bzImage": bzimage,
                    "configfile": config
                }
        }
        print(dict_)
        with open("{}/{}.json".format(storage_dir, extid), "w", encoding='utf-8') as f:
            # json.dump(dict_, f)  # 写为一行
            json.dump(dict_, f, indent=2, sort_keys=False, ensure_ascii=False)  # 写为多行

    
# if __name__ == "__main__":
#     parser = argparse.ArgumentParser()
#     parser.formatter_class = argparse.RawTextHelpFormatter
#     parser.description = "Generate json config for bugs from syzbot"
#     subparsers = parser.add_subparsers(
#         dest="command", help="commands to run", required=True
#     )



# crawl information
#build_syzbot_json()
import time
ids=get_syzbot_extid()
# 使用线程池多线程处理
# 



print(ids)
for i in range(len(ids)):
    time.sleep(2)
    compare_unmini_syz(ids[i])
    if i %5==0:

        turn_to_excel(store)
turn_to_excel(store)