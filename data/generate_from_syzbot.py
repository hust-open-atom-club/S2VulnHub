#!/usr/bin/env python3
import os
import requests
import argparse
import json

# configs
storage_dir = "./kernel_bug"
local_extid = "./extids.txt"

def get_syzbot_extid():
    # find all the extid from the fixed page
    extids = []
    if os.path.exists(local_extid):
    # file exists, read lines
        with open(local_extid, 'r') as file:
            extids = file.readlines()
            return extids

    # check if stored locally
    wholepage = requests.get("https://syzkaller.appspot.com/upstream/fixed").text
    alltitle = wholepage.split('<td class="title">')

    with open(local_extid, 'w') as file:
        for title in alltitle :
            # /bug?id=  /bug?extid=
            # print(title)
            id_extid = title.split('a href="/bug?extid=')
            if len(id_extid)==1 :
                continue
            extid = id_extid[1].split('"')[0].strip()
            file.write(extid+'\n')
            extids.append(extid)
    
    return extids

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
        commitid, cpoc, config, bzimage = crawl_information(extid)

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
build_syzbot_json()
