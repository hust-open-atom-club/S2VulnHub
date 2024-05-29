#!/bin/zsh
# 输入CVE编号，检查容器是否启动并进入
    
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <CVE>"
    exit 1
fi

CVE=$1
cve=${1//CVE/cve}

docker_id=$(docker ps --filter ancestor=${cve}:v1 --format "{{.ID}}")

if [ -n "$docker_id" ]; then
    docker exec -it ${docker_id} /bin/bash
else
    echo "${cve}:v1 docker not found."
    exit 1
fi