#!/bin/zsh
# 输入CVE编号，检查镜像是否存在并启动容器

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <CVE>"
    exit 1
fi

CVE=$1
cve=${1//CVE/cve}

if docker images | grep -q ${cve}; then
    # 镜像存在，则启动容器
    docker run -it --device=/dev/kvm --rm ${cve}:v1
else
    echo "${cve}:v1 image not found."
    exit 1
fi