#!/bin/zsh

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <CVE>"
    exit 1
fi

CVE=$1

python cli.py reproduce -C ${CVE}

# if [ ! -f "./Dockerfile/${CVE}" ]; then
#     python cli.py reproduce -C ${CVE}
# fi

cve=${1//CVE/cve}

docker build -f ./Dockerfile/${CVE} -t ${cve}:v1 .
if [ $? -eq 0 ]; then
    docker run -it ${cve}:v1
else
    echo "Docker build failed."
    exit 1
fi
