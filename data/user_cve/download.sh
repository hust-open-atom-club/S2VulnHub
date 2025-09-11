#!/bin/bash

PREFIX="https://github.com/hust-open-atom-club/S2VulnHub/raw/master/data/user_cve"

cd $(dirname $0)

for file in $(ls -1 . | grep json)
do
    echo Processing USER_CVE file $file
    id=${file%.*}
    mkdir -p poc/$id 
    pushd poc/$id > /dev/null
    for link in $(cat ../../$file | grep -oE '"poc"\s*:\s*".*"' | awk -F '"' '{print $4}')
    do
        pocFile=${link##*/}
        rawLink=$(echo $link | sed 's|/blob/|/raw/|g')
        if [ "$rawLink" != "$link" ]
        then
            echo Warning! POC file link is not raw link, change to raw link...
        fi
        echo Downloading POC file $pocFile
        if [ "$(echo $link | grep -E 'https?://(www.)?github.com/hust-open-atom-club/S2VulnHub')" ]
        then
            echo Exist.
            continue 
        fi
        curl -L $rawLink > $pocFile
        if [ "$?" == 0 ]
        then
            echo Success!
            printf "%-80s%s\n" $id/$pocFile $link >> ../origin_url
            newLink=$PREFIX/poc/$id/$pocFile
            sed -i "s|$link|$newLink|g" ../../$file 
        else
            echo Download $link failure!
        fi
        echo
    done
    echo 
    popd > /dev/null
done

