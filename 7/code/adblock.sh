#!/bin/bash
# You are NOT allowed to change the files' names!
domainNames="domainNames.txt"
IPAddresses="IPAddresses.txt"
adblockRules="adblockRules"

function adBlock() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi
    if [ "$1" = "-domains"  ]; then
        # Configure adblock rules based on the domain names of $domainNames file.
        touch adblock.tmpIPAddresses # create temp file
        dig -f "$domainNames" +short >> "adblock.tmpIPAddresses" # resolve domain names to IPs

        while IFS= read line # feed iptables with the temp file
        do
            iptables -A INPUT -s $line -d 0/0 -j REJECT 2>/dev/null # suppress errors about ipv6

        done <"adblock.tmpIPAddresses"

        rm "adblock.tmpIPAddresses" # delete temp file
        true
            
    elif [ "$1" = "-ips"  ]; then
        # Configure adblock rules based on the IP addresses of $IPAddresses file.
        while IFS= read line
        do
            iptables -A INPUT -s $line -d 0/0 -j REJECT

        done <"$IPAddresses"
        true
        
    elif [ "$1" = "-save"  ]; then
        # Save rules to $adblockRules file.
        iptables-save > "$adblockRules"
        true
        
    elif [ "$1" = "-load"  ]; then
        # Load rules from $adblockRules file.
        iptables-restore < "$adblockRules"
        true
        
    elif [ "$1" = "-reset"  ]; then
        # Reset rules to default settings (i.e. accept all).
        iptables -F
        true
        
    elif [ "$1" = "-list"  ]; then
        # List current rules.
        iptables --list -n -v
        true
        
    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple adblock mechanism. It rejects connections from specific domain names or IP addresses using iptables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -domains\t  Configure adblock rules based on the domain names of '$domainNames' file.\n"
        printf "  -ips\t\t  Configure adblock rules based on the IP addresses of '$IPAddresses' file.\n"
        printf "  -save\t\t  Save rules to '$adblockRules' file.\n"
        printf "  -load\t\t  Load rules from '$adblockRules' file.\n"
        printf "  -list\t\t  List current rules.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

adBlock $1
exit 0