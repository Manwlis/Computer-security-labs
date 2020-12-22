Emmanouil Petrakos 2014030009

All requested functionality has been implemented.

Option -domains uses a temp file named "adblock.tmpIPAddresses"

Tested with given domain list and the following ones.
https://pgl.yoyo.org/adservers/iplist.php
https://raw.githubusercontent.com/notracking/hosts-blocklists/master/domains.txt (takes two days to resolve all the domains)

After configuring the rules, the following websites have been visited.
https://ads-blocker.com/testing/
https://canyoublockit.com/testing/

Some ads persist. If the ad server is not in the list, it's ads are not getting rejected. After inspecting the output of "adblock.sh -list", it appears that some packets from certain ips have been rejected. In order to block all ads, the rules must be expanded to include all ad provider ips.

Problems like long loading arise when the website code waits for the ad to load in order to function. The ad request must timeout for the site to fully load. Also, if the blocked domain serves necessary data, the website does not function properly.
