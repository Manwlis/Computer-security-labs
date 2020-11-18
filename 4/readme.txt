Tool's provided corpus has been preserved. Minor changes in entry struct. New function get_entries() in acmonitor.c, creates an array of entries from the .log file.

File fingerprint is saved as a string in hex format. Entries marked as denied or file open don't count as file changes even with different fingerprints.

Unauthorized accesses are defined as fopen() that failed because of insufficient rights and fwrite() on files that were opened without write mode.


test_aclog tries to create two files, write on the first one without opening it with write mode and write on the second one with write mode
See file comments for more info

Testing:
user			uid		password
normal_user		1000	1
malicious_user 	1001	1

run as normal_user:
make all
make run    # check that normal_user is the only one with write privileges
su malicious_user -c "make run"    # password: 1
./acmonitor -m
./acmonitor -i file_0
./acmonitor -i file_1

expected contents of file_logging.log:
1000 0 0 /home/normal_user/test/file_0 d41d8cd98f00b204e9800998ecf8427e 1605640420
1000 0 0 /home/normal_user/test/file_1 d41d8cd98f00b204e9800998ecf8427e 1605640420
1000 1 0 /home/normal_user/test/file_0 d41d8cd98f00b204e9800998ecf8427e 1605640420
1000 2 1 /home/normal_user/test/file_0 d41d8cd98f00b204e9800998ecf8427e 1605640420
1000 2 1 /home/normal_user/test/file_0 d41d8cd98f00b204e9800998ecf8427e 1605640420
1000 2 1 /home/normal_user/test/file_0 d41d8cd98f00b204e9800998ecf8427e 1605640420
1000 2 1 /home/normal_user/test/file_0 d41d8cd98f00b204e9800998ecf8427e 1605640420
1000 2 1 /home/normal_user/test/file_0 d41d8cd98f00b204e9800998ecf8427e 1605640420
1000 1 0 /home/normal_user/test/file_1 d41d8cd98f00b204e9800998ecf8427e 1605640420
1000 2 0 /home/normal_user/test/file_1 ba9d332813a722b273a95fa13dd88d94 1605640420
1000 2 0 /home/normal_user/test/file_1 8cedd94df857eb09fef87fdfcb5ccc06 1605640420
1000 2 0 /home/normal_user/test/file_1 39a297b7b1c0c15a9b47edbe12fc512e 1605640420
1000 2 0 /home/normal_user/test/file_1 26f7ef0b4f4bb540d16b6878d1d2aa1b 1605640420
1000 2 0 /home/normal_user/test/file_1 46f35d65f3ec24aee848bd7eea3ab89d 1605640420
1001 0 1 /home/normal_user/test/file_0 d41d8cd98f00b204e9800998ecf8427e 1605640428
1001 0 1 /home/normal_user/test/file_1 46f35d65f3ec24aee848bd7eea3ab89d 1605640428
1001 1 0 /home/normal_user/test/file_0 d41d8cd98f00b204e9800998ecf8427e 1605640428
1001 2 1 /home/normal_user/test/file_0 d41d8cd98f00b204e9800998ecf8427e 1605640428
1001 2 1 /home/normal_user/test/file_0 d41d8cd98f00b204e9800998ecf8427e 1605640428
1001 2 1 /home/normal_user/test/file_0 d41d8cd98f00b204e9800998ecf8427e 1605640428
1001 2 1 /home/normal_user/test/file_0 d41d8cd98f00b204e9800998ecf8427e 1605640428
1001 2 1 /home/normal_user/test/file_0 d41d8cd98f00b204e9800998ecf8427e 1605640428
1001 1 1 /home/normal_user/test/file_1 46f35d65f3ec24aee848bd7eea3ab89d 1605640428

expected acmonitor output:
malicious_user		# ./acmonitor -m

normal_user     1	# ./acmonitor -i file_0
malicious_user  0

normal_user     6	# ./acmonitor -i file_1
malicious_user  0
