--------------------------------------------------------------------------------------------------
HOW TO USE

ransomware.sh
./ransomware.sh [-c -e -d] <directory> <number of files>

option -c creates <number of files> files in <directory> using test_aclog.c

option -e encrypts the first non-encrypted <number of files> files in <directory>
If the non-encrypted files in <directory> are less than <number of files>, all the non-encrypted files are encrypted

option -d decrypts the first encrypted <number of files> files in <directory>
If the encrypted files in <directory> are less than <number of files>, all the encrypted files are decrypted


logger.c
Logger has been expanded and overloads fopen64() to catch the opening of files by the openssl library.


acmonitor.c
Help message has been expanded to show information about the new functionality.

New option -v <number of files>
Prints how many files were created in the last 20 minutes according to file_logging.log
Prints if the behavior is suspicious according to <number of files>

New option -e
Prints all the files that have been encrypted.
If a "name".encrypt file was created, then the "name" file was encrypted.


--------------------------------------------------------------------------------------------------
TESTING
I use the empty directory "test"


LD_PRELOAD=./logger.so ./ransomware.sh -c ./test 10	// creates 10 files in test directory

./acmonitor -v 10									// check how many files were created
	// expected output:
	// Num created files in last 20 minutes: 10
	// Suspicious behavior

LD_PRELOAD=./logger.so ./ransomware.sh -e ./test 5	// encrypts 5 files in test directory

./acmonitor -e										// show which files were encrypted
	// expected output (5 files):
	// /.../test/file_0
	// ...
	// /.../test/file_4

LD_PRELOAD=./logger.so ./ransomware.sh -e ./test 50 // encrypts the rest

./acmonitor -e										// show which files were encrypted
	// expected output (10 files):
	// /.../test/file_0
	// ...
	// /.../test/file_9