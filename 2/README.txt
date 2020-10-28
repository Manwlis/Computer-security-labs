All requested functionality has been developed. Tool's skeleton and function signatures have been preserved.

Key generation is achieved with EVP_BytesToKey().
Encrytion, decryption and signing follow a Initialize/Start/Finalize/Clean pattern.
Verification compares message's CMAC with one derived from the decrypted message.

Function file_to_string moves data from a file to string.
Function string_to_file saves data from a string to a file.

Neither of the cmacs verified. (After a little experimentation I observed that they could be verified with cbc mode of operation.)

Main sources:
https://wiki.openssl.org/index.php/Main_Page
https://www.openssl.org/docs/manmaster/
