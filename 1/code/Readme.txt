Demo program demonstrates the use of the library.
Function input_string is used to read input of unknown size.
Function strip_string skips illegal characters from input strings.
One time pad ciphertext is printed in hexadecimal format.

Library includes One Time Pad, Caesar's & Vigenere’s encryption/decryption.
One time pad supports all ASCII characters. /dev/urandom is used to generate random characters.
Caesar's & Vigenere’s need a dictionary with the set of legal characters provided.
If none provided, a default one is used.( The default dictionaries are the one described in the assignment.)
If a character in the input doesn't belong in the dictionary, the functions return a null pointer.

compile with: make all
run with: ./demo