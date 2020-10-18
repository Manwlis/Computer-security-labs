#ifndef _SIMPLE_CRYPTO_H
#define _SIMPLE_CRYPTO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* otp_key;
/************************************
Encrypts a string using one time pad.
@param char* unnencrypted string.
@return a char* encrypted string.
*************************************/
char* otp_encrypt(char* message);

/************************************
Decrypts a cipher made by otp_encrypt.
@param char* cipher string.
@return a char* decrypted string.
*************************************/
char* otp_decrypt(char* ciphertext);


/************************************
Encrypts a string using Caesars . ----------------TO-DO
@param char* unnencrypted string.
@param int key.
@return a char* encrypted string.
*************************************/
char* caesars_encrypt( char* message , int key );

/************************************
Decrypts a cipher made by caesars_encrypt.
@param char* cipher string.
@param int key.
@return a char* decrypted string.
*************************************/
char* caesars_decrypt( char* ciphertext , int key );

/************************************
Encrypts a string using Vigenere . ----------------TO-DO
@param char* unnencrypted string.
@param char* key.
@return a char* encrypted string.
*************************************/
char* vigenere_encrypt( char* message , char* key );

/************************************
Decrypts a cipher made by vigenere_encrypt.
@param char* cipher string.
@param char* key.
@return a char* decrypted string.
*************************************/
char* vigenere_decrypt( char* ciphertext , char* key );

#endif