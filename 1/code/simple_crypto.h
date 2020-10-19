#ifndef _SIMPLE_CRYPTO_H
#define _SIMPLE_CRYPTO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/************************************
Encrypts a string using one time pad.
@param char* unnencrypted string.
@param char** pointer to key string. The function creates the key.
@return a char* encrypted string.
*************************************/
char* otp_encrypt( char* message , char** otp_key );

/************************************
Decrypts a cipher made by otp_encrypt.
@param char* cipher string.
@param char* key string.
@return a char* decrypted string.
*************************************/
char* otp_decrypt( char* ciphertext , char* otp_key );

/************************************
Encrypts a string using Caesars . ----------------TO-DO
@param char* unnencrypted string.
@param int key.
@param char* dictionary with the set of legal characters. If none provided, use the default one.
@return a char* encrypted string.
*************************************/
char* caesars_encrypt( char* message , int key, char* dictionary );

/************************************
Decrypts a cipher made by caesars_encrypt.
@param char* cipher string.
@param int key.
@param char* dictionary with the set of legal characters. If none provided, use the default one.
@return a char* decrypted string.
*************************************/
char* caesars_decrypt( char* ciphertext , int key, char* dictionary );

/************************************
Encrypts a string using Vigenere . ----------------TO-DO
@param char* unnencrypted string.
@param char* key.
@return a char* encrypted string.
*************************************/
char* vigenere_encrypt( char* message , char* key , char* dictionary );

/************************************
Decrypts a cipher made by vigenere_encrypt.
@param char* cipher string.
@param char* key.
@return a char* decrypted string.
*************************************/
char* vigenere_decrypt( char* ciphertext , char* key , char* dictionary );

#endif