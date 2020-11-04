#ifndef _RSA_H
#define _RSA_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>


/*--------------------------------------- Key generation ---------------------------------------*/

# define RSA_SIEVE_LIMIT 255

/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 * It includes a common optimization, which is to start enumerating the multiples of each prime i from i^2.
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 * arg2:  The prime numbers that are less or equal to the limit. Empty argument used as ret val
 */
void sieve_of_eratosthenes( int limit , size_t** primes , int* primes_sz );

/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int
gcd(int , int);

/*
 * Chooses 'e' where 
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 * arg1: primes' pool size
 * arg2: primes' list
 * arg3: source of randomness
 *
 * ret: 'e'
 */
size_t choose_e( size_t , int , size_t* , FILE* );

/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 */
size_t
mod_inverse(size_t, size_t);

/* 
 * Saves an rsa key to a file
 * 
 * arg0: file name
 * arg1: n
 * arg2: d or e
 */
void save_key_to_file( char* filename , size_t a , size_t b );

/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void
rsa_keygen(void);


/*--------------------------------------- Encrypt / Decrupt ---------------------------------------*/

/*
* Move data from a file to a sting.
* arg0: file path
* arg1: output string
* arg2: output size
*/
void file_to_string( char* input_file , char** string , size_t* length );

/*
* Move data from a string to a file.
* arg0: file path
* arg1: output string
* arg2: output size
*/
void string_to_file( char* output_file , char* string , long length );

/* 
 * Read an rsa key from a file
 * 
 * arg0: file name
 * arg1: n
 * arg2: d or e
 */
void read_key_from_file( char* filename , size_t* a , size_t* b );

/*
 * Computes c = m^e mod n to avoid using pow()
 * 
 * arg0: m
 * arg1: e
 * arg2: n
 * 
 * ret: c
 */
size_t power_modulo( size_t a , size_t b , size_t n );

/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_encrypt(char *, char *, char *);

/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_decrypt(char *, char *, char *);

#endif /* _RSA_H */
