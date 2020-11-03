#ifndef _RSA_H
#define _RSA_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

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
 * arg0: primes' list
 * arg0: source of randomness
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
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void
rsa_keygen(void);


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
