#include "rsa.h"
#include "utils.h"


void sieve_of_eratosthenes( int limit , size_t** primes , int* primes_sz )
{
	// index == number but 0 and 1 are not parts of the sieve
	// limit is the size of the sieve.
	int offset = 2;
	limit = limit + offset;
	unsigned char sieve[limit];
	// all set to 1
	memset( sieve , '1', limit );

	// map sieve
	// start from second element
	for( int i = offset ; i < sqrt(limit) ; i++ )
		if( sieve[i] == '1' )
			for( int j = i * i ; j < limit ; j += i )
				sieve[j] = '0';

	// count primes
	for( int i = offset ; i < limit ; i++ )
		if( sieve[i] == '1' )
			(*primes_sz)++;

	// create array
	*primes = malloc( sizeof(size_t) * (*primes_sz) );

	// fill array
	int count = 0;
	for( int i = offset ; i < limit ; i++ )
	{
		if( sieve[i] == '1' )
		{
			(*primes)[count] = (size_t) i;
			count++;
		}
	}
}


int gcd( int a , int b )
{
	while( b != 0 )
	{
		int temp = b;
		b = a % b;
		a = temp;
	}
	return a;
}


size_t choose_e( size_t fi_n , int primes_sz , size_t* primes , FILE* urandom )
{
	size_t e = 0;
	// exits when (e % fi(n) != 0) AND (gcd(e, fi(n)) == 1)
	while( ( e % fi_n == 0 ) || ( gcd( e , fi_n ) != 1 ) )
	{
		// get random prime e
		unsigned int e_random_index = primes_sz;
		while ( e_random_index >= primes_sz )
			e_random_index = (int) fgetc( urandom );

		e =  primes[ e_random_index ];
	}
	return e;
}


// adaptation of the extended Euclidean algorithm. ax + by = gcd( a , b ) = 1
// based on https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Computing_multiplicative_inverses_in_modular_structures
size_t mod_inverse( size_t a , size_t b )
{
	long a_new = (long) a;
	long b_new = (long) b;
	long y = 0;
	long x = 1;

	while ( a_new > 1 )
	{ 
		long quotient = a_new / b_new;

		// new a, b
		long temp = b_new;
		b_new = a_new % b_new;
		a_new = temp;
  
		// update y, x
		temp = y;
		y = x - quotient * y;
		x = temp;
	} 
  
	// make x positive 
	if ( x < 0 ) 
	   x += b; 
  
	return x; 
}


void rsa_keygen( void )
{
	size_t p;
	size_t q;
	size_t n;
	size_t fi_n;
	size_t e;
	size_t d;

	// find primes
	size_t* primes;
	unsigned int primes_sz = 0;
	sieve_of_eratosthenes( RSA_SIEVE_LIMIT , &primes , &primes_sz );

	// open urandom as file
	FILE* urandom = fopen( "/dev/urandom", "r" );

	// get random indexes
	unsigned int p_random_index = primes_sz;
	unsigned int q_random_index = primes_sz;
	
	// with current limits, pool can't have more than 256 elements.
	// If that changes, fgetc has to change to.
	while ( p_random_index >= primes_sz )
		p_random_index = (int) fgetc( urandom );
	
	while ( q_random_index >= primes_sz )
		q_random_index = (int) fgetc( urandom );
	
	
	// pick two random primes p and q
	p = primes[ p_random_index ];
	q = primes[ q_random_index ];


	// calculate n
	n = p * q;

	// calculate fi(n) ( Euler’s totient function )
	fi_n = ( p - 1 ) * ( q - 1 );

	// choose a prime e
	e = choose_e( fi_n , primes_sz , primes , urandom );

	// choose d. gcd( e , fi_n ) == 1 => Modular inverse exists.
	d = mod_inverse( e , fi_n );

	// save to files

}


void rsa_encrypt( char* input_file , char* output_file , char* key_file )
{

	/* TODO */

}


void rsa_decrypt( char* input_file , char* output_file , char* key_file )
{

	/* TODO */

}