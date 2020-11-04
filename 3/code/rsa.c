#include "rsa.h"
#include "utils.h"


/*--------------------------------------- Key generation ---------------------------------------*/

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


void save_key_to_file( char* filename , size_t a , size_t b )
{
	FILE* f = fopen( filename , "w" );
	if( !f )
	{
		perror( filename );
		exit(-1);
	}
	fwrite( &a , sizeof(size_t) , 1 , f );
	fwrite( &b , sizeof(size_t) , 1 , f );

	fclose(f);
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
	int primes_sz = 0;
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
	save_key_to_file( "public.key" , n , d );
	save_key_to_file( "private.key" , n , e );
}


/*--------------------------------------- Encrypt / Decrupt ---------------------------------------*/

void file_to_string( char* input_file , char** string , size_t* length )
{
	FILE* f = fopen ( input_file , "r" );

	if ( !f )
	{
		perror( input_file );
		exit(-1);
	}

	fseek( f , 0 , SEEK_END );
	*length = ftell(f);
	fseek( f , 0 , SEEK_SET );

	*string = malloc( *length );
	int fread_value = fread( *string , 1 , *length , f );

	fclose (f);
}


void string_to_file( char* output_file , char* string , long length )
{
	FILE* f = fopen ( output_file , "w" );
	
	if (f)
	{
		for( int i = 0 ; i < length ; i++ )
			fputc( string[i] , f );
	}
	else
	{
		perror( output_file );
		exit(-1);
	}
	fclose(f);
}


void read_key_from_file( char* filename , size_t* a , size_t* b )
{
	FILE* f = fopen( filename , "r" );
	if( !f )
	{
		perror( filename );
		exit(-1);
	}
	int fread_val = fread( a , sizeof(size_t) , 1 , f );
	fread_val = fread( b , sizeof(size_t) , 1 , f );

	fclose(f);
}


size_t power_modulo(size_t a, size_t b, size_t n)
{
	long x = 1;
	long y = a;

	while ( b > 0 )
	{
		if ( b % 2 )
			x = (x * y) % n;

		// Square the base
		y = ( y * y ) % n;

		b = b / 2;
	}
	return x % n;
}


void rsa_encrypt( char* input_file , char* output_file , char* key_file )
{
	// read key
	size_t n;
	size_t d_or_e;
	read_key_from_file( key_file , &n , &d_or_e );

	// read plaintext
	char* plaintext;
	size_t plaintext_length;
	file_to_string( input_file , &plaintext , &plaintext_length );
	
	// ciphertext size is 8 times larger than plaintext size
	size_t ciphertext[ plaintext_length ];

	// encrypt. For every char call power_modulo
	for( int i = 0 ; i < plaintext_length ; i++ )
		ciphertext[i] = power_modulo( (size_t) plaintext[i] , d_or_e , n );

	// store ciphertext
	FILE* f = fopen( output_file , "w" );
	if( !f )
	{
		perror( output_file );
		exit(-1);
	}
	fwrite( ciphertext , sizeof(size_t) , plaintext_length , f );

	fclose(f);
}


void rsa_decrypt( char* input_file , char* output_file , char* key_file )
{
	// read key
	size_t n;
	size_t d_or_e;
	read_key_from_file( key_file , &n , &d_or_e );

	// open file and find size
	FILE* f = fopen ( input_file , "r" );
	if ( !f )
	{
		perror( input_file );
		exit(-1);
	}
	fseek( f , 0 , SEEK_END );
	size_t size = ftell(f);
	fseek( f , 0 , SEEK_SET );

	// text length and arrays
	size_t text_length = size/8;
	size_t* ciphertext = malloc( sizeof( size_t ) * text_length );
	char* plaintext = malloc( sizeof( char ) * text_length );

	// read numbers from ciphertext
	int fread_val = fread( ciphertext , sizeof( size_t ) , text_length , f );

	// decrypt. For every ulong call power_modulo
	for( int i = 0 ; i < text_length ; i++ )
		plaintext[i] = (char) power_modulo( ciphertext[i] , d_or_e , n );

	// store plaintext
	string_to_file( output_file , plaintext , text_length );
}
