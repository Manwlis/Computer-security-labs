#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include "simple_crypto.h"

// malloc kai files perror?

/************************************
Read input of variable size.
@param FILE* input stream.
@return char* created string.
************************************/
char* input_string( FILE* input )
{
	size_t size = 10; // start size
	char* str;
	int ch;
	size_t len = 0;

	str = malloc( sizeof( char ) * size );

	while( EOF != ( ch = fgetc ( input ) ) && ch != '\n' && ch != '\0' )
	{
		str[ len++ ] = ch;
		if( len == size )
			str = realloc( str , sizeof( char ) * ( size += 10 ) );
	}
	str[ len++ ]= '\0';

	return realloc( str , sizeof( char ) * len );
}


// Modes of operation for strip_string()
#define ALNUM 0
#define UPPER 1
/************************************
Strip a string from non-legal characters.
@param char* nonstriped string.
@param int mode of operation. ALNUM(0) to strip non-alphanumeric, UPPER(1) to strip non-uppercase.
@return a char* striped string of equal or less lenght.
************************************/
char* strip_string( char* dirty_str , int mode )
{
	size_t len = 0;
	char* clean_str =  malloc( sizeof( char ) * ( strlen( dirty_str ) + 1 )  ); // +1 for the \0

	if( mode == ALNUM )
	{
		for( size_t i = 0 ; i < strlen( dirty_str ) ; i++ )
		{
			if ( isalnum( dirty_str[i] ) )
				clean_str[ len++ ] = dirty_str[i];
		}
	}
	else
	{
		for( size_t i = 0 ; i < strlen( dirty_str ) ; i++ )
		{
			if ( isupper( dirty_str[i] ) )
				clean_str[ len++ ] = dirty_str[i];
		}
	}
	clean_str[ len++ ] = '\0';
	
	return realloc( clean_str , sizeof( char ) * len);
}


int main( void )
{
	char* input;
    char* plaintext;
	char* ciphertext;
	char* decrypted_text;
	char* input_key;
	char* key;
	uint caesars_key;

/***************** OTP *****************/
    printf( "[OTP] input: " );
	input = input_string( stdin ); // input can be any size
	plaintext = strip_string( input , ALNUM ); // skip non-alphanumeric

	// input was a redirected file (<). Print it.
	if ( !isatty(STDIN_FILENO) )
		printf("%s\n", plaintext);

	ciphertext = otp_encrypt( plaintext );
	printf( "[OTP] encrypted: %s\n" , ciphertext );
	decrypted_text = otp_decrypt( ciphertext );
	printf( "[OTP] decrypted: %s\n" , decrypted_text );

	free( input );
	free( plaintext );
	free( ciphertext );
	free( decrypted_text );

/***************** Caesars *****************/
    printf( "[Caesars] input: " );
	input = input_string( stdin );
	plaintext = strip_string( input , ALNUM ); // skip non-alphanumeric

	// input was a redirected file (<). Print it.
	if ( !isatty(STDIN_FILENO) )
		printf("%s\n", plaintext);

	printf( "[Caesars] key: " );
    caesars_key = atoi ( input_string( stdin ) );

	// input was a redirected file (<). Print it.
	if ( !isatty(STDIN_FILENO) )
		printf("%d\n", caesars_key);

	ciphertext = caesars_encrypt( plaintext , caesars_key );
	printf( "[Caesars] encrypted: %s\n" , ciphertext );
	decrypted_text = caesars_decrypt( ciphertext , caesars_key );
	printf( "[Caesars] decrypted: %s\n" , decrypted_text );

	free( input );
	free( plaintext );
	free( ciphertext );
	free( decrypted_text );

/***************** Vigenere *****************/
    printf( "[Vigenere] input: " );
	input = input_string( stdin );
	plaintext = strip_string( input , UPPER ); // skip non-uppercase

	// input was a redirected file (<). Print it.
	if ( !isatty(STDIN_FILENO) )
		printf("%s\n", plaintext);

	printf( "[Vigenere] key: " );
    input_key = input_string( stdin );
	key = strip_string( input_key , UPPER ); // skip non-uppercase
	
	// input was a redirected file (<). Print it.
	if ( !isatty(STDIN_FILENO) )
		printf("%s\n", key);

	ciphertext = vigenere_encrypt( plaintext , key );
	printf( "[Vigenere] encrypted: %s\n" , ciphertext );
	decrypted_text = vigenere_decrypt( ciphertext , key );
	printf( "[Vigenere] decrypted: %s\n" , decrypted_text );

	free( input );
	free( plaintext );
	free( key );
	free( ciphertext );
	free( decrypted_text );

    return 0;
}


