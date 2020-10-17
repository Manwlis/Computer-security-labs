#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


/************************************
Read input of variable size.
@param FILE* input stream.
@return char* created string.
************************************/
char * input_string( FILE* input )
{
	size_t size = 10; // start size
	char *str;
	int ch;
	size_t len = 0;

	str = malloc( sizeof( char ) * size );

	while( EOF != ( ch = fgetc ( input ) ) && ch != '\n' )
	{
		str[ len++ ] = ch;
		if( len == size )
			str = realloc( str , sizeof( char ) * ( size += 10 ) );

	}
	str[ len++ ]= '\0';

	return realloc( str , sizeof( char ) * len );
}


/************************************
Strip a string from non-alphanumeric characters
@param char* nonstriped string.
@return a char* striped string of equal or less lenght.
************************************/
char * strip_string( char* dirty_str )
{
	size_t len = 0;
	char * clean_str =  malloc( ( sizeof( char ) + 1 ) * strlen( dirty_str ) ); // +1 for the \0

	for( int i = 0 ; i < strlen( dirty_str ) ; i++ )
	{
		if ( isalnum( dirty_str[i] ) )
			clean_str[ len++ ] = dirty_str[i];
	}
	clean_str[ len++ ] = '\0';

	return realloc( clean_str , sizeof( char ) * len);
}


int main( void )
{
    char *plaintext;
	char *key;

    printf( "[OTP] input: " );
    plaintext = input_string( stdin );
	plaintext = strip_string( plaintext );

	printf( "[OTP] encrypted: %s\n" , plaintext ); // plaintext -> otp_encrypt
	printf( "[OTP] decrypted: %s\n" , plaintext ); // plaintext -> otp_decrypt


    printf( "[Caesars] input: " );
    plaintext = input_string( stdin );
	printf( "[Caesars] key: " );
    key = input_string( stdin );

	printf( "[Caesars] encrypted: %s\n" , plaintext ); // plaintext -> caesars_encrypt
	printf( "[Caesars] decrypted: %s\n" , plaintext ); // plaintext -> caesars_decrypt


    printf( "[Vigenere] input: " );
    plaintext = input_string( stdin );
	printf( "[Vigenere] key: " );
    key = input_string( stdin );

	printf( "[Vigenere] encrypted: %s\n" , plaintext ); // plaintext -> vigenere_encrypt
	printf( "[Vigenere] decrypted: %s\n" , plaintext ); // plaintext -> vigenere_decrypt

    free( plaintext );
    return 0;
}