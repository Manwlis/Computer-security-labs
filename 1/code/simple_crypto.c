#include "simple_crypto.h"


/***************** OTP *****************/

char* otp_encrypt( char* message , char** otp_key )
{
	// same size as message, +1 and \0 in last potision if I need to print it
	*otp_key = malloc( sizeof( char ) * strlen( message ) );

	char* ciphertext = malloc( sizeof( char ) * ( strlen( message ) + 1 ) ); // +1 for the \0
	ciphertext[ strlen( message ) ] = '\0';

	// open urandom as file
	FILE* urandom = fopen( "/dev/urandom", "r" );

	size_t index = 0;
	while( index < strlen( message ) )
	{
		(*otp_key)[index] = fgetc( urandom ); // get a random character
		ciphertext[index] = message[index] ^ (*otp_key)[index]; // XOR message with key
		// if ciphertext[index] is a printable character, keep it. Else do it again
		if( ciphertext[index] >= 33 && ciphertext[index] != 127 ) // 127 = DEL
			index++;
	}
	return ciphertext;
}

char* otp_decrypt( char* ciphertext , char* otp_key )
{
	char* decrypted_text = malloc( sizeof( char ) * ( strlen( ciphertext ) + 1 ) ); // +1 for the \0
	decrypted_text[ strlen( ciphertext ) ] = '\0';

	//XOR second time with key. ciphertext -> original message
	for( size_t i = 0 ; i < strlen( ciphertext ) ; i++ )
		decrypted_text[i] = ciphertext[i] ^ otp_key[i];

	return decrypted_text;
}


/***************** Caesars *****************/

// Legal characters for caesars encryption
const char caesars_dictionary[] = {"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwyz"};

char* caesars_encrypt( char* message , int key, char* dictionary )
{
	// no dictionary was provided, use the default one
	if( dictionary == NULL)
		dictionary = (char*) (&caesars_dictionary);
	int dict_size = strlen( dictionary );

	char* ciphertext = malloc( sizeof( char ) * ( strlen( message ) + 1 ) ); // +1 for the \0
	ciphertext[ strlen( message ) ] = '\0';

	// there is no point to make more shift than the size of the dictionary.
	// shift(strlen(dictionary)*k + i) == shift(i), k = 0, 1, 2 ...
	key = key % strlen( dictionary );
	// shift each character
	for( size_t i = 0 ; i < strlen( message ) ; i++ )
	{
		// distance between character and the start of the array 
		int start_position = (int) ( strchr( dictionary , message[i] ) - dictionary );

		// out of dictionary
		if( start_position + key >= dict_size )
			// continue from the start
			ciphertext[i] = dictionary[ start_position + key - dict_size ];
		else
			ciphertext[i] = dictionary[ start_position + key ];
	}

	return ciphertext;
}

char* caesars_decrypt( char* ciphertext , int key, char* dictionary )
{
	// no dictionary was provided, use the default one
	if( dictionary == NULL)
		dictionary = (char*) (&caesars_dictionary);
	int dict_size = strlen( dictionary );

	char* decrypted_text = malloc( sizeof( char ) * ( strlen( ciphertext ) + 1 ) ); // +1 for the \0
	decrypted_text[ strlen( ciphertext ) ] = '\0';

	// there is no point to make more shift than the size of the dictionary.
	// shift(strlen(dictionary)*k + i) == shift(i), k = 0, 1, 2 ...
	key = key % strlen( dictionary );
	// shift each character
	for( size_t i = 0 ; i < strlen( ciphertext ) ; i++ )
	{
		// distance between character and the start of the array 
		int start_position = (int) ( strchr( dictionary , ciphertext[i] ) - dictionary );

		// out of dictionary
		if( start_position - key < 0 )
			// continue from the end
			decrypted_text[i] = dictionary[ start_position - key + dict_size ];
		else
			decrypted_text[i] = dictionary[ start_position - key ];
	}
	return decrypted_text;
}


/***************** Vigenere *****************/

const char vigenere_dictionary[] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZ"};

char* vigenere_encrypt( char* message , char* key , char* dictionary )
{
	// no dictionary was provided, use the default one
	if( dictionary == NULL)
		dictionary = (char*) (&vigenere_dictionary);
	int dict_size = strlen( dictionary );

	char* ciphertext = malloc( sizeof( char ) * ( strlen( message ) + 1 ) ); // +1 for the \0
	ciphertext[ strlen( message ) ] = '\0';

	// translate key to shifts
	size_t key_size = strlen( key );
	int shifts[key_size];

	for( size_t i = 0 ; i < key_size ; i++ )
		shifts[i] = (int) ( strchr( dictionary , key[i] ) - dictionary );

	// create ciphertext
	size_t key_index = 0;
	for( size_t i = 0 ; i < strlen( message ) ; i++ )
	{
		// distance between character and the start of the array 
		int start_position = (int) ( strchr( dictionary , message[i] ) - dictionary );

		// out of dictionary
		if( start_position + shifts[key_index] >= dict_size )
			// continue from the start
			ciphertext[i] = dictionary[ start_position + shifts[key_index] - dict_size ];
		else
			ciphertext[i] = dictionary[ start_position + shifts[key_index] ];

		key_index++; // next key digit
		if( key_index == key_size) // used all of the key
			key_index = 0; // continue from the start of the key
	}
	return ciphertext;
}

char* vigenere_decrypt( char* ciphertext , char* key , char* dictionary )
{
	// no dictionary was provided, use the default one
	if( dictionary == NULL)
		dictionary = (char*) (&vigenere_dictionary);
	int dict_size = strlen( dictionary );

	char* decrypted_text = malloc( sizeof( char ) * ( strlen( ciphertext ) + 1 ) ); // +1 for the \0
	decrypted_text[ strlen( ciphertext ) ] = '\0';

	// translate key to shifts
	size_t key_size = strlen( key );
	int shifts[key_size];

	for( size_t i = 0 ; i < key_size ; i++ )
		shifts[i] = (int) ( strchr( dictionary , key[i] ) - dictionary );

	// decrypt ciphertext
	size_t key_index = 0;
	for( size_t i = 0 ; i < strlen( ciphertext ) ; i++ )
	{
		// distance between character and the start of the array 
		int start_position = (int) ( strchr( dictionary , ciphertext[i] ) - dictionary );

		// out of dictionary
		if( start_position - shifts[key_index] < 0 )
			// continue from the start
			decrypted_text[i] = dictionary[ start_position - shifts[key_index] + dict_size ];
		else
			decrypted_text[i] = dictionary[ start_position - shifts[key_index] ];

		key_index++; // next key digit
		if( key_index == key_size) // used all of the key
			key_index = 0; // continue from the start of the key
	}
	return decrypted_text;
}