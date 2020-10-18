#include "simple_crypto.h"


/***************** OTP *****************/

char* otp_encrypt( char* message )
{
    // same size as message, +1 and \0 in last potision if I need to print it
    otp_key = malloc( sizeof( char ) * strlen( message ) ); 
    char* ciphertext = malloc( sizeof( char ) * ( strlen( message ) + 1 ) ); // +1 for the \0

    // open urandom as file
    FILE* urandom = fopen( "/dev/urandom", "r" );

    size_t index = 0;
    while(  index < strlen( message ) )
    {
        otp_key[index] = fgetc( urandom ); // get a random character
        ciphertext[index] = message[index] ^ otp_key[index]; // XOR message with key
        // if ciphertext[index] is a printable character, keep it. Else do it again
        if( ciphertext[index] >= 33 && ciphertext[index] != 127 ) // 127 = DEL
            index++;
    }
    return ciphertext;
}

char* otp_decrypt( char* ciphertext )
{
    char* decrypted_text =  malloc( sizeof( char ) * ( strlen( ciphertext ) + 1 ) ); // +1 for the \0

    for( size_t i = 0 ; i < strlen( ciphertext ) ; i++ )
    {
        decrypted_text[i] = ciphertext[i] ^ otp_key[i];
    }
    // key isn't needed anymore
    free(otp_key);
    return decrypted_text;
}


/***************** Caesars *****************/

char* caesars_encrypt( char* message , int key )
{
    char* ciphertext =  malloc( sizeof( char ) * ( strlen( message ) + 1 ) ); // +1 for the \0

    strcpy( ciphertext , message );

    return ciphertext;
}

char* caesars_decrypt( char* ciphertext , int key )
{
    char* decrypted_text =  malloc( sizeof( char ) * ( strlen( ciphertext ) + 1 ) ); // +1 for the \0

    strcpy( decrypted_text , ciphertext );

    return decrypted_text;
}


/***************** Vigenere *****************/

char* vigenere_encrypt( char* message , char* key )
{
    char* ciphertext =  malloc( sizeof( char ) * ( strlen( message ) + 1 ) ); // +1 for the \0

    strcpy( ciphertext , message );

    return ciphertext;
}

char* vigenere_decrypt( char* ciphertext , char* key )
{
    char* decrypted_text =  malloc( sizeof( char ) * ( strlen( ciphertext ) + 1 ) ); // +1 for the \0

    strcpy( decrypted_text , ciphertext );

    return decrypted_text;
}