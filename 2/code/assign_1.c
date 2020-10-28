/* 
assign_2.c
Tool to encrypt, decrypt, sign and verify files using openSSL library.
Created: 26/10/2020
Author: Emmanouil Petrakos
Developed with VScode 1.50.1 on WSL2
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16
// CMAC size is 128 bits according to https://tools.ietf.org/html/rfc4493
#define CMAC_SIZE 16


/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
void encrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int );
int decrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);

/*
* Move data from a file to a sting.
* @param char* file path
* @param char** output string
* @param long* output size
*/
void file_to_string( char* input_file , char** string , long* length );

/*
* Move data from a string to a file.
* @param char* file path
* @param char* output string
*/
void string_to_file( char* output_file , char* string , long length );


/*
 * Prints the hex value of the input
 * 16 values per line
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 */
void
print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void
check_args(char *input_file, char *output_file, unsigned char *password, 
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


/*
 * Generates a key using a password
 */
void
keygen(unsigned char *password, unsigned char *key, unsigned char *iv, int bit_mode)
{
    const EVP_MD *dgst = EVP_get_digestbyname("SHA1");

	const EVP_CIPHER *cipher;
	if( bit_mode == 128 )
    	cipher = EVP_aes_128_ecb();
    else
		cipher = EVP_aes_256_ecb();
	
	// This function is used to derive keying material for an encryption algorithm from a password in the data parameter.
	EVP_BytesToKey( cipher , dgst , NULL , (unsigned char *) password , strlen( (char*) password ) , 1 , key , iv );
}


/*
 * Encrypts the data
 */
void
encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int bit_mode)
{
	// set up a context
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	int len;

	// initialise encryption operation
	const EVP_CIPHER* cipher;
	if( bit_mode == 128 )
		cipher = EVP_aes_128_ecb();
	else
		cipher = EVP_aes_256_ecb();

	EVP_EncryptInit_ex( ctx , cipher , NULL , key , iv );
	
	// start encryption
	EVP_EncryptUpdate( ctx , ciphertext , &len , plaintext , plaintext_len );

	// finalize encryption, encrypts the "final" data.
	EVP_EncryptFinal_ex( ctx , ciphertext + len , &len );

	// clean up
	EVP_CIPHER_CTX_free(ctx);
}


/*
 * Decrypts the data and returns the plaintext size
 */
int
decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext, int bit_mode)
{
	int plaintext_len;
	int len;
	// set up a context
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	
	// initialise encryption operation
	const EVP_CIPHER* cipher;
	if( bit_mode == 128 )
		cipher = EVP_aes_128_ecb();
	else
		cipher = EVP_aes_256_ecb();

	EVP_DecryptInit_ex( ctx , cipher , NULL , key , iv );

	// start decryption
	EVP_DecryptUpdate( ctx , plaintext , &len , ciphertext , ciphertext_len );
	plaintext_len = len;

	// finalise decryption
	EVP_DecryptFinal_ex( ctx , plaintext + len , &len );
	plaintext_len += len;

	// clean up
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}


/*
 * Generates a CMAC
 */
void
gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, unsigned char *cmac, int bit_mode)
{
	size_t cmac_len = 0;
	// set up a context
	CMAC_CTX* ctx = CMAC_CTX_new();

	// initialise signing operation
	const EVP_CIPHER* type;
	if( bit_mode == 128 )
		type = EVP_aes_128_ecb();
	else
		type = EVP_aes_256_ecb();

	CMAC_Init( ctx , key , bit_mode/8 , type , NULL );

	// start signing
	CMAC_Update( ctx , data , data_len );

	// finalize signing
	CMAC_Final( ctx , cmac , &cmac_len );

	// clean up
	CMAC_CTX_free(ctx);
}


/*
 * Verifies a CMAC
 */
int
verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
	for ( int i = 0 ; i < CMAC_SIZE ; i++ )
		if( cmac1[i] != cmac2[i] )
			return 0;

	return 1;
}


void file_to_string( char* input_file , char** string , long* length )
{
	FILE* f = fopen ( input_file , "r" );

	if (f)
	{
		fseek( f , 0 , SEEK_END );
		*length = ftell(f);
		fseek( f , 0 , SEEK_SET );

		*string = malloc( *length );
		int fread_value = fread( *string , 1 , *length , f );

		fclose (f);
	}
	else
	{
		perror( "file_to_string" );
		exit(-1);
	}
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
		perror( "string_to_file" );
		exit(-1);
	}
}


/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;


	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 0 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 2 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 3 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}

	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);


	/* -------------------------------------------------------------------------- */
	// read FILE
	unsigned char* input_string = NULL;
	long input_size;
	file_to_string( input_file , (char**) &input_string , &input_size);
	
	// make all algorithms available to the EVP* routines
	OpenSSL_add_all_algorithms();

	/* Key generation from password */
	unsigned char key[bit_mode / 8]; // char size is in bytes
	keygen( password , key , NULL , bit_mode );

	/* encrypt */
	if( op_mode == 0 )
	{
		// aes ecb encryption is done in blocks. Ciphertext's size != paintext's size due to padding
		long ciphertext_size = (input_size/BLOCK_SIZE + 1) * BLOCK_SIZE;
		unsigned char ciphertext[ ciphertext_size ];
		// encrypt plaintext
		encrypt( input_string , input_size , key , NULL , ciphertext , bit_mode );
		// save to file
		string_to_file( output_file , (char*) ciphertext , ciphertext_size );
	}
	/* decrypt */
	else if( op_mode == 1 )
	{
		unsigned char plaintext[ input_size ];
		// decrypt ciphertext
		int plaintext_size = decrypt( input_string , input_size , key , NULL , plaintext , bit_mode );
		// save to file
		string_to_file( output_file , (char*) plaintext , plaintext_size );
	}
	/* encrypt and sign */
	else if( op_mode == 2 )
	{
		// encrypt
		long ciphertext_size = ( input_size / BLOCK_SIZE + 1 ) * BLOCK_SIZE;
		unsigned char ciphertext[ ciphertext_size ];
		encrypt( input_string , input_size , key , NULL , ciphertext , bit_mode );

		// generate CMAC
		unsigned char cmac[ CMAC_SIZE ];
		gen_cmac( input_string , input_size , key, cmac , bit_mode );

		// concat cypher with cmac
		unsigned char ciphertext_with_cmac[ ciphertext_size + CMAC_SIZE ];
		for( int i = 0 ; i < ciphertext_size ; i++ )
			ciphertext_with_cmac[i] = ciphertext[i];
		for( int i = ciphertext_size ; i < ciphertext_size + CMAC_SIZE ; i++ )
			ciphertext_with_cmac[i] = cmac[ i - ciphertext_size ];

		// save to file
		string_to_file( output_file , (char*) ciphertext_with_cmac , ciphertext_size + CMAC_SIZE );
	}
	/* decrypt and verify */
	else if( op_mode == 3 )
	{
		// separate cyphertext and CMAC
		long ciphertext_size = input_size - CMAC_SIZE;
		unsigned char ciphertext[ ciphertext_size ];
		unsigned char message_cmac[ CMAC_SIZE ];

		for( int i = 0 ; i < ciphertext_size ; i++ )
			ciphertext[i] = input_string[i];
		for( int i = ciphertext_size ; i < ciphertext_size + CMAC_SIZE ; i++ )
			message_cmac[ i - ciphertext_size ] = input_string[ i ];

		// decrypt ciphertext
		unsigned char plaintext[ ciphertext_size ];
		int plaintext_size = decrypt( ciphertext , ciphertext_size , key , NULL , plaintext , bit_mode );

		// generate CMAC
		unsigned char generated_cmac[ CMAC_SIZE ];
		gen_cmac( plaintext , plaintext_size , key, generated_cmac , bit_mode );

		// compare CMACs. If succesfully verified, save the plaintext
		if( verify_cmac( message_cmac , generated_cmac ) )
			string_to_file( output_file , (char*) plaintext , plaintext_size );
		else
			printf("The ciphertext is not verifed.\n");
	}	
	/* Clean up */
	free(input_file);
	free(output_file);
	free(password);

	return 0;
}