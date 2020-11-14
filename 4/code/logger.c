#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <openssl/md5.h>


void file_fingerprint( FILE* file , unsigned char* fingerprint );


FILE* fopen( const char* path , const char* mode ) 
{
	// get UID
	uid_t user_id = getuid();

	// get time & data
	time_t t;
    time(&t);

	// get access type
	uint access_type = 0;
	if( access( path, F_OK ) != -1 )
		access_type = 1;  // file existed
	if( *mode == 'w' ) // Even if file existed, its content is erased and the file is considered as a new empty file
		access_type = 0;
		
	// call the original fopen function
	FILE* original_fopen_ret;
	FILE* (*original_fopen)( const char* , const char* );
	original_fopen = dlsym( RTLD_NEXT , "fopen" );
	original_fopen_ret = (*original_fopen)( path , mode );

	// check if action denied
	uint action_denied = 0;
	if( original_fopen_ret )
		action_denied = 1;
		
	// get actual path
	char actual_path[PATH_MAX+1];
	char* actual_path_pointer = realpath( path , actual_path ); // Null if error
	
	// create file fingerprint
	unsigned char fingerprint[16];
	
	file_fingerprint( original_fopen_ret , fingerprint );

	// Log to file
	FILE* log = (*original_fopen)( "file_logging.log" , "a" );

	fprintf( log , "%u %u %u %s " , user_id , access_type , action_denied , actual_path );
	for(int i = 0; i < 16; i++)
		fprintf( log , "%02x", (unsigned int)fingerprint[i]);
	fprintf( log , " %s" , ctime(&t) );

	fclose(log);

	return original_fopen_ret;
}


size_t fwrite( const void* ptr , size_t size , size_t nmemb , FILE* stream ) 
{

	size_t original_fwrite_ret;
	size_t (*original_fwrite)( const void* , size_t , size_t , FILE* );

	/* call the original fwrite function */
	original_fwrite = dlsym( RTLD_NEXT, "fwrite" );
	original_fwrite_ret = (*original_fwrite)( ptr , size , nmemb , stream );


	return original_fwrite_ret;
}


void file_fingerprint( FILE* file , unsigned char* fingerprint )
{
	long length = 0;
	char* string;
	if( file )
	{
		fseek( file , 0 , SEEK_END );
		length = ftell(file);
		fseek( file , 0 , SEEK_SET );

		string = malloc( length );
		int fread_value = fread( string , 1 , length , file );

	}
	MD5_CTX context;

	MD5_Init( &context );

	MD5_Update( &context , string , length );

	MD5_Final( fingerprint , &context );
}