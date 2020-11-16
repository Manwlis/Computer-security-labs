#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <linux/limits.h>
#include <errno.h>


FILE* fopen( const char* path , const char* mode ) 
{
	// get UID
	uid_t user_id = getuid();

	// get time & data
	time_t t;
	time(&t);

	// get access type
	uint access_type = 0;
	if( access( path, F_OK ) != -1 || *mode == 'r' )
		access_type = 1;  // file existed or read mode
	if( *mode == 'w' ) // Even if file existed, its content is erased and the file is considered as a new empty file
		access_type = 0;

	// call the original fopen function
	FILE* original_fopen_ret;
	FILE* (*original_fopen)( const char* , const char* );
	original_fopen = dlsym( RTLD_NEXT , "fopen" );
	original_fopen_ret = (*original_fopen)( path , mode );

	// check if action denied
	uint action_denied = 0;
	if( !original_fopen_ret && ( errno == EACCES || errno == EBADF ) )
		action_denied = 1;

	// get actual path
	char actual_path[PATH_MAX+1];
	realpath( path , actual_path );

	// create file fingerprint
	unsigned char fingerprint[MD5_DIGEST_LENGTH];

	// get files size
	int current_pos = ftell( original_fopen_ret );
	fseek( original_fopen_ret , 0 , SEEK_END );
	int length = ftell( original_fopen_ret );

	// read file
	fseek( original_fopen_ret , 0 , SEEK_SET );
	char buf[length];
	fread( buf , 1 , length , original_fopen_ret );

	// reset seek
	fseek( original_fopen_ret , 0 , current_pos );

	// create fingerprint
	MD5_CTX context;
	MD5_Init( &context );
	MD5_Update( &context , buf , length );
	MD5_Final( fingerprint , &context );

	// Log to file
	FILE* log = (*original_fopen)( "file_logging.log" , "a" );

	fprintf( log , "%u %u %u %s " , user_id , access_type , action_denied , actual_path );
	for(int i = 0; i < MD5_DIGEST_LENGTH; i++)
		fprintf( log , "%02x", (unsigned int)fingerprint[i] );
	fprintf( log , " %ld\n" , t );

	fclose(log);

	return original_fopen_ret;
}


size_t fwrite( const void* ptr , size_t size , size_t nmemb , FILE* stream ) 
{
	// get UID
	uid_t user_id = getuid();

	// get time & data
	time_t t;
    time(&t);

	// get access type
	uint access_type = 2;

	/* call the original fwrite function */
	size_t original_fwrite_ret;
	size_t (*original_fwrite)( const void* , size_t , size_t , FILE* );
	original_fwrite = dlsym( RTLD_NEXT, "fwrite" );
	original_fwrite_ret = (*original_fwrite)( ptr , size , nmemb , stream );

	// check if action denied
	uint action_denied = 0;
	if( !original_fwrite_ret && ( errno == EACCES || errno == EBADF ) )
		action_denied = 1;

	// get actual path
	char path[PATH_MAX+1];
	char proclnk[PATH_MAX+1];

	int fd; // file desctriptor
	fd = fileno( stream ); // from file pointer

	sprintf(proclnk, "/proc/self/fd/%d", fd);
	ssize_t bytes = readlink(proclnk, path, PATH_MAX);
	path[bytes] = '\0';

	// create file fingerprint
	unsigned char fingerprint[MD5_DIGEST_LENGTH];

	// get files size
	int current_pos = ftell(stream);
	fseek( stream , 0 , SEEK_END );
	int length = ftell(stream);

	// read file
	fseek( stream , 0 , SEEK_SET );
	char buf[length];
	fread( buf , 1 , length , stream );

	// reset seek
	fseek( stream , 0 , current_pos );

	// create fingerprint
	MD5_CTX context;
	MD5_Init( &context );
	MD5_Update( &context , buf , length );
	MD5_Final( fingerprint , &context );

	// Log to file
	FILE* (*original_fopen)( const char* , const char* );
	original_fopen = dlsym( RTLD_NEXT , "fopen" );
	FILE* log = (*original_fopen)( "file_logging.log" , "a" );

	fprintf( log , "%u %u %u %s " , user_id , access_type , action_denied , path );
	for(int i = 0; i < MD5_DIGEST_LENGTH; i++)
		fprintf( log , "%02x", (unsigned int)fingerprint[i]);
	fprintf( log , " %ld\n" , t );

	fclose(log);

	return original_fwrite_ret;
}