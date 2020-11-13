#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>

FILE* fopen( const char* path , const char* mode ) 
{

	FILE* original_fopen_ret;
	FILE* (*original_fopen)( const char* , const char* );


	if( access( path, F_OK ) != -1 )
	{
		printf("%s exists\n", path );
	}
	else
	{
		printf("%s created\n", path );
	}
	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */

	/* call the original fopen function */
	original_fopen = dlsym( RTLD_NEXT , "fopen" );
	original_fopen_ret = (*original_fopen)( path , mode );

	return original_fopen_ret;
}


size_t fwrite( const void* ptr , size_t size , size_t nmemb , FILE* stream ) 
{

	size_t original_fwrite_ret;
	size_t (*original_fwrite)( const void* , size_t , size_t , FILE* );

	/* call the original fwrite function */
	original_fwrite = dlsym( RTLD_NEXT, "fwrite" );
	original_fwrite_ret = (*original_fwrite)( ptr , size , nmemb , stream );


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	return original_fwrite_ret;
}


