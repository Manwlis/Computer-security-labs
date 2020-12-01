#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <linux/limits.h>

// Creates argv[2] empty files in argv[1] directory.
int main( int argc, char *argv[] ) 
{
	if ( argc != 3 )
	{
		printf( "Wrong number of arguments\n" );
		exit( -1 );
	}
	int limit = atoi( argv[2] );

	for( int i = 0 ; i < limit ; i++ )
	{
		char name[ PATH_MAX + 15 ];
		sprintf( name , "%s/file_%d" , argv[1] , i );

		FILE *file = fopen( name , "w+" ); // file creation
		if ( file == NULL ) 
		{
			printf( "fopen error\n" );
			fflush( stdout );
		}
		else
		{
			fprintf( file , "%s" , name );
			fclose( file );
		}
	}
}