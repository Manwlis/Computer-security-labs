#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <pwd.h>


typedef struct entry
{
	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	time_t date_time; /* file access time */

	char* file; /* filename (string) */
	char* fingerprint; /* file fingerprint */
} entry;


void usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-v, Prints the total number of files created in the last 20 minutes\n"
		   "-e, Prints all the files that were encrypted by the ransomware\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}

// Creates an array of entries from the .log file
void get_entries( FILE* log , entry* entries , int num_entries )
{
	for(int i = 0 ; i < num_entries ; i++ )
	{
		char* line;
		size_t line_length = 0;
		getline( &line , &line_length , log );

		entries[i].uid = atoi( strtok( line , " " ) );
		entries[i].access_type = atoi( strtok( NULL , " " ) );
		entries[i].action_denied = atoi( strtok( NULL , " " ) );
		entries[i].file = strtok( NULL , " " );
		entries[i].fingerprint = strtok( NULL , " " );
		entries[i].date_time = atol( strtok( NULL , "\0" ) );
	}
}

void list_unauthorized_accesses( FILE* log )
{
	// get log file's size
	int num_entries = 0;
	while (EOF != ( fscanf( log , "%*[^\n]" ) , fscanf( log , "%*c" ) ) )
        num_entries++;
	fseek( log , 0 , SEEK_SET );

	// get entries from log file
	struct entry entries[num_entries];
	get_entries( log , entries , num_entries );

	// create array with users
	int num_users = 0;
	int users[num_entries]; // worst case is every entry is from another user
	// for every entry
	for( int i = 0 ; i < num_entries ; i++ )
	{
		uint duplicate = 0;
		// if it's user is already in the user table
		for(int k = 0 ; k < num_users ; k++)
			if( entries[i].uid == users[k] )
				duplicate = 1; // user has already been recorded

		// if not found
		if( duplicate == 0 )
		{ // put him in
			users[num_users] = entries[i].uid;
			num_users++;
		}
	}

	// get unauthorized accesses for each user
	int unauthorized_accesses[num_users];
	for( int i = 0 ; i < num_users ; i++ ) // init table
		unauthorized_accesses[i] = 0;
	// for every entry
	for( int i = 0 ; i < num_entries ; i++ )
		// that got denied
		if( entries[i].action_denied == 1 )
			// find it's user
			for( int k = 0 ; k < num_users ; k++ )
				// in the user table
				if( entries[i].uid == users[k] )
					//and increment his unauthorized accesses counter
					unauthorized_accesses[k]++;

	// print malicious users
	for(int i = 0 ; i < num_users ; i++ )
		if( unauthorized_accesses[i] > 7 )
			printf("%s\n" , getpwuid( users[i] )->pw_name );
}


void list_file_modifications( FILE *log , char *file_to_scan )
{
	// get log file's size
	int num_entries = 0;
	while (EOF != ( fscanf( log , "%*[^\n]" ) , fscanf( log , "%*c" ) ) )
        num_entries++;
	fseek( log , 0 , SEEK_SET );

	// get entries from log file
	struct entry entries[num_entries];
	get_entries( log , entries , num_entries );

	// create array with users
	int num_users = 0;
	int users[num_entries]; // worst case is every entry is from another user
	// for every entry
	for( int i = 0 ; i < num_entries ; i++ )
	{
		uint duplicate = 0;
		// if it's user is already in the user table
		for(int k = 0 ; k < num_users ; k++)
			if( entries[i].uid == users[k] )
				duplicate = 1; // user has already been recorded

		// if not found
		if( duplicate == 0 )
		{ // put him in
			users[num_users] = entries[i].uid;
			num_users++;
		}
	}

	int changes_per_user[num_users];
	for( int i = 0 ; i < num_users ; i++ )
		changes_per_user[i] = 0;

	char actual_path[PATH_MAX+1];
	realpath( file_to_scan , actual_path );
	char previous_fingerprint[33] = " ";
	// for every entry
	for( int i = 0 ; i < num_entries ; i++ )
	{
		// that match the file, has different fingerprint from its last occurent
		if( !strcmp( entries[i].file , actual_path ) && strcmp( entries[i].fingerprint , previous_fingerprint ) != 0 )
		{
			// increment its user's changes
			for( int k = 0 ; k < num_users ; k++ )
			{	// if he changed the file ( not denied and not open )
				if( entries[i].uid == users[k] && entries[i].access_type != 1 && entries[i].action_denied != 1 )
				{
					changes_per_user[k]++;

					// change last occurrence fingerprint
					strcpy( previous_fingerprint , entries[i].fingerprint );
				}
			}
		}
	}
	for( int i = 0 ; i < num_users ; i++ )
		printf("%s	%d\n" , getpwuid( users[i] )->pw_name , changes_per_user[i] );

	return;
}


void num_files_created_20m( FILE *log , int suspicious_behavior )
{
	// get log file's size
	int num_entries = 0;
	while (EOF != ( fscanf( log , "%*[^\n]" ) , fscanf( log , "%*c" ) ) )
		num_entries++;
	fseek( log , 0 , SEEK_SET );

	// get entries from log file
	struct entry entries[num_entries];
	get_entries( log , entries , num_entries );

	// get time 20 min ago
	time_t twenty_minutes_ago = time(NULL) - 20*60;

	// how many files were created in last 20 minutes
	int num_created_files = 0;

	// for every entry
	for( int i = 0 ; i < num_entries ; i++ )
		// that is in the timeframe
		if( entries[i].date_time > twenty_minutes_ago )
			// and a file was successfully created
			if( entries[i].access_type == 0 && entries[i].action_denied == 0 )
				// increment the counter
				num_created_files++;

	printf( "Num created files in last 20 minutes: %d\n" , num_created_files );
	if( num_created_files >= suspicious_behavior )
		printf("Suspicious behaviour\n");
	else
		printf("No suspicious behaviour\n");
}


// Used by list_encrypted_files function to find the extension of a file.
const char* get_filename_ext( const char *filename )
{
	const char *dot = strrchr( filename , '.' );
	if( !dot || dot == filename ) 
		return "";
}


// If a "name".encrypt file was created, then the "name" file was encrypted and the function prints it.
void list_encrypted_files( FILE *log )
{
	// get log file's size
	int num_entries = 0;
	while (EOF != ( fscanf( log , "%*[^\n]" ) , fscanf( log , "%*c" ) ) )
		num_entries++;
	fseek( log , 0 , SEEK_SET );

	// get entries from log file
	struct entry entries[num_entries];
	get_entries( log , entries , num_entries );

	// for every entry
	for( int i = 0 ; i < num_entries ; i++ )
		// if it the successful creation of a file
		if( entries[i].access_type == 0 && entries[i].action_denied == 0 )
			// and if the file has the suffix ".encrypt"
			if( strcmp( get_filename_ext( entries[i].file ) , ".encrypt" ) == 0 )
			{
				// remove suffix to get the name of the original file
				char copy [ PATH_MAX+1 ];
				strcpy( copy , entries[i].file );
				*strrchr( copy , '.' ) = '\0';
				// and print it
				printf( "%s\n" , copy );
			}
}


int main( int argc , char *argv[] )
{
	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ( ( ch = getopt( argc , argv , "hiv:me" ) ) != -1 )
	{
		switch (ch)
		{		
		case 'i':
			list_file_modifications( log , optarg );
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		case 'v':
			num_files_created_20m( log , atoi( optarg ) );
			break;
		case 'e':
			list_encrypted_files( log );
			break;
		default:
			usage();
		}
	}

	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
