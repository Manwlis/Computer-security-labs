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
		   "-h, Help message\n\n"
		   );

	exit(1);
}


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
		// that match the file and has different fingerprint from its last occurent
		if( !strcmp( entries[i].file , actual_path ) && strcmp( entries[i].fingerprint , previous_fingerprint ) != 0 )
		{
			// change last occurrence fingerprint
			strcpy( previous_fingerprint , entries[i].fingerprint );
			// increment user's changes.
			for( int k = 0 ; k < num_users ; k++ )
			{
				if( entries[i].uid == users[k] )
					changes_per_user[k]++;
			}
		}
	}
	for( int i = 0 ; i < num_users ; i++ )
		printf("%s	%d\n" , getpwuid( users[i] )->pw_name , changes_per_user[i] );

	return;
}


int main(int argc, char *argv[])
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

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
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
