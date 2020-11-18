#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>


int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[2][7] = { "file_0" , "file_1"  };

	// All of this should work if user has the appropriate rights
	// file_0 and file_1 created once
	for( int i = 0 ; i < 2 ; i++ )
	{
		file = fopen(filenames[i], "w+"); // file creation
		if (file == NULL) 
		{
			printf("fopen error\n");
			fflush(stdout);
		}
		else
		{
			fclose(file);
		}
	}

	file = fopen(filenames[0], "r"); // file_0 open once
	if (file == NULL) 
		printf("fopen error\n");
	else
	{	// all should fail because file was opened with wrong mode
		bytes = fwrite(filenames[0], strlen(filenames[0]), 1, file); // file modification 5 times
		bytes = fwrite(filenames[0], strlen(filenames[0]), 1, file);
		bytes = fwrite(filenames[0], strlen(filenames[0]), 1, file);
		bytes = fwrite(filenames[0], strlen(filenames[0]), 1, file);
		bytes = fwrite(filenames[0], strlen(filenames[0]), 1, file);
		fclose(file);
	}

	file = fopen(filenames[1], "r+"); // file_1 open once
	if (file == NULL) 
		printf("fopen error\n");
	else
	{	// all should work if user has write rights
		bytes = fwrite(filenames[1], strlen(filenames[1]), 1, file); // file modification 5 times
		bytes = fwrite(filenames[1], strlen(filenames[1]), 1, file);
		bytes = fwrite(filenames[1], strlen(filenames[1]), 1, file);
		bytes = fwrite(filenames[1], strlen(filenames[1]), 1, file);
		bytes = fwrite(filenames[1], strlen(filenames[1]), 1, file);
		fclose(file);
	}
}
/* In total:
 * If user has write rights for both files
 * file_0 is created once
 * file_0 is created once and modified 5 times
 * 5  denied accesses
 *
 * If user does not have any write rights
 * No file is created or modified
 * 8 denied accesses
 */