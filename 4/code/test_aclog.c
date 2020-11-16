#include <stdio.h>
#include <string.h>


int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[6][8] = { "file_0" , "file_1" , "file_2" , "file_3" , "file_4" , "file_5" };
	char modes[6][3] = { "r" , "w" , "a" , "r+" , "w+" , "a+"  };

	// All of this should work if user has the appropriate rights
	for (i = 0; i < 6; i++)
	{
		file = fopen(filenames[i], "w+"); // file creation
		if (file == NULL) 
			printf("fopen error\n");
		else
		{
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file); // file modification
			fclose(file);
		}
	}

	file = fopen(filenames[0], "r"); // file open
	if (file == NULL) 
		printf("fopen error\n");
	else
	{	// all should fail
		bytes = fwrite(filenames[0], strlen(filenames[0]), 1, file); // file modification
		bytes = fwrite(filenames[0], strlen(filenames[0]), 1, file);
		bytes = fwrite(filenames[0], strlen(filenames[0]), 1, file);
		bytes = fwrite(filenames[0], strlen(filenames[0]), 1, file);
		bytes = fwrite(filenames[0], strlen(filenames[0]), 1, file);
		fclose(file);
	}

	file = fopen(filenames[1], "w+"); // file open
	if (file == NULL) 
		printf("fopen error\n");
	else
	{	// all should work if user has write rights
		bytes = fwrite(filenames[1], strlen(filenames[1]), 1, file); // file modification
		bytes = fwrite(filenames[1], strlen(filenames[1]), 1, file);
		bytes = fwrite(filenames[1], strlen(filenames[1]), 1, file);
		bytes = fwrite(filenames[1], strlen(filenames[1]), 1, file);
		bytes = fwrite(filenames[1], strlen(filenames[1]), 1, file);
		fclose(file);
	}
}