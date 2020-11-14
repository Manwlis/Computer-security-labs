#include <stdio.h>
#include <string.h>

int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[6][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_6"};

	char modes[6][3] = { "r" , "w" , "a" , "r+" , "w+" , "a+" };

	for (i = 0; i < 6; i++) {

		file = fopen(filenames[i], "r");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			//bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


}
