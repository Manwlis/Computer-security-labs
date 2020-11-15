#include <stdio.h>
#include <string.h>

#include <fcntl.h>

int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[6][8] = { "file_0" , "file_1" , "file_2" , "file_3" , "file_4" , "file_5" };
	char modes[6][3] = { "r" , "w" , "a" , "r+" , "w+" , "a+"  };

	// for (i = 0; i < 6; i++) {

	// 	file = fopen(filenames[i], modes[i]);
	// 	if (file == NULL) 
	// 		printf("fopen error\n");
	// 	else {
	// 		bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
	// 		bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
	// 		fclose(file);
	// 	}
	// }

	file = fopen(filenames[0], modes[1]);
	bytes = fwrite(filenames[0], strlen(filenames[0]), 1, file);
	bytes = fwrite(filenames[0], strlen(filenames[0]), 1, file);
}