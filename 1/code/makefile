all: library demo

library:  
	gcc -Wall -Wextra -o simple_crypto.o simple_crypto.c -O
demo: library
	gcc -Wall -Wextra -o demo demo.c simple_crypto.o

clean:
	rm -f simple_crypto.o demo 