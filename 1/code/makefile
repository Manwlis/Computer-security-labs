all: library demo

library: simple_crypto.c simple_crypto.h
	gcc -c simple_crypto.c -O2 -Wall -Wextra -pedantic

demo: demo.c library
	gcc -o demo demo.c simple_crypto.o -O2 -Wall -Wextra -pedantic

clean:
	rm -f simple_crypto.o demo 