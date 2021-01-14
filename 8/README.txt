Emmanouil Petrakos 2014030009

How the exploit was developed:

1. Finding the buffer, the executable memory and the returned address (eip) location was achieved through gdb.

For the first two, the memory of the program was examined with the 'x' command.
Ex:
x/128xb buf		shows the position of the buffer and the value of the 128 next bytes in hex format.
x/32i Name		shows the position of the executable memory and the next 32 assembly commands.

The eip location was found with the 'info frame' command in the 'saved registers/eip' field.

In the given precompiled program the following addresses were found:
buf at 0xffffd1dc
Name at 0x80dacc0
eip at 0xffffd20c

Sources:
https://sourceware.org/gdb/current/onlinedocs/gdb/Memory.html
https://stackoverflow.com/questions/32345320/get-return-address-gdb
https://en.wikipedia.org/wiki/Stack_buffer_overflow


2. The following shellcode was used as the payload.
http://shell-storm.org/shellcode/files/shellcode-811.php

compile & run:
gcc -m32 -fno-stack-protector -z execstack -g -o shell  shellcode.c
./shell


3. inputGenerator.py creates the input file that uses the exploit.
Eip starts 50 bytes after the start of the buffer. Payload is 28 bytes, padding of 22 bytes is needed.

run:
python3 inputGenerator.py


4. The given precompiled program was used for testing. An sh shell spawns.

run:
(cat input; cat) | ./Greeter
(need to press Enter once)
ls, whoami etc