all: isa-tazatel

isa-tazatel: isa-tazatel.c
	gcc -Wall -Wextra isa-tazatel.c -o isa-tazatel -g -lpcap -lresolv
