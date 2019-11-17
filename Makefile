all: isa-tazatel

isa-tazatel: isa-tazatel.c
	gcc isa-tazatel.c -o isa-tazatel -g -lpcap -lresolv
