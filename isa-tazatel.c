/***************************
 *  ISA projekt   *
 *  Peter Havan   *
 *   xhavan00     *
 *  isa-tazatel.c *
 *   2019/2020    *
***************************/

/******************************************************************
* Inspired by exmaples IPK/ISA course files from FIT VUT          *
* Reused some code from 2018/2019 ipk-scan project by Peter Havan *
*******************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include "isa-tazatel.h"

int main(int argc, char* argv[])
{
	int opt;
	bool wflag = false, qflag = false, dflag = false;
	while ((opt = getopt(argc, argv, "q:d:w:")) !=  -1)
	{
		switch (opt)
		{
			case 'q':
				printf("%s\n", optarg);
				qflag = true;
				break;
			case 'w':
				printf("%s\n", optarg);
				wflag = true;
				break;
			case 'd':
				printf("%s\n", optarg);
				dflag = true;
				break;
			default:
				errorMsg("wrong arguments");
		}
	}
	return 0;
}

void errorMsg(char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(1);
}
