/***************************
 *  ISA projekt   *
 *  Peter Havan   *
 *   xhavan00     *
 *  isa-tazatel.c *
 *   2019/2020    *
***************************/

/***********************************************************************
* Inspired by exmaples IPK/ISA course files from FIT VUT               *
* Reused code from 2018/2019 ipk-scan project by Peter Havan (myself)  *
************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include "isa-tazatel.h"

#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif

int main(int argc, char* argv[])
{
	int opt;
	bool wflag = false, qflag = false, dflag = false, ipv6Flag = false, ipv4Flag = false;;
	char destinationAddress[100], entryAddress[100], whoIsAddress[100], errbuf[PCAP_ERRBUF_SIZE];
	char sourceIp4[32], sourceIp6[50];
	char *dev;
	while ((opt = getopt(argc, argv, "q:d:w:")) !=  -1)
	{
		switch (opt)
		{
			case 'q':
				printf("%s\n", optarg);
				strcpy(entryAddress, optarg);
				qflag = true;
				break;
			case 'w':
				printf("%s\n", optarg);
				strcpy(whoIsAddress, optarg);
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
	if (!(qflag & wflag))
		errorMsg("wrong arguments");

	/* getting server adress */
	/* inspired by https://gist.github.com/jirihnidek/bf7a2363e480491da72301b228b35d5d by jirihnidek */
	/******************************************************************
	* gethostbyname() cant deal with IPv6, we need to use getaddrinfo *
	******************************************************************/
	struct addrinfo hints, *res;
	int errcode;
	void *ptr;
	memset (&hints, 0, sizeof (hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags |= AI_CANONNAME;
	printf("%s\n", entryAddress);
	errcode = getaddrinfo (whoIsAddress, NULL, &hints, &res);
	if (errcode != 0)
		errorMsg("ERROR: gettaddrinfo()");
	while (res)
	{
		inet_ntop (res->ai_family, res->ai_addr->sa_data, destinationAddress, 100);
		switch (res->ai_family)
		{
			case AF_INET: //found IPv4 address
				ipv4Flag = true;
				ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
				break;
			case AF_INET6: //found IPv6 address
				ipv6Flag = true;
				ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
				break;
		}
		inet_ntop (res->ai_family, ptr, destinationAddress, 100);
		res = res->ai_next;
		if (ipv4Flag) // IPv4 is prefered in case argument was not IP address but hostname
		{
			break;
		}
	}

	if ((dev = pcap_lookupdev(errbuf)) == NULL)
		errorMsg("ERROR: pcap_lookupdev() failed");

	//getting address on the interface, inspired by
	//https://stackoverflow.com/questions/33125710/how-to-get-ipv6-interface-address-using-getifaddr-function
	struct ifaddrs *ifa, *ifa_tmp;
	char sourceAddress[50];
	if (getifaddrs(&ifa) == -1)
		errorMsg("ERROR: getifaddrs() failed");
	ifa_tmp = ifa;
	while (ifa_tmp)
	{
		if ((ifa_tmp->ifa_addr) && ((ifa_tmp->ifa_addr->sa_family == AF_INET) ||
																(ifa_tmp->ifa_addr->sa_family == AF_INET6)))
		{
			if (ifa_tmp->ifa_addr->sa_family == AF_INET)
			{
				// create IPv4 string
				if (!strcmp(ifa_tmp->ifa_name, dev))
				{
					struct sockaddr_in *in = (struct sockaddr_in*) ifa_tmp->ifa_addr;
					inet_ntop(AF_INET, &in->sin_addr, sourceAddress, sizeof(sourceAddress));
					strcpy(sourceIp4, sourceAddress);
				}
			}

			else
			{
				// create IPv6 string
				if (!strcmp(ifa_tmp->ifa_name, dev))
				{
					struct sockaddr_in6 *in6 = (struct sockaddr_in6*) ifa_tmp->ifa_addr;
					inet_ntop(AF_INET6, &in6->sin6_addr, sourceAddress, sizeof(sourceAddress));
					strcpy(sourceIp6, sourceAddress);
					break;
				}
			}
		}
		ifa_tmp = ifa_tmp->ifa_next;
	}

	if (ipv4Flag) // if IPv4 destinationAddress was found, we'll use that
		sendV4Packet(sourceIp4, destinationAddress, dev);
	else
		sendV6Packet(sourceIp6, destinationAddress, dev);
	return 0;
}

void sendV4Packet(char *sourceIp4, char *destinationAddress, char *dev)
{
	return;
}

void sendV6Packet(char *sourceIp6, char *destinationAddress, char *dev)
{
	return;
}

void errorMsg(char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(1);
}
