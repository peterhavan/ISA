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

//whois -h whois.nic.cz vutbr.cz

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
#include <resolv.h>
#include "isa-tazatel.h"

#define SA struct sockaddr
#define PORT 43
#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif

int main(int argc, char* argv[])
{
	int opt;
	bool wflag = false, qflag = false, dflag = false, ipv6Flag = false, ipv4Flag = false;;
	char destinationAddress[100], whoIsAddress[100], errbuf[PCAP_ERRBUF_SIZE];
	char entryAddress[100];
	//char sourceIp4[32], sourceIp6[50];
	//char *dev;
	while ((opt = getopt(argc, argv, "q:d:w:")) !=  -1)
	{
		switch (opt)
		{
			case 'q':
				//entryAddress = (char *) malloc(sizeof(optarg)+2*sizeof(char));
				//printf("%ld", sizeof(optarg)+2*sizeof(char));
				strcpy(entryAddress, optarg);
				qflag = true;
				break;
			case 'w':
				strcpy(whoIsAddress, optarg);
				wflag = true;
				break;
			case 'd':
				dflag = true;
				break;
			default:
				errorMsg("wrong arguments");
		}
	}
	if (!(qflag & wflag))
		errorMsg("wrong arguments");

		u_char answer[1024] = "";
		res_init();
		int rv = res_query(entryAddress, ns_c_in, ns_t_txt, answer, sizeof(answer));
		printf("rv=%d\n", rv);

		//return 0;

		/*struct sockaddr_in sa1; // could be IPv4 if you want
        char host[1024];

        sa1.sin_family = AF_INET;
        sa1.sin_addr.s_addr = inet_addr("81.2.195.254");

        getnameinfo((struct sockaddr*)&sa1, sizeof sa1, host, sizeof host, NULL, 0, 0);
        printf("hostname: %s", host);*/
		//return 0;


	//printf("%d\n", isValidIpv4Address(entryAddress));

	//entryAddress[strlen(entryAddress)] = '\r';
	//entryAddress[strlen(entryAddress)] = '\n';

	char hbuf[1024], sbuf[NI_MAXSERV];
	if (isValidIpv4Address(entryAddress))
	{
		printf("IpV4\n");
		struct sockaddr_in sa;
		sa.sin_family = AF_INET;
		inet_pton(AF_INET, entryAddress, &sa.sin_addr.s_addr);
		//sa.sin_addr.s_addr = inet_addr("81.2.195.254");

		if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), 0));
  		printf("host=%s, serv=%s\n", hbuf, sbuf);
	}
	else if(isValidIpv6Address(entryAddress))
	{
		printf("IpV6\n");
		struct sockaddr_in6 sa6;
		sa6.sin6_family = AF_INET6;
		inet_pton(AF_INET6, entryAddress, &sa6.sin6_addr.s6_addr);
		if (getnameinfo((struct sockaddr*)&sa6, sizeof(sa6), hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV) == 0)
			printf("host=%s, serv=%s\n", hbuf, sbuf);
	}
	//strcpy(entryAddress, hbuf);

	else
	{
		entryAddress[strlen(entryAddress)] = '\r';
		entryAddress[strlen(entryAddress)] = '\n';
	}

	return 0;
	/* getting whois adress */
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
	printf("%s\n", destinationAddress);

	int sock;
  struct sockaddr_in servaddr, cli;
  // socket create and varification
  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == -1)
		errorMsg("socket(): FAILED");
  bzero(&servaddr, sizeof(servaddr));
  // assign IP, PORT
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = inet_addr(destinationAddress);
  servaddr.sin_port = htons(PORT);
  // connect the client socket to server socket
  if (connect(sock, (SA*)&servaddr, sizeof(servaddr)) != 0)
		errorMsg("connect(): FAILED");
	char buffer[65535];
	//char *addr = "vutbr.cz\r\n";
	//send(sock, addr, strlen(addr), 0);
	send(sock, entryAddress, strlen(entryAddress), 0);
	read(sock, buffer, 65535);
	printf("%s\n", buffer);
	//./isa-tazatel -q google.com -w whois.markmonitor.com
  // close the socket
  close(sock);
	//free(entryAddress);
	return 0;
}

/*******************************************************************
	Inspired by https://stackoverflow.com/questions/791982/determine-if-a-string-is-a-valid-ipv4-address-in-c
*******************************************************************/

bool isValidIpv4Address(char *ipAddress)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
    return result != 0;
}

bool isValidIpv6Address(char *ipAddress)
{
    struct sockaddr_in6 sa;
    int result = inet_pton(AF_INET6, ipAddress, &(sa.sin6_addr));
    return result != 0;
}

void errorMsg(char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(1);
}
