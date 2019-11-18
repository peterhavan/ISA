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
#include <regex.h>
#include "isa-tazatel.h"

#define PORT 43 // whois port

int main(int argc, char* argv[])
{
	/* setting up variables */
	int opt;
	bool wflag = false, qflag = false, dflag = false, ipv4Flag = false, oflag = false;
	char destinationAddress[100], whoIsAddress[100];
	char entryAddress[100], dnsServer[100];
	bzero(entryAddress, 100);
	bzero(destinationAddress, 100);
	bzero(whoIsAddress, 100);
	bzero(dnsServer, 100);
	/* parsing input */
	while ((opt = getopt(argc, argv, "q:d:w:o")) !=  -1)
	{
		switch (opt)
		{
			case 'q': // address to lookup
				strcpy(entryAddress, optarg);
				qflag = true;
				break;
			case 'w': // whois server to ask
				strcpy(whoIsAddress, optarg);
				wflag = true;
				break;
			case 'd': // dns resolver to ask
				dflag = true;
				strcpy(dnsServer, optarg);
				break;
			case 'o': // turn off changing IP to host if IP was given for -q
				oflag = true;
				break;
			default:
				errorMsg("wrong arguments");
		}
	}
	if (!(qflag & wflag))
		errorMsg("wrong arguments");

	/***************************************************************************
	 	 attempt to change IP address to hostname before parsing DNS result
		 might not be wanted behaviour, option -o will disable this
	 **************************************************************************/
	char hbuf[NI_MAXHOST + 2], sbuf[NI_MAXSERV];
	bzero(hbuf, NI_MAXHOST +2);
	bzero(sbuf, NI_MAXSERV);
	strcpy(hbuf, entryAddress);
	if (!oflag)
	{
		// need to determine whether the address is IPv4 or IPv6 before translation
		if (isValidIpv4Address(entryAddress))
		{	//IPv4
			struct sockaddr_in sa;
			sa.sin_family = AF_INET;
			inet_pton(AF_INET, entryAddress, &sa.sin_addr.s_addr);
			getnameinfo((struct sockaddr*)&sa, sizeof(sa), hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), 0);
		}
		else if(isValidIpv6Address(entryAddress))
		{ //IPv6
			struct sockaddr_in6 sa6;
			sa6.sin6_family = AF_INET6;
			inet_pton(AF_INET6, entryAddress, &sa6.sin6_addr.s6_addr);
			getnameinfo((struct sockaddr*)&sa6, sizeof(sa6), hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), 0);
		}
	}

	char aRecords[MAXRECORDS][ARECORDLEN];
	char aaaaRecords[MAXRECORDS][AAAARECORDLEN];
	bzero(aRecords, MAXRECORDS*ARECORDLEN);
	bzero(aaaaRecords, MAXRECORDS*AAAARECORDLEN);
	int aCount = 0;
	int aaaaCount = 0;
	res_init();
	if (dflag) // change variable of resolv.h if dns server was given as argument
		inet_pton(AF_INET, dnsServer, &(_res.nsaddr_list[0].sin_addr.s_addr));
	red();
	printf("================DNS================\n");
	// get each DNS record type individually
	// for PTR we always use given address even if option -o was not selected
	// if option -o was selected, hbuf is equal to entryAddress
	aCount = resolveDns(hbuf, ns_t_a, aRecords, aaaaRecords); // A record
	aaaaCount = resolveDns(hbuf, ns_t_aaaa, aRecords, aaaaRecords); // AAAA record
	resolveDns(hbuf, ns_t_mx, aRecords, aaaaRecords); // MX record
	resolveDns(hbuf, ns_t_cname, aRecords, aaaaRecords); // NS record
	resolveDns(hbuf, ns_t_ns, aRecords, aaaaRecords); // NS record
	resolveDns(hbuf, ns_t_soa, aRecords, aaaaRecords); // SOA record
	resolveDns(entryAddress, ns_t_ptr, aRecords, aaaaRecords); // PTR record

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
				//ipv6Flag = true;
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
	freeaddrinfo(res);
	green();
	printf("===============WHOIS===============\n");
	printf("for:\t%s\n", entryAddress);
	// when asking whois, the message has to end with ASCII <CR><LF>
	entryAddress[strlen(entryAddress)] = '\r';
	entryAddress[strlen(entryAddress)] = '\n';
	// first ask whois server about input address/hostname given in option -q
	myWhois(entryAddress, destinationAddress);
	// loop through list of A and AAAA records and ask whois for each of them
	for (int i = 0; i < aCount; i++)
	{
		// when asking whois, the message has to end with ASCII <CR><LF>
		aRecords[i][strlen(aRecords[i])] = '\r';
		aRecords[i][strlen(aRecords[i])] = '\n';
		green();
		printf("-----------------------------------\n");
		printf("\nfor record A:\t%s\n", aRecords[i]);
		myWhois(aRecords[i], destinationAddress);
	}

	for (int i = 0; i < aaaaCount; i++)
	{
		// when asking whois, the message has to end with ASCII <CR><LF>
		aaaaRecords[i][strlen(aaaaRecords[i])] = '\r';
		aaaaRecords[i][strlen(aaaaRecords[i])] = '\n';
		green();
		printf("-----------------------------------\n");
		printf("for record AAAA:\t%s\n", aaaaRecords[i]);
		myWhois(aaaaRecords[i], destinationAddress);
	}

	reset();
	return 0;
}

/**************************************************************************
  Function handles actual quering whois server
	@param entryAddress address to ask whois server about
	@param destinationAddress whois server to ask
 *************************************************************************/
void myWhois(char *entryAddress, char *destinationAddress)
{
	//setting up BSD socket
	int sock;
	struct sockaddr_in servaddr;
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1)
		errorMsg("socket(): FAILED");
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(destinationAddress);
	servaddr.sin_port = htons(PORT);
	if (connect(sock, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0)
		errorMsg("connect(): FAILED");
	char buffer[131072]; //might consider lowering the size
	bzero(buffer, 131072);
	char *line = NULL; //we'll check output line by line
	send(sock, entryAddress, strlen(entryAddress), 0);
	int n = 1;
	int offset = 0;
	// need to loop read() to make sure we get the entire answer
	while (n != 0)
	{
		n = read(sock, buffer + offset, 131072 - offset);
		offset += n;
	}
	// to parse answer we use simple regular expression
	regex_t re;
	int retval;
	line = strtok(buffer, "\n");
	// regular expression based on answer from whois.arin.net, whois.ripe.net, whois.nic.cz
	char *expression = "(^NetRange)|(^CIDR)|(^NetName)|(^OrgName)|(^Address)|(^City)|(^Country)|(^inetnum)|(^address)|(^admin-c)|(^country)|(^descr)|(^phone)";
	while( line != NULL ) // compare regex with each line
	{
		if (regcomp(&re, expression, REG_EXTENDED) != 0)
			errorMsg("ERROR: regcomp()");
		if ((retval = regexec(&re, line, 0, NULL, 0)) == 0)
				printf("%s\n", line);
		//printf("%s\n", line);
		regfree(&re);
		line = strtok(NULL, "\n");
	}
	//regfree(&re);
	close(sock);
}

/**************************************************************************
  Function handles asking and parsing DNS answer
	uses resolv.h
	inpisred by
	https://docstore.mik.ua/orelly/networking_2ndEd/dns/ch15_02.htm
	and
	https://gist.github.com/wil/6141275?fbclid=IwAR1gr5QeUmV4SOm-nqPhw25HekKxAnHFpa8sj1L4yQDDfAcDzL6iN18qIWI
	res_xx() functions set up external global parameters to use
	@param entryAddress address to ask DNS server about
	@param nsType what record to look for
	@param aRecords list of A DNS records
	@param aaaaRecords list of AAAA DNS records
	@return number of A/AAAA records found, 0 for other records, -1 for no records
 *************************************************************************/
int resolveDns(char *entryAddress, ns_type nsType,
	 						char aRecords[MAXRECORDS][ARECORDLEN],
							char aaaaRecords[MAXRECORDS][AAAARECORDLEN])
{

	u_char answer[1024] = "";
	bzero(answer, 1024);
	int aCount = 0;
	int aaaaCount = 0;
	int rv;
	// for PTR we need to reverse IP address first
	// works only for IPv4, IPv6 not implemented
	if ((nsType == ns_t_ptr) && (isValidIpv4Address(entryAddress)))
	{
		uint32_t addrInt;
		inet_pton(AF_INET, entryAddress, &addrInt); //convert to binary
		addrInt = htonl(addrInt); //swap byte order
		char tmp[100];
		bzero(tmp, 100);
		inet_ntop(AF_INET, &addrInt, tmp, sizeof(tmp)); //back from binary
		strcpy(&tmp[strlen(tmp)], ".in-addr.arpa"); // add suffix
		rv = res_query(tmp, ns_c_in, nsType, answer, sizeof(answer)); //query for newly created address
		if (rv <= 0) // no record found
			return -1;
	}
	else
	{
		rv = res_query(entryAddress, ns_c_in, nsType, answer, sizeof(answer)); //query for given address
		if (rv <= 0) // no record found
			return -1;
	}
	ns_msg handle;
	if (ns_initparse(answer, rv, &handle) < 0)
		errorMsg("ERROR:ns_initparse()");
	ns_rr rr;
	u_int16_t counter = ns_msg_count(handle, ns_s_an);
	char buf[1024];
	bzero(buf, 1024);
	for (int i = 0; i < counter; i++)
	{
		// parsing through all found records
		// records are in compressed form or in binary
		// resolv.h provides uncompressing fucntion
		// TXT record is programmed but never queried for
		ns_parserr(&handle, ns_s_an, i, &rr);
		switch (ns_rr_type(rr))
		{
			case ns_t_soa:
				printf("SOA:\t");
				ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle),
														ns_rr_rdata(rr), buf, sizeof(buf));
				printf("%s\n", buf);
				break;
			case ns_t_a:
				printf("A:\t");
				inet_ntop(AF_INET, ns_rr_rdata(rr), buf, sizeof(buf));
				printf("%s\n", buf);
				strncpy(aRecords[aCount], buf, ARECORDLEN);
				aCount++;
				break;
			case ns_t_aaaa:
				printf("AAAA:\t");
				inet_ntop(AF_INET6, ns_rr_rdata(rr), buf, sizeof(buf));
				printf("%s\n", buf);
				strncpy(aaaaRecords[aaaaCount], buf, AAAARECORDLEN);
				aaaaCount++;
				break;
			case ns_t_mx:
				printf("MX:\t");
				ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle),
										ns_rr_rdata(rr) + NS_INT16SZ, buf, sizeof(buf));
				printf("%s\n", buf);
				break;
			case ns_t_ns:
				printf("NS:\t");
				ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle),
														ns_rr_rdata(rr), buf, sizeof(buf));
				printf("%s\n", buf);
				break;
			case ns_t_ptr:
				printf("PTR:\t");
				ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle),
														ns_rr_rdata(rr), buf, sizeof(buf));
				printf("%s\n", buf);
				break;
			case ns_t_cname:
				printf("CNAME:\t");
				ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle),
														ns_rr_rdata(rr), buf, sizeof(buf));
				printf("%s\n", buf);
				break;
			case ns_t_txt:
				printf("TXT:\t");
				printf("%s\n", ns_rr_rdata(rr));
				break;
			default:
				break;
		}
	}
	//return number of A/AAAA records if we're looking for them
	if (nsType == ns_t_a)
		return aCount;
	if (nsType == ns_t_aaaa)
		return aaaaCount;
	return 0;
}

/*******************************************************************
	Inspired by https://stackoverflow.com/questions/791982/determine-if-a-string-is-a-valid-ipv4-address-in-c
	testing whether given address is IPv4/IPv6
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

/* adding some colors for nice output */
void red()
{
  printf("\033[1;31m");
}

/* green() will alternate between green and yellow for nicer output */
void green()
{
	static bool b = false;
	if (!b)
	{
  	printf("\033[1;32m");
		b = true;
	}
	else
	{
		b = false;
		yellow();
	}
}

void yellow()
{
  printf("\033[1;33m");
}

void reset()
{
  printf("\033[0m");
}

void errorMsg(char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(1);
}
