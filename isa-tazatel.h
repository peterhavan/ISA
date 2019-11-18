#define MAXRECORDS 10
#define ARECORDLEN 100
#define AAAARECORDLEN 100

void errorMsg(char *msg);
bool isValidIpv4Address(char *ipAddress);
bool isValidIpv6Address(char *ipAddress);
int resolveDns(char * entryAddress, ns_type ns_t,
              char[MAXRECORDS][ARECORDLEN],
              char[MAXRECORDS][AAAARECORDLEN]);
void myWhois(char *entryAddress, char *destinationAddress);
void red();
void green();
void reset();
void yellow();
