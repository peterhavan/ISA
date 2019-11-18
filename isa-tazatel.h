#define MAXRECORDS 10
#define ARECORDLEN 32
#define AAAARECORDLEN 50
void errorMsg(char *msg);
bool isValidIpv4Address(char *ipAddress);
bool isValidIpv6Address(char *ipAddress);
int resolveDns(char * entryAddress, ns_type ns_t,
              char[MAXRECORDS][ARECORDLEN],
              char[MAXRECORDS][AAAARECORDLEN]);

extern const char *_res_opcodes[];
