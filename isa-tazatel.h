void errorMsg(char *msg);
bool isValidIpv4Address(char *ipAddress);
bool isValidIpv6Address(char *ipAddress);
int resolveDns(char * entryAddress, ns_type ns_t);

extern const char *_res_opcodes[];
