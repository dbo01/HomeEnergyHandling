#define WIFICONFIG_STRUCTS_VERSION 1
#include <applibs/wificonfig.h>

#define NO_ERROR_INFO 0

extern WifiConfig_ConnectedNetwork WiFiInfo;

extern char SonoffSrvState[10];
extern int SrvConnected;

int openSocket(void);
int ServerConnect(int socketFd);
int CheckConnStatus(int ConnFd);
int SonoffSendMessage(int srvFd, char* msg, size_t msgSize);
int SonoffRecEchoMsg(int srvFd, char * resp);

void Log_Error(char* buff, int res);
int GetWifiInfo(void);