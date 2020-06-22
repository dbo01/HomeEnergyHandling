#define WIFICONFIG_STRUCTS_VERSION 1
#include <applibs/wificonfig.h>

#define NO_ERROR_INFO 0

extern WifiConfig_ConnectedNetwork WiFiInfo;

extern char SonoffSrvState[30];
extern int SrvConnected;

int openSocket(void);
int ServerConnect(int socketFd, const char* IP);
int CheckConnStatus(int ConnFd);
int SonoffSendMessage(int srvFd, char* msg, size_t msgSize);
int SonoffRecEchoMsg(int srvFd, char * resp);
int SonoffActionMessage(int srvFd, char* msg, size_t msgSize);

void Log_Error(char* buff, int res);
int GetWifiInfo(void);