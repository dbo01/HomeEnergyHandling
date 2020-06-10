#define _GNU_SOURCE // required for asprintf
#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stddef.h>

#include "netinet/in.h"

#include "epoll_timerfd_utilities.h"


#include "Sonoff.h"
#include <sys/socket.h>
#include <applibs/log.h>

#include <arpa/inet.h>

WifiConfig_ConnectedNetwork WiFiInfo = {0};
char SonoffSrvState[10] = "INIT";
int SrvConnected = 0;
int8_t connected = -1;

static int ret = -1;

void Log_Error(char *buff, int res)
{
    Log_Debug("[ERROR]: %s , ret val =  %d, error =  %s \n", buff, res, strerror(errno));
}

int GetWifiInfo(void)
{

    return WifiConfig_GetCurrentNetwork(&WiFiInfo);

}

int openSocket(void)
{
    int localFd = -1;
    int retFd = -1;

    int sockType = SOCK_STREAM | SOCK_NONBLOCK;
    do {
        // Create a TCP / IPv4 socket. This will form the listen socket.
        localFd = socket(AF_INET, sockType, /* protocol */ 0);
        if (localFd == -1) {
            Log_Error("socket", localFd);
            break;
        }

        // Enable rebinding soon after a socket has been closed.
        int enableReuseAddr = 1;
        int r = setsockopt(localFd, SOL_SOCKET, SO_REUSEADDR, &enableReuseAddr,
            sizeof(enableReuseAddr));
        if (r != 0) {
            Log_Error("setsockopt/SO_REUSEADDR",r);
            break;
        }

        //select()   

        // Port opened successfully.
        retFd = localFd;
        localFd = -1;
    } while (0);

    //close(localFd);

    return retFd;
}

int ServerConnect(int socketFd)
{
    struct in_addr SonoffIP = { 0 };

    inet_aton("192.168.1.122", &SonoffIP);
    // Bind to a well-known IP address.
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = SonoffIP.s_addr;
    addr.sin_port = htons((uint16_t)9999);

    if (socketFd < 0)
    {
        Log_Error("Broken socket - Connection Failed",-1);
        SrvConnected = 0;
        return -1;
    }
    else
    {
        Log_Debug("Connecting to socket \n");

        int r = connect(socketFd, (const struct sockaddr*) & addr, sizeof(addr));
        if (!r)
        {
            strcpy(SonoffSrvState, "Connected");
            Log_Debug("Connected to Socket Sucesfully!! \n");
            SrvConnected = 1;
            connected = 0;
        }
        else
        {
            strcpy(SonoffSrvState, strerror(errno));
            Log_Error(" Error while connecting %d", r);
            //SrvConnected = 0;
            connected = -1;
            
        }
        return r;
    }
}

int CheckConnStatus(int ConnFd)
{
    socklen_t len = 0;
    int SrvError = 0;
    len = sizeof(SrvError);

    getsockopt(ConnFd, SOL_SOCKET, SO_ERROR, (void *)SrvError, &len); 

    Log_Debug("Connection Status: %s, SrvError Value %d  !! \n", strerror(SrvError), SrvError);
    strcpy(SonoffSrvState, strerror(SrvError));
    Log_Debug(" ///////////// Connected Value %d", connected);
    //return SrvError == 0 ? connected : SrvError;
    return connected;
}

int SonoffSendMessage(int srvFd, char* msg, size_t msgSize)
{

    if (NULL == msg)
    {
        return -1;
    }
    //char txBuff[] = "on";
    //
    ret = send(srvFd, msg, sizeof(msg), MSG_EOR | MSG_NOSIGNAL);
    if (ret < 0)
    {
        Log_Error("Msg not sent", ret); 
        SrvConnected = 0;
        
    }
    else if (ret == sizeof(msg))
    {
        Log_Debug("Msg sent: %s, %d bytes succesfully !! \n", msg, ret);
        SrvConnected = 1;
    }
    return ret;
}

int SonoffRecEchoMsg(int srvFd, char * resp)
{
    char rxBuff[20];
    while (ret != recv(srvFd, rxBuff, sizeof(rxBuff), MSG_WAITALL))
    {
        if ( (errno != EAGAIN) | (errno != EAGAIN) )
        {
            Log_Error("Failed to receive msg: %s !! \n", errno);
            SrvConnected = 0;
            break;
        }
    }
    if (NULL != resp)
    {
        strncpy(resp, rxBuff, ret);
    }
    Log_Debug("Received msg: %s !! \n", rxBuff);

    return ret;
}
