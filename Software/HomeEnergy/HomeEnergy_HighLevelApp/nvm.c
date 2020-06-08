#include "nvm.h"

#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <applibs/storage.h>
#include <applibs/log.h>

/// <summary>
/// Write an integer to this application's persistent data file
/// </summary>
int WriteToMutableFile(double value)
{
    int fd = Storage_OpenMutableFile();
    if (fd == -1) {
        Log_Debug("ERROR: Could not open mutable file:  %s (%d).\n", strerror(errno), errno);
        return -1;
    }
    size_t ret = write(fd, &value, sizeof(value));
    if (ret == -1) {
        // If the file has reached the maximum size specified in the application manifest,
        // then -1 will be returned with errno EDQUOT (122)
        Log_Debug("ERROR: An error occurred while writing to mutable file:  %s (%d).\n",
            strerror(errno), errno);
        return -2;
    }
    else if (ret < sizeof(value)) {
        // For simplicity, this sample logs an error here. In the general case, this should be
        // handled by retrying the write with the remaining data until all the data has been
        // written.
        Log_Debug("ERROR: Only wrote %d of %d bytes requested\n", ret, (int)sizeof(value));
        return -3;
    }
    close(fd);

    return 0;
}


/// <summary>
/// Read an integer from this application's persistent data file
/// </summary>
/// <returns>
/// The integer that was read from the file.  If the file is empty, this returns 0.  If the storage
/// API fails, this returns -1.
/// </returns>
double ReadMutableFile(void)
{
    int fd = Storage_OpenMutableFile();
    if (fd == -1) {
        Log_Debug("ERROR: Could not open mutable file:  %s (%d).\n", strerror(errno), errno);
        return -1;
    }
    double value = 0;
    size_t ret = read(fd, &value, sizeof(value));
    if (ret == -1) {
        Log_Debug("ERROR: An error occurred while reading file:  %s (%d).\n", strerror(errno),
            errno);
    }
    close(fd);

    if (ret < sizeof(value)) {
        return 0;
    }

    return value;
}