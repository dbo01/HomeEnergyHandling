/* Copyright (c) Microsoft Corporation. All rights reserved.
   Licensed under the MIT License. */


#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>

#include <stdlib.h>
#include <time.h>
#include <stdarg.h>

#include <sys/time.h>
#include <sys/socket.h>


#include "applibs_versions.h"
#include <applibs/log.h>
#include <applibs/networking.h>
#include <applibs/gpio.h>
#include <applibs/application.h>

#include "epoll_timerfd_utilities.h"
#include "Security.h"
#include "ACS712.h"
#include "oled.h"
#include "Sonoff.h"
#include "nvm.h"

// MT3620 RDB: Button A
#define SAMPLE_BUTTON_1 12

// MT3620 RDB: Button B
#define SAMPLE_BUTTON_2 13

// MT3620 RDB: LED 1 (red channel)
#define SAMPLE_LED 8


// Azure IoT SDK
#include <iothub_client_core_common.h>
#include <iothub_device_client_ll.h>
#include <iothub_client_options.h>
#include <iothubtransportmqtt.h>
#include <iothub.h>
#include <azure_sphere_provisioning.h>

//static volatile sig_atomic_t terminationRequired = false;
#include "parson.h" // used to parse Device Twin messages.

#define SCOPEID_LENGTH 20
#define RT_CORE_POOLING_TIMER 4
#define PUMP_DELAY_COUNT 2
#define HEATER_RESISTANCE 36 // 36 Ohm for 1500W single heating element

// sending azure period configuration
#define AZURE_TELEMETRY_PERIOD 10 // seconds

static char scopeId[SCOPEID_LENGTH]; // ScopeId for the Azure IoT Central application, set in
									 // app_manifest.json, CmdArgs

static const char connectionString[] = MY_CONNECTION_STRING;

static IOTHUB_DEVICE_CLIENT_LL_HANDLE iothubClientHandle = NULL;
static const int keepalivePeriodSeconds = 20;
static bool iothubAuthenticated = false;
static void SendMessageCallback(IOTHUB_CLIENT_CONFIRMATION_RESULT result, void* context);
static void TwinCallback(DEVICE_TWIN_UPDATE_STATE updateState, const unsigned char* payload,
	size_t payloadSize, void* userContextCallback);
static void TwinReportBoolState(const char* propertyName, bool propertyValue);
static void ReportStatusCallback(int result, void* context);
static const char* GetReasonString(IOTHUB_CLIENT_CONNECTION_STATUS_REASON reason);
static const char* getAzureSphereProvisioningResultString(
	AZURE_SPHERE_PROV_RETURN_VALUE provisioningResult);
static void SendTelemetry(const unsigned char* key, const unsigned char* value);
static void SetupAzureClient(void);

uint8_t ConnectedPi = 0;

//sensors data
float current_sensor = 0;

/* File descriptors - initialized to invalid value */

// File descriptor for Raspberry Pi server controlling Sonoff Devices
int PiSrvFd = -1;

// Buttons
static int ButtonAGpioFd = -1;
static int sendOrientationButtonGpioFd = -1;

// LED
static int deviceTwinStatusLedGpioFd = -1;
static bool statusLedOn = false;

// Timer / polling
static int buttonPollTimerFd = -1;
static int azureTimerFd = -1;
static int sensorTimerFd = -1;

// Azure IoT poll periods
static const int AzureIoTDefaultPollPeriodSeconds = 5;
static const int AzureIoTMinReconnectPeriodSeconds = 60;
static const int AzureIoTMaxReconnectPeriodSeconds = 10 * 60;

static int azureIoTPollPeriodSeconds = -1;

// Button state variables
static GPIO_Value_Type sendMessageButtonState = GPIO_Value_High;
static GPIO_Value_Type sendOrientationButtonState = GPIO_Value_High;
// Button state variables
static GPIO_Value_Type buttonState = GPIO_Value_High;
static GPIO_Value_Type ledState = GPIO_Value_High;

static GPIO_Value_Type NewledState = GPIO_Value_High;

static void ButtonPollTimerEventHandler(EventData* eventData);
static bool deviceIsUp = false; // Orientation
static void AzureTimerEventHandler(EventData* eventData);

// Azure IoT SDK
static int epollFd = -1;
static int timerFd = -1;
static int sockFd = -1;
static volatile sig_atomic_t terminationRequired = false;

// helping vars TODO: refactor later
uint8_t PumpIsOff = 1;
static uint8_t OnDelayCounter = 0;
static uint8_t OffDelayCounter = 0;

static const char rtAppComponentId[] = "005180bc-402f-4cb3-a662-72937dbcde47";

static void TerminationHandler(int signalNumber);
static void TimerEventHandler(EventData *eventData);
static void SendMessageToRTCore(void);
static void SocketEventHandler(EventData *eventData);
static int InitHandlers(void);
static void CloseHandlers(void);
static void AzureSensorEventHandler(EventData* eventData);
static int HandlePumpControl(void);

// RT App data
union ADC_DataType
{
	uint32_t u32;
	uint8_t u8[4];
} ADC_Data;

//Sensors Data

uint8_t TempSensor1 = 0;
uint8_t TempSensor2 = 0; 


static void Send_ADC_data(void);
static void Send_Energy_data(void);
/// <summary>
///     Signal handler for termination requests. This handler must be async-signal-safe.
/// </summary>
static void TerminationHandler(int signalNumber)
{
    // Don't use Log_Debug here, as it is not guaranteed to be async-signal-safe.
    terminationRequired = true;
}

/// <summary>
///     Handle send timer event by writing data to the real-time capable application.
/// </summary>
static void TimerEventHandler(EventData *eventData)
{
    if (ConsumeTimerFdEvent(timerFd) != 0) {
        terminationRequired = true;
        return;
    }

    SendMessageToRTCore();
}

/// <summary>
///     Helper function for TimerEventHandler sends message to real-time capable application.
/// </summary>
static void SendMessageToRTCore(void)
{
    static int iter = 0;

	// Send "HELLO-WORLD-%d" message to real-time capable application.
    static char txMessage[32];
    sprintf(txMessage, "Hello-World-%d", iter++);
    Log_Debug("Sending: %s\n", txMessage);

    int bytesSent = send(sockFd, txMessage, strlen(txMessage), 0);
    if (bytesSent == -1) {
        Log_Debug("ERROR: Unable to send message: %d (%s)\n", errno, strerror(errno));
        terminationRequired = true;
        return;
    }
}



/// <summary>
///     Handle socket event by reading incoming data from real-time capable application.
/// </summary>
static void SocketEventHandler(EventData *eventData)
{
    // Read response from real-time capable application.
    char rxBuf[32];
    int bytesReceived = recv(sockFd, rxBuf, sizeof(rxBuf), 0);

    if (bytesReceived == -1) {
        Log_Debug("ERROR: Unable to receive message: %d (%s)\n", errno, strerror(errno));
        terminationRequired = true;
    }

    Log_Debug("Received %d bytes: ", bytesReceived);
	uint8_t RTCore_status = 0;

    for (int i = 0; i < bytesReceived; ++i) {

		ADC_Data.u8[i] = rxBuf[i];	
    }

	Log_Debug("Analog value := %d  \n", ADC_Data.u32);
	current_sensor = toAmpsACS712(ADC_Data.u32);

	if (current_sensor > maxCurr)
	{
		maxCurr = current_sensor;
	}
	else (current_sensor < MinCurr);
	{
		MinCurr = current_sensor;
	}

	// Energy = Power * time -> Power = I^2 * R 
	double deltaEnergy = current_sensor * current_sensor * HEATER_RESISTANCE * RT_CORE_POOLING_TIMER/3600; // Wh

	TotalEnergy += deltaEnergy / 1000; // kWh
}

// event handler data structures. Only the event handler field needs to be populated.
static EventData timerEventData		= {.eventHandler = &TimerEventHandler};
static EventData socketEventData	= {.eventHandler = &SocketEventHandler};
static EventData buttonPollEventData = { .eventHandler = &ButtonPollTimerEventHandler };
static EventData azureEventData		= { .eventHandler = &AzureTimerEventHandler };
static EventData azureSensorData	= { .eventHandler = &AzureSensorEventHandler };

/// <summary>
///     Set up SIGTERM termination handler and event handlers for send timer
///     and to receive data from real-time capable application.
/// </summary>
/// <returns>0 on success, or -1 on failure</returns>
static int InitHandlers(void)
{
    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = TerminationHandler;
    sigaction(SIGTERM, &action, NULL);

    epollFd = CreateEpollFd();
    if (epollFd < 0) {
        return -1;
    }

    // Register timer to send a message to the real-time core.
    static const struct timespec sendPeriod = {.tv_sec = RT_CORE_POOLING_TIMER, .tv_nsec = 0};
    timerFd = CreateTimerFdAndAddToEpoll(epollFd, &sendPeriod, &timerEventData, EPOLLIN);
    if (timerFd < 0) {
        return -1;
    }
    RegisterEventHandlerToEpoll(epollFd, timerFd, &timerEventData, EPOLLIN);

    // Open connection to real-time capable application.
    sockFd = Application_Socket(rtAppComponentId);
    if (sockFd == -1) {
        Log_Debug("ERROR: Unable to create socket: %d (%s)\n", errno, strerror(errno));
        return -1;
    }

    // Set timeout, to handle case where real-time capable application does not respond.
    static const struct timeval recvTimeout = {.tv_sec = 5, .tv_usec = 0};
    int result = setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &recvTimeout, sizeof(recvTimeout));
    if (result == -1) {
        Log_Debug("ERROR: Unable to set socket timeout: %d (%s)\n", errno, strerror(errno));
        return -1;
    }

    // Register handler for incoming messages from real-time capable application.
    if (RegisterEventHandlerToEpoll(epollFd, sockFd, &socketEventData, EPOLLIN) != 0) {
        return -1;
    }

	//Register handler for incooming Telemetry
	struct timespec azureTelemetryPeriod = { AzureIoTDefaultPollPeriodSeconds, 0 };
	azureTimerFd =
		CreateTimerFdAndAddToEpoll(epollFd, &azureTelemetryPeriod, &azureEventData, EPOLLIN);
	if (azureTimerFd < 0) {
		return -1;
	}

	struct timespec sensorTelemetryPeriod = { AZURE_TELEMETRY_PERIOD, 0 };
	sensorTimerFd =
		CreateTimerFdAndAddToEpoll(epollFd, &sensorTelemetryPeriod, &azureSensorData, EPOLLIN);
	if (sensorTimerFd < 0) {
		return -1;
	}

	// buttons pooling
	struct timespec buttonPressCheckPeriod = { 0, 1000 * 1000 };
	buttonPollTimerFd =
		CreateTimerFdAndAddToEpoll(epollFd, &buttonPressCheckPeriod, &buttonPollEventData, EPOLLIN);
	if (buttonPollTimerFd < 0) {
		return -1;
	}

	/*** GPIO FDs ***/

	// Open button A GPIO as input
	Log_Debug("Opening SAMPLE_BUTTON_1 as input\n");
	ButtonAGpioFd = GPIO_OpenAsInput(SAMPLE_BUTTON_1);
	if (ButtonAGpioFd < 0) {
		Log_Debug("ERROR: Could not open button A: %s (%d).\n", strerror(errno), errno);
		return -1;
	}

	 //LED 4 Blue is used to show Device Twin settings state
	Log_Debug("Opening SAMPLE_LED as output\n");
	deviceTwinStatusLedGpioFd =
		GPIO_OpenAsOutput(SAMPLE_LED, GPIO_OutputMode_PushPull, GPIO_Value_High);
	if (deviceTwinStatusLedGpioFd < 0) {
		Log_Debug("ERROR: Could not open LED: %s (%d).\n", strerror(errno), errno);
		return -1;
	}

	TotalEnergy =  ReadMutableFile();

    return 0;
}

/// <summary>
///     Clean up the resources previously allocated.
/// </summary>
static void CloseHandlers(void)
{
    Log_Debug("Closing file descriptors.\n");
    CloseFdAndPrintError(sockFd, "Socket");
    CloseFdAndPrintError(timerFd, "Timer");
    CloseFdAndPrintError(epollFd, "Epoll");

	CloseFdAndPrintError(azureTimerFd, "AzureTimer");
	CloseFdAndPrintError(sensorTimerFd, "SensorTimer");
}

int main(int argc, char* argv[])
{
    Log_Debug("High-level intercore application.\n");
    Log_Debug("Sends data to, and receives data from the real-time core.\n");

	if (argc == 2) {
		Log_Debug("Setting Azure Scope ID %s\n", argv[1]);
		strncpy(scopeId, argv[1], SCOPEID_LENGTH);
	}
	else {
		Log_Debug("ScopeId needs to be set in the app_manifest CmdArgs\n");
		return -1;
	}


	//if (InitPeripheralsAndHandlers() != 0) {
	//	terminationRequired = true;
	//}

    if (InitHandlers() != 0) {
        terminationRequired = true;
    }

	if (0 == initI2c())
	{
		Log_Debug("[INFO]: OLED DETECTED, Init done \n");
		update_oled();
	}
	else
	{
		Log_Debug("[ERROR]: OLED MISSING, Init done \n");
	}// dupa call

	if (GetWifiInfo() != 0)
	{
		Log_Debug("[ERROR]: WiFi INFO Failed \n");
	}

	update_oled();

	PiSrvFd = openSocket();
	ServerConnect(PiSrvFd);

    while (!terminationRequired) {

		int sentBytes = 0;
        if (WaitForEventAndCallHandler(epollFd) != 0) {
            terminationRequired = true;
        }

		/* Debuging purpose led*/
		if (NewledState != ledState)
		{
			
			if (GPIO_Value_Low == ledState) 
			{
				sentBytes = SonoffSendMessage(PiSrvFd, "on", sizeof("on"));
				oled_state = 1;
			}
			else
			{
				sentBytes = SonoffSendMessage(PiSrvFd, "off", sizeof("off"));
			}
			NewledState = ledState;
			if (sentBytes > 0)
			{
				SonoffRecEchoMsg(PiSrvFd, NULL);
			}
		}
    }
    CloseHandlers();
    Log_Debug("Application exiting.\n");
    return 0;
}

//Azure IoT Buttons
static void ButtonPollTimerEventHandler(EventData* eventData)
{
	if (ConsumeTimerFdEvent(buttonPollTimerFd) != 0) {
		terminationRequired = true;
		return;
	}
	// Check for a button press
	GPIO_Value_Type newButtonState;

	int result = GPIO_GetValue(ButtonAGpioFd, &newButtonState);
	if (result != 0) {
		Log_Debug("ERROR: Could not read button GPIO: %s (%d).\n", strerror(errno), errno);
		terminationRequired = true;
		return;
	}

	// If the button has just been pressed, change the LED blink interval
	// The button has GPIO_Value_Low when pressed and GPIO_Value_High when released
	if (newButtonState != buttonState) {


		if (GPIO_Value_Low == buttonState)
		{
			ledState = !ledState;
			GPIO_SetValue(deviceTwinStatusLedGpioFd, ledState);
		}
		
		buttonState = newButtonState;
	}
}

/// <summary>
/// Azure timer event:  Check connection status and send telemetry
/// </summary>
static void AzureTimerEventHandler(EventData* eventData)
{
	update_oled();

	if (ConsumeTimerFdEvent(azureTimerFd) != 0) {
		terminationRequired = true;
		return;
	}

	bool isNetworkReady = false;
	if (Networking_IsNetworkingReady(&isNetworkReady) != -1) {
		if (isNetworkReady && !iothubAuthenticated) {
			SetupAzureClient();
		}
	}
	else {
		Log_Debug("Failed to get Network state\n");
	}

	if (iothubAuthenticated) { // put data to be sent when checking connection to client

		Send_ADC_data();
		IoTHubDeviceClient_LL_DoWork(iothubClientHandle);
		
	}
}

static void AzureSensorEventHandler(EventData* eventData)
{
	Log_Debug("Handling cyclic networking events\n");

	if (ConsumeTimerFdEvent(sensorTimerFd) != 0) {
		terminationRequired = true;
		Log_Error("Consume Error", -1);
		return;
	}

	if (!SrvConnected)
	{
		if (0 == ServerConnect(PiSrvFd))
		{
			oled_state = 1;
		}
	}


	bool isNetworkReady = false;
	if (Networking_IsNetworkingReady(&isNetworkReady) != -1) {
		if (isNetworkReady && !iothubAuthenticated) {
			SetupAzureClient();
		}
	}
	else {
		Log_Debug("Failed to get Network state\n");
	}

	if (SrvConnected)
	{
		int sentBytes = SonoffSendMessage(PiSrvFd, "T1", sizeof("T1"));
		char temperatureVal[5] = { NULL };

		if (sentBytes > 0)
		{
			SonoffRecEchoMsg(PiSrvFd, temperatureVal);
			TempSensor1 = strtol((temperatureVal), NULL, 10);
			Log_Debug("Temperature T1 has value %d\n", TempSensor1);
		}

		sentBytes = SonoffSendMessage(PiSrvFd, "T2", sizeof("T2"));

		if (sentBytes > 0)
		{
			SonoffRecEchoMsg(PiSrvFd, temperatureVal);
			TempSensor2 = strtol((temperatureVal), NULL, 10);
			Log_Debug("Temperature T2 has value %d\n", TempSensor2);
		}
	}

	HandlePumpControl();

	int res = WriteToMutableFile(TotalEnergy);
	if (0 != res)
	{
		Log_Error("Writing to non volatile memory failed", res );
	}
	Send_Energy_data();

	if (iothubAuthenticated) { // put data to be sent on timed interval

		
	}
}

/// <summary>
///		Turn On or Off heat exhanging pump when needed
/// </summary>
static int HandlePumpControl()
{
	if (TempSensor1 > TempSensor2 && PumpIsOff)
	{
		OnDelayCounter++;
		OffDelayCounter = 0;
		if (OnDelayCounter >= PUMP_DELAY_COUNT)
		{
			NewledState = !ledState;
			OnDelayCounter = 0;
			PumpIsOff = 0;
		}
	}
	else if (TempSensor1 < TempSensor2 && !PumpIsOff)
	{
		OnDelayCounter = 0;
		OffDelayCounter++;

		if (OffDelayCounter >= PUMP_DELAY_COUNT)
		{
			NewledState = !ledState;
			OffDelayCounter = 0;
			PumpIsOff = 1;
		}
	}
}

/// <summary>
///     Sets the IoT Hub authentication state for the app
///     The SAS Token expires which will set the authentication state
/// </summary>
static void HubConnectionStatusCallback(IOTHUB_CLIENT_CONNECTION_STATUS result,
	IOTHUB_CLIENT_CONNECTION_STATUS_REASON reason,
	void* userContextCallback)
{
	iothubAuthenticated = (result == IOTHUB_CLIENT_CONNECTION_AUTHENTICATED);
	Log_Debug("IoT Hub Authenticated: %s\n", GetReasonString(reason));
}

/// <summary>
///     Sets up the Azure IoT Hub connection (creates the iothubClientHandle)
///     When the SAS Token for a device expires the connection needs to be recreated
///     which is why this is not simply a one time call.
/// </summary>
static void SetupAzureClient(void)
{
	if (iothubClientHandle != NULL)
		IoTHubDeviceClient_LL_Destroy(iothubClientHandle);

	iothubClientHandle = IoTHubDeviceClient_LL_CreateFromConnectionString(connectionString, MQTT_Protocol);

	if (iothubClientHandle == NULL) {
		return false;
	}

	// Successfully connected, so make sure the polling frequency is back to the default
	azureIoTPollPeriodSeconds = AzureIoTDefaultPollPeriodSeconds;
	struct timespec azureTelemetryPeriod = { azureIoTPollPeriodSeconds, 0 };
	SetTimerFdToPeriod(azureTimerFd, &azureTelemetryPeriod);

	iothubAuthenticated = true;

	if (IoTHubDeviceClient_LL_SetOption(iothubClientHandle, OPTION_KEEP_ALIVE,
		&keepalivePeriodSeconds) != IOTHUB_CLIENT_OK) {
		Log_Debug("ERROR: failure setting option \"%s\"\n", OPTION_KEEP_ALIVE);
		return;
	}


	if (IoTHubDeviceClient_LL_SetOption(iothubClientHandle, "TrustedCerts",
		azureIoTCertificatesX) != IOTHUB_CLIENT_OK) {
		Log_Debug("ERROR: failure to set option \"TrustedCerts\"\n");
		return false;
	}


	IoTHubDeviceClient_LL_SetDeviceTwinCallback(iothubClientHandle, TwinCallback, NULL);
	IoTHubDeviceClient_LL_SetConnectionStatusCallback(iothubClientHandle,
		HubConnectionStatusCallback, NULL);
}

/// <summary>
///     Callback invoked when a Device Twin update is received from IoT Hub.
///     Updates local state for 'showEvents' (bool).
/// </summary>
/// <param name="payload">contains the Device Twin JSON document (desired and reported)</param>
/// <param name="payloadSize">size of the Device Twin JSON document</param>
static void TwinCallback(DEVICE_TWIN_UPDATE_STATE updateState, const unsigned char* payload,
	size_t payloadSize, void* userContextCallback)
{
	size_t nullTerminatedJsonSize = payloadSize + 1;
	char* nullTerminatedJsonString = (char*)malloc(nullTerminatedJsonSize);
	if (nullTerminatedJsonString == NULL) {
		Log_Debug("ERROR: Could not allocate buffer for twin update payload.\n");
		abort();
	}

	// Copy the provided buffer to a null terminated buffer.
	memcpy(nullTerminatedJsonString, payload, payloadSize);
	// Add the null terminator at the end.
	nullTerminatedJsonString[nullTerminatedJsonSize - 1] = 0;

	JSON_Value* rootProperties = NULL;
	rootProperties = json_parse_string(nullTerminatedJsonString);
	if (rootProperties == NULL) {
		Log_Debug("WARNING: Cannot parse the string as JSON content.\n");
		goto cleanup;
	}

	JSON_Object* rootObject = json_value_get_object(rootProperties);
	JSON_Object* desiredProperties = json_object_dotget_object(rootObject, "desired");
	if (desiredProperties == NULL) {
		desiredProperties = rootObject;
	}

	// Handle the Device Twin Desired Properties here.
	JSON_Object* OledState = json_object_dotget_object(desiredProperties, "OledState");
	if (OledState != NULL)
	{
		oled_state = (uint8_t)json_object_get_number(OledState, "value");
		TwinReportBoolState("OledState", oled_state);
	}


cleanup:
	// Release the allocated memory.
	json_value_free(rootProperties);
	free(nullTerminatedJsonString);
}

/// <summary>
///     Converts the IoT Hub connection status reason to a string.
/// </summary>
static const char* GetReasonString(IOTHUB_CLIENT_CONNECTION_STATUS_REASON reason)
{
	static char* reasonString = "unknown reason";
	switch (reason) {
	case IOTHUB_CLIENT_CONNECTION_EXPIRED_SAS_TOKEN:
		reasonString = "IOTHUB_CLIENT_CONNECTION_EXPIRED_SAS_TOKEN";
		break;
	case IOTHUB_CLIENT_CONNECTION_DEVICE_DISABLED:
		reasonString = "IOTHUB_CLIENT_CONNECTION_DEVICE_DISABLED";
		break;
	case IOTHUB_CLIENT_CONNECTION_BAD_CREDENTIAL:
		reasonString = "IOTHUB_CLIENT_CONNECTION_BAD_CREDENTIAL";
		break;
	case IOTHUB_CLIENT_CONNECTION_RETRY_EXPIRED:
		reasonString = "IOTHUB_CLIENT_CONNECTION_RETRY_EXPIRED";
		break;
	case IOTHUB_CLIENT_CONNECTION_NO_NETWORK:
		reasonString = "IOTHUB_CLIENT_CONNECTION_NO_NETWORK";
		break;
	case IOTHUB_CLIENT_CONNECTION_COMMUNICATION_ERROR:
		reasonString = "IOTHUB_CLIENT_CONNECTION_COMMUNICATION_ERROR";
		break;
	case IOTHUB_CLIENT_CONNECTION_OK:
		reasonString = "IOTHUB_CLIENT_CONNECTION_OK";
		break;
	}
	return reasonString;
}

/// <summary>
///     Converts AZURE_SPHERE_PROV_RETURN_VALUE to a string.
/// </summary>
static const char* getAzureSphereProvisioningResultString(
	AZURE_SPHERE_PROV_RETURN_VALUE provisioningResult)
{
	switch (provisioningResult.result) {
	case AZURE_SPHERE_PROV_RESULT_OK:
		return "AZURE_SPHERE_PROV_RESULT_OK";
	case AZURE_SPHERE_PROV_RESULT_INVALID_PARAM:
		return "AZURE_SPHERE_PROV_RESULT_INVALID_PARAM";
	case AZURE_SPHERE_PROV_RESULT_NETWORK_NOT_READY:
		return "AZURE_SPHERE_PROV_RESULT_NETWORK_NOT_READY";
	case AZURE_SPHERE_PROV_RESULT_DEVICEAUTH_NOT_READY:
		return "AZURE_SPHERE_PROV_RESULT_DEVICEAUTH_NOT_READY";
	case AZURE_SPHERE_PROV_RESULT_PROV_DEVICE_ERROR:
		return "AZURE_SPHERE_PROV_RESULT_PROV_DEVICE_ERROR";
	case AZURE_SPHERE_PROV_RESULT_GENERIC_ERROR:
		return "AZURE_SPHERE_PROV_RESULT_GENERIC_ERROR";
	default:
		return "UNKNOWN_RETURN_VALUE";
	}
}

/// <summary>
///     Sends telemetry to IoT Hub
/// </summary>
/// <param name="key">The telemetry item to update</param>
/// <param name="value">new telemetry value</param>
static void SendTelemetry(const unsigned char* key, const unsigned char* value)
{
	static char eventBuffer[100] = { 0 };
	static const char* EventMsgTemplate = "{ \"%s\": \"%s\" }";
	int len = snprintf(eventBuffer, sizeof(eventBuffer), EventMsgTemplate, key, value);
	if (len < 0)
		return;

	Log_Debug("Sending IoT Hub Message: %s\n", eventBuffer);

	IOTHUB_MESSAGE_HANDLE messageHandle = IoTHubMessage_CreateFromString(eventBuffer);

	if (messageHandle == 0) {
		Log_Debug("WARNING: unable to create a new IoTHubMessage\n");
		return;
	}

	if (IoTHubDeviceClient_LL_SendEventAsync(iothubClientHandle, messageHandle, SendMessageCallback,
		/*&callback_param*/ 0) != IOTHUB_CLIENT_OK) {
		Log_Debug("WARNING: failed to hand over the message to IoTHubClient\n");
	}
	else {
		Log_Debug("INFO: IoTHubClient accepted the message for delivery\n");
	}

	IoTHubMessage_Destroy(messageHandle);
}

/// <summary>
///     Callback confirming message delivered to IoT Hub.
/// </summary>
/// <param name="result">Message delivery status</param>
/// <param name="context">User specified context</param>
static void SendMessageCallback(IOTHUB_CLIENT_CONFIRMATION_RESULT result, void* context)
{
	Log_Debug("INFO: Message received by IoT Hub. Result is: %d\n", result);
}

/// <summary>
///     Creates and enqueues a report containing the name and value pair of a Device Twin reported
///     property. The report is not sent immediately, but it is sent on the next invocation of
///     IoTHubDeviceClient_LL_DoWork().
/// </summary>
/// <param name="propertyName">the IoT Hub Device Twin property name</param>
/// <param name="propertyValue">the IoT Hub Device Twin property value</param>
static void TwinReportBoolState(const char* propertyName, bool propertyValue)
{
	if (iothubClientHandle == NULL) {
		Log_Debug("ERROR: client not initialized\n");
	}
	else {
		static char reportedPropertiesString[30] = { 0 };
		int len = snprintf(reportedPropertiesString, 30, "{\"%s\":%s}", propertyName,
			(propertyValue == true ? "true" : "false"));
		if (len < 0)
			return;

		if (IoTHubDeviceClient_LL_SendReportedState(
			iothubClientHandle, (unsigned char*)reportedPropertiesString,
			strlen(reportedPropertiesString), ReportStatusCallback, 0) != IOTHUB_CLIENT_OK) {
			Log_Debug("ERROR: failed to set reported state for '%s'.\n", propertyName);
		}
		else {
			Log_Debug("INFO: Reported state for '%s' to value '%s'.\n", propertyName,
				(propertyValue == true ? "true" : "false"));
		}
	}
}

/// <summary>
///     Callback invoked when the Device Twin reported properties are accepted by IoT Hub.
/// </summary>
static void ReportStatusCallback(int result, void* context)
{
	Log_Debug("INFO: Device Twin reported properties update result: HTTP status code %d\n", result);
}

/// <summary>
///     Sends ADC values 
/// </summary>
static void Send_ADC_data(void)
{
	
	Log_Debug("Current IS: %f \n.", toAmpsACS712(ADC_Data.u32));
	char tempBuffer[20];
	int len = snprintf(tempBuffer, 6, "%f", toAmpsACS712(ADC_Data.u32));
	if (len > 0)
		SendTelemetry("ADC1", tempBuffer);
	else
		Log_Debug("ERROR: ADC value not send to IoT Central");
}

/// <summary>
///     Sends IoT telemetry 
/// </summary>
static void Send_Energy_data(void)
{
	char tempBuffer[20];
	int len = snprintf(tempBuffer, 6, "%f", TotalEnergy);
	if (len > 0)
		SendTelemetry("Et", tempBuffer);
	else
		Log_Error("Total Energy Value not sent !!!", -1);
}

