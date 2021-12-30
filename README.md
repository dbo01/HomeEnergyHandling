# HomeEnergyHandling

After cloning this repository, Security.h file is needed containing only one define.
#define MY_CONNECTION_STRING "HostName=YOUR HOST NAME.azure-devices.net;DeviceId=YOUR DEVICE ID;SharedAccessKey=YOUR SHARED ACCESS KEY"

When you create you IoT Central /IoT Hub Application, go to your device and click connect, note Scope ID, Device ID, Pimary Key.

A one-time execution of a command-line tool called `dps-keygen` is required from Windows Powershell to generate the "connection string"
Run `dps-keygen -si:<Scope ID> -di:<Device ID> -dk:<Device primary shared key>`

This command will generate connection string which should be copied to MY_CONNECTION_STRING as showed above.
