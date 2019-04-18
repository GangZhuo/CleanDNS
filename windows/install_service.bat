@echo off


set SERVICE_NAME=CleanDNS
set SERVICE_DESCRIPTION=Non-polluting DNS. Support ECS (edns-client-subnet). https://github.com/GangZhuo/CleanDNS

SET BIND_ADDR=0.0.0.0
SET BIND_PORT=5354
SET CHNROUTE=chnroute.txt
SET CHINA_IP=203.208.32.0/24
SET FOREIGN_IP=218.189.25.0/24
SET DNS_SERVER=8.8.8.8:53,114.114.114.114
SET COMPRESSION=-m
SET TIMEOUT=5
SET VERBOSE=

set CURR_PATH=%~dp0

sc create "%SERVICE_NAME%" binpath= "\"%CURR_PATH%cleandns.exe\" -b %BIND_ADDR% -p %BIND_PORT% -c \"%CURR_PATH%%CHNROUTE%\" -l %CHINA_IP% -f %FOREIGN_IP% -s %DNS_SERVER% %COMPRESSION% -t %TIMEOUT% %VERBOSE% --daemon" displayname= "%SERVICE_NAME%" depend= Tcpip start= auto  

sc description "%SERVICE_NAME%" "Non-polluting DNS. Support ECS (edns-client-subnet). https://github.com/GangZhuo/CleanDNS"

@echo on