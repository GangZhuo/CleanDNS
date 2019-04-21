@echo off

set SERVICE_NAME=CleanDNS
set SERVICE_DESCRIPTION=Non-polluting DNS. Forward DNS requests with ECS (edns-client-subnet) support.

SET CONFIG_FILE=cleandns.config

set CURR_PATH=%~dp0

if not exist "%CURR_PATH%%CONFIG_FILE%" (
	(
		echo.
		echo config cfg
		echo 	option bind_addr '0.0.0.0'
		echo 	option bind_port '5354'
		echo 	option chnroute '%CURR_PATH%chnroute.txt'
		echo 	option china_ip '203.208.32.0/24'
		echo 	option foreign_ip '218.189.25.0/24'
		echo 	option dns_server '8.8.8.8:53,114.114.114.114'
		echo 	option compression '1'
		echo 	option timeout '5'
		echo 	option log_file '%CURR_PATH%cleandns.log'
		echo 	#option proxy 'socks5://127.0.0.1:1080'
	)> "%CURR_PATH%%CONFIG_FILE%"
)

sc create "%SERVICE_NAME%" binpath= "\"%CURR_PATH%cleandns.exe\" --daemon --config=\"%CURR_PATH%%CONFIG_FILE%\" --launch_log=\"%CURR_PATH%cleandns_launch_log.log\"" displayname= "%SERVICE_NAME%" depend= Tcpip start= auto  

sc description "%SERVICE_NAME%" "%SERVICE_DESCRIPTION%"

pause

@echo on