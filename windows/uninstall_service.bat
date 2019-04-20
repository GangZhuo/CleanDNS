@echo off

set SERVICE_NAME=CleanDNS

sc delete "%SERVICE_NAME%"  

pause

@echo on