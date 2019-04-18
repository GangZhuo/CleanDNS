@echo off

set SERVICE_NAME=CleanDNS

sc delete "%SERVICE_NAME%"  

@echo on