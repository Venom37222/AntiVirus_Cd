@echo off 
title Antivirus 
echo Antivirus 
echo created by Venom37222
:start if exist virus.bat goto infected 
cd C:\Windows\system32 
if not exist virus.bat goto clean :infected 
echo warning virus detected 
exit 
del virus.bat 
pause 
goto start 
:clean 
echo System secure! 
pause
