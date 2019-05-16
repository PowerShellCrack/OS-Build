@ECHO OFF
SET TYPE=W10E1703
SET /P BUILD=What is the build number (eg. 1710)? 
ECHO Copying %TYPE%.wim
copy "%~dp0WIM\%BUILD%\%TYPE%.wim" "%~dp0SourceFiles\%TYPE%\sources\install.wim" /y
If %ERRORLEVEL% NEQ 0 GOTO EOF
ECHO Builiding %~dp0ISO\%TYPE%_%BUILD%.iso
"%~dp0OSCDIMG.EXE" -u2 -udfver102 -m -o -h -yo"%~dp0BootOrder.txt" -bootdata:2#p0,e,b"%~dp0etfsboot.com"#pEF,e,b"%~dp0efisys.bin" -l%TYPE%_%BUILD% "%~dp0SourceFiles\%TYPE%" "%~dp0ISO\%TYPE%_%BUILD%.iso" 
If %ERRORLEVEL% NEQ 0 GOTO EOF

:EOF
ECHO Error...%ERRORLEVEL%
timeout 30
EXIT