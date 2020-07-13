@echo off

rem Start-up script for JEB (Windows Console)

rem set JAVA_HOME=C:\Program Files (x86)\Java\jdk1.7.0_65\
rem set JAVA_HOME=C:\Program Files\Java\jdk1.7.0_65\
set JAVA_HOME=C:\Program Files (x86)\Java\jre7\
rem set JAVA_HOME=C:\Program Files\Java\jre7\

rem Prefer a JDK over a JRE, which allows support for JEB native Java plugins
if defined JAVA_HOME (set base="%JAVA_HOME%\bin") else (set base="%SystemRoot%\System32")
set JAVA=%base%\java.exe

rem Note: Make sure your SWT build matches your Java build (32-bit or 64-bit)
rem If the Java path generation does not yield a correct result, manually set
rem the JAVA variable (defined above) to a correct value

if exist %JAVA% goto :checkdep
echo JEB requires a Java runtime environment, please install one.
exit /B -1

:checkdep
set JEBDIPATH="%~dp0\bin\jebdi.jar"
%JAVA% -jar %JEBDIPATH%
if errorlevel 0 goto :checkupdate
exit /B -1

:checkupdate
set JEBUPPATH="%~dp0\bin\jebup.jar"
%JAVA% -jar %JEBUPPATH%
if errorlevel 0 goto :runjeb
exit /B -1

:runjeb
set JEBPATH="%~dp0\bin\jeb.jar"

rem Allow the Java VM to allocate up to 2 Gb of memory
%JAVA% -Xmx1024m -XX:-UseParallelGC -XX:MinHeapFreeRatio=15 -jar %JEBPATH% %*
rem %JAVA% -Xmx4096m -XX:-UseParallelGC -XX:MinHeapFreeRatio=15 -jar %JEBPATH% %*
