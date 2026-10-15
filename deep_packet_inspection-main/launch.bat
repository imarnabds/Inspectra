@echo off
setlocal
cd /d "%~dp0"

if /i "%1"=="web" goto launch_web
if /i "%1"=="--web" goto launch_web
if /i "%1"=="ui" goto launch_web

echo ======================================================================
echo    Deep Packet Inspection (DPI) ^& Packet Analyzer Launcher
echo ======================================================================
echo.
echo Tip: To launch the Web Dashboard UI instead, run: launch.bat web
echo.

:: Detect nested or local src directory
if exist "src\main\java\com\packetanalyzer\Main.java" (
    set "PROJ_DIR=."
) else if exist "deep_packet_inspection-main\src\main\java\com\packetanalyzer\Main.java" (
    set "PROJ_DIR=deep_packet_inspection-main"
) else (
    echo [ERROR] Could not find project source directory.
    exit /b 1
)

:: Ensure PCAP file exists, generate if missing
if not exist "%PROJ_DIR%\test_dpi.pcap" (
    echo [INFO] Generating sample PCAP file with TLS SNI, HTTP, and DNS...
    python "%PROJ_DIR%\generate_test_pcap.py"
)

:: Compile cleanly
echo [INFO] Compiling Java DPI Analyzer...
pushd "%PROJ_DIR%\src\main\java"
javac com\packetanalyzer\*.java
set "COMPILE_ERR=%ERRORLEVEL%"
popd

if %COMPILE_ERR% neq 0 (
    echo [ERROR] Compilation failed.
    exit /b %COMPILE_ERR%
)

:: Run Analyzer
echo [INFO] Running Deep Packet Inspection on test_dpi.pcap...
echo ======================================================================
echo.
java -cp "%PROJ_DIR%\src\main\java" com.packetanalyzer.Main "%PROJ_DIR%\test_dpi.pcap" %*

echo.
echo ======================================================================
echo Analysis finished successfully.
exit /b 0

:launch_web
echo ======================================================================
echo    Launching DeepPacket.AI Web Dashboard (http://localhost:5174)
echo ======================================================================
echo.
if exist "..\web" (
    cd ..\web
) else if exist "web" (
    cd web
)
npm.cmd run dev
