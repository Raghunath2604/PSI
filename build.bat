@echo off
REM ============================================================
REM  DPI Engine v4.0 - Build Script for Windows
REM  Builds: dpi_working.exe  (PCAP analysis, offline)
REM          dpi_engine.exe   (multi-threaded PCAP)
REM          dpi_live.exe     (Real-time live capture **Run as Admin**)
REM  Requires: MSYS2 with MinGW-w64 at C:\msys64
REM ============================================================

SET "MINGW=%SystemDrive%\msys64\mingw64\bin"
IF NOT EXIST "%MINGW%\g++.exe" (
    echo ERROR: g++.exe not found at %MINGW%
    echo Install MSYS2 from https://www.msys2.org/
    echo Then:  pacman -S mingw-w64-x86_64-gcc
    exit /b 1
)
SET "PATH=%MINGW%;%PATH%"
cd /d "%~dp0"

echo.
echo ================================================================
echo   DPI ENGINE v4.0 -- Build System
echo ================================================================
echo.

SET FAILED=0

echo [1/3] Building dpi_working.exe  (single-threaded PCAP analysis)...
g++ -std=c++17 -O2 -I include ^
    src\main_working.cpp src\pcap_reader.cpp src\packet_parser.cpp ^
    src\sni_extractor.cpp src\types.cpp ^
    -o dpi_working.exe 2>&1
IF %errorlevel%==0 ( echo   ^> OK ) ELSE ( echo   ^> FAILED & SET FAILED=1 )

echo.
echo [2/3] Building dpi_engine.exe   (multi-threaded PCAP analysis)...
g++ -std=c++17 -O2 -I include ^
    src\dpi_mt.cpp src\pcap_reader.cpp src\packet_parser.cpp ^
    src\sni_extractor.cpp src\types.cpp ^
    -pthread -o dpi_engine.exe 2>&1
IF %errorlevel%==0 ( echo   ^> OK ) ELSE ( echo   ^> FAILED & SET FAILED=1 )

echo.
echo [3/3] Building dpi_live.exe     (real-time live capture)...
g++ -std=c++17 -O2 -I include ^
    src\dpi_live.cpp ^
    -lws2_32 -liphlpapi -pthread ^
    -o dpi_live.exe 2>&1
IF %errorlevel%==0 ( echo   ^> OK ) ELSE ( echo   ^> FAILED & SET FAILED=1 )

echo.
IF %FAILED%==1 (
    echo ================================================================
    echo   BUILD FAILED - check errors above
    echo ================================================================
    exit /b 1
)

echo ================================================================
echo   BUILD COMPLETE
echo ================================================================
echo.
echo  dpi_working.exe  -- Analyze PCAP files (offline)
echo    Usage: dpi_working.exe input.pcap output.pcap [options]
echo    Flags: --block-app ^<App^>  --block-domain ^<d^>  --block-port ^<p^>
echo           --rules rules.txt  --export-json r.json  --export-csv r.csv
echo           --top ^<N^>  --verbose  --quiet
echo.
echo  dpi_engine.exe   -- Multi-threaded PCAP analysis (faster)
echo    Usage: dpi_engine.exe input.pcap output.pcap [--lbs N] [--fps N]
echo.
echo  dpi_live.exe     -- REAL-TIME live capture (Run as Administrator!)
echo    Usage: dpi_live.exe [--iface ^<IP^>] [--save cap.pcap] [options]
echo    Flags: --block-app ^<App^>  --block-domain ^<d^>  --block-port ^<p^>
echo           --no-save
echo.
echo  Quick tests:
echo    dpi_working.exe test_dpi.pcap output.pcap --top 5
echo    dpi_live.exe --help
echo.
