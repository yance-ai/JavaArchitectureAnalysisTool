@echo off
REM build.bat — 跨平台编译 JavaArchitectureAnalysisTool / Cross-platform build
REM 用法 / Usage:
REM   build.bat              编译所有平台到 dist/                  Build all platforms to dist/
REM   build.bat current      仅编译当前平台                        Build current platform only
REM   build.bat linux        仅编译 Linux (amd64 + arm64)          Build Linux only
REM   build.bat windows      仅编译 Windows (amd64)                Build Windows only
REM   build.bat darwin       仅编译 macOS (amd64 + arm64)          Build macOS only
REM   build.bat clean        清理 dist/ 目录                       Clean dist/ directory

setlocal EnableDelayedExpansion

set "PROJECT=JavaArchitectureAnalysisTool"
set "DIST_DIR=dist"

REM ====== 颜色输出 (Windows 10+) / Colored output ======
REM 获取 ESC 字符 (ASCII 27) / Get ESC character
for /f %%i in ('echo prompt $E ^| cmd') do set "ESC=%%i"

set "RED=!ESC![31m"
set "GREEN=!ESC![32m"
set "YELLOW=!ESC![33m"
set "BLUE=!ESC![34m"
set "NC=!ESC![0m"

REM ====== 双语输出 / Bilingual output ======
:bi
echo %~1 / %~2
goto :eof

:bi_blue
echo %BLUE%%~1 / %~2%NC%
goto :eof

:bi_green
echo %GREEN%%~1 / %~2%NC%
goto :eof

:bi_yellow
echo %YELLOW%%~1 / %~2%NC%
goto :eof

:bi_red
echo %RED%%~1 / %~2%NC%
goto :eof

:green
echo %GREEN%%~1%NC%
goto :eof

:red
echo %RED%%~1%NC%
goto :eof

:yellow
echo %YELLOW%%~1%NC%
goto :eof

:blue
echo %BLUE%%~1%NC%
goto :eof

REM ====== 编译单个目标 / Build single target ======
:build_one
setlocal
set "GOOS_VAL=%~1"
set "GOARCH_VAL=%~2"
set "SUFFIX=%~3"
set "OUTPUT=%DIST_DIR%\%PROJECT%-%SUFFIX%"

echo   -^> %GOOS_VAL%/%GOARCH_VAL% -^> %OUTPUT% ...
set "GOOS=%GOOS_VAL%"
set "GOARCH=%GOARCH_VAL%"
go build -trimpath -ldflags "-s -w" -o "%OUTPUT%" .
if errorlevel 1 (
    endlocal
    call :bi_red "失败" "FAIL"
    exit /b 1
)
endlocal
call :green "OK"
goto :eof

REM ====== 编译所有平台 / Build all platforms ======
:build_all
call :bi_blue "=== 编译所有平台 ===" "=== Build All Platforms ==="
if not exist "%DIST_DIR%" mkdir "%DIST_DIR%"

call :blue "Linux:"
call :build_one linux amd64 linux-amd64
if errorlevel 1 exit /b %ERRORLEVEL%
call :build_one linux arm64 linux-arm64
if errorlevel 1 exit /b %ERRORLEVEL%

call :blue "Windows:"
call :build_one windows amd64 windows-amd64.exe
if errorlevel 1 exit /b %ERRORLEVEL%

call :blue "macOS:"
call :build_one darwin amd64 darwin-amd64
if errorlevel 1 exit /b %ERRORLEVEL%
call :build_one darwin arm64 darwin-arm64
if errorlevel 1 exit /b %ERRORLEVEL%

echo.
call :bi_green "=== 编译完成 ===" "=== Build Complete ==="
dir /b "%DIST_DIR%\"
goto :eof

REM ====== 仅编译 Linux / Build Linux only ======
:build_linux
call :bi_blue "=== 编译 Linux ===" "=== Build Linux ==="
if not exist "%DIST_DIR%" mkdir "%DIST_DIR%"
call :build_one linux amd64 linux-amd64
if errorlevel 1 exit /b %ERRORLEVEL%
call :build_one linux arm64 linux-arm64
if errorlevel 1 exit /b %ERRORLEVEL%
echo.
call :bi_green "=== 编译完成 ===" "=== Build Complete ==="
dir /b "%DIST_DIR%\%PROJECT%-linux-*"
goto :eof

REM ====== 仅编译 Windows / Build Windows only ======
:build_windows
call :bi_blue "=== 编译 Windows ===" "=== Build Windows ==="
if not exist "%DIST_DIR%" mkdir "%DIST_DIR%"
call :build_one windows amd64 windows-amd64.exe
if errorlevel 1 exit /b %ERRORLEVEL%
echo.
call :bi_green "=== 编译完成 ===" "=== Build Complete ==="
dir /b "%DIST_DIR%\%PROJECT%-windows-*"
goto :eof

REM ====== 仅编译 macOS / Build macOS only ======
:build_darwin
call :bi_blue "=== 编译 macOS ===" "=== Build macOS ==="
if not exist "%DIST_DIR%" mkdir "%DIST_DIR%"
call :build_one darwin amd64 darwin-amd64
if errorlevel 1 exit /b %ERRORLEVEL%
call :build_one darwin arm64 darwin-arm64
if errorlevel 1 exit /b %ERRORLEVEL%
echo.
call :bi_yellow "注意: Windows 下无法编译 universal 二进制 (需 macOS lipo)" "Note: Universal binary requires macOS lipo"
call :bi_green "=== 编译完成 ===" "=== Build Complete ==="
dir /b "%DIST_DIR%\%PROJECT%-darwin-*"
goto :eof

REM ====== 编译当前平台 / Build current platform ======
:build_current
call :bi_blue "=== 编译当前平台 ===" "=== Build Current Platform ==="
go build -trimpath -ldflags "-s -w" -o "%PROJECT%" .
if errorlevel 1 (
    call :bi_red "失败" "FAIL"
    exit /b 1
)
call :bi_green "=== 编译完成: .\%PROJECT% ===" "=== Build Complete: .\%PROJECT% ==="
echo.
dir "%PROJECT%"
goto :eof

REM ====== 清理 / Clean ======
:clean
call :bi_blue "=== 清理 %DIST_DIR%/ ===" "=== Clean %DIST_DIR%/ ==="
if exist "%DIST_DIR%" (
    rmdir /s /q "%DIST_DIR%"
    echo %DIST_DIR% 已删除 / %DIST_DIR% deleted
) else (
    echo %DIST_DIR% 不存在，无需清理 / %DIST_DIR% does not exist, nothing to clean
)
call :bi_green "=== 清理完成 ===" "=== Clean Complete ==="
goto :eof

REM ====== 显示帮助 / Show help ======
:show_help
echo 用法 / Usage: build.bat [target]
echo   (无参数)   编译所有平台到 dist/                           Build all platforms to dist/
echo   all        编译所有平台到 dist/                           Build all platforms to dist/
echo   current    编译当前平台到当前目录                         Build current platform to current directory
echo   linux      编译 Linux (amd64 + arm64) 到 dist/            Build Linux (amd64 + arm64) to dist/
echo   windows    编译 Windows (amd64) 到 dist/                  Build Windows (amd64) to dist/
echo   darwin     编译 macOS (amd64 + arm64) 到 dist/           Build macOS (amd64 + arm64) to dist/
echo   clean      清理 dist/ 目录                                Clean dist/ directory
echo   help       显示此帮助信息                                 Show this help message
goto :eof

REM ====== 主逻辑 / Main logic ======
set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=all"

if /i "%TARGET%"=="all" (
    call :build_all
) else if /i "%TARGET%"=="linux" (
    call :build_linux
) else if /i "%TARGET%"=="windows" (
    call :build_windows
) else if /i "%TARGET%"=="darwin" (
    call :build_darwin
) else if /i "%TARGET%"=="current" (
    call :build_current
) else if /i "%TARGET%"=="clean" (
    call :clean
) else if /i "%TARGET%"=="help" (
    call :show_help
) else if /i "%TARGET%"=="-h" (
    call :show_help
) else (
    call :bi_red "未知目标: %TARGET%" "Unknown target: %TARGET%"
    call :bi "运行 build.bat help 查看用法" "Run build.bat help for usage"
    exit /b 1
)

endlocal