@echo off
setlocal

set _EXITCODE=0

REM If no target is provided, default to start
if [%1]==[] goto start

set _TARGETS=start,test,build

REM Run target.
for %%a in (%_TARGETS%) do (if x%1==x%%a goto %%a)
goto usage

REM start builds the plugin and runs the vault server with the plugin mounted.
:start
    call :build
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=.\vault\plugins
	goto :eof

REM build compiles the plugin
:build
    mkdir .\vault\plugins\
	go build -o .\vault\plugins\atlas.exe cmd\atlas\main.go
	goto :eof

REM test runs the unit tests and vets the code.
:test
	go test %_TEST% %TESTARGS% -timeout=30s -parallel=4
    go vet .\...
	call :setMaxExitCode %ERRORLEVEL%
	echo.

:setMaxExitCode
	if %1 gtr %_EXITCODE% set _EXITCODE=%1
	goto :eof
:usage
	echo usage: make [target]
	echo.
	echo target is in {%_TARGETS%}.
	echo target defaults to test if none is provided.
	exit /b 2
	goto :eof