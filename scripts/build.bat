@echo off
setlocal enabledelayedexpansion
rem Build helper: load the MSVC environment, then run cargo with the arguments given.
rem
rem Why this exists: rustc's linker step needs the MSVC + Windows SDK import
rem libraries (kernel32.lib, ...), which only exist on the LIB path after
rem vcvars64.bat. On a plain shell, a stray link.exe earlier in PATH (MSYS
rem coreutils ships one) is picked up instead of MSVC's linker.
rem
rem Usage:  scripts\build.bat build --release
rem         scripts\build.bat test
rem         scripts\build.bat clippy --all-targets -- -D warnings

set "VCVARS="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -prerelease -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2^>nul`) do (
        set "VCVARS=%%i\VC\Auxiliary\Build\vcvars64.bat"
    )
)

rem vswhere cannot see installations newer than its own query version (VS previews
rem ship ahead of the bundled locator), so fall back to the standard install roots.
if not defined VCVARS (
    for /d %%d in ("%ProgramFiles%\Microsoft Visual Studio\*") do (
        for /d %%e in ("%%d\*") do (
            if exist "%%e\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%%e\VC\Auxiliary\Build\vcvars64.bat"
        )
    )
)

if not defined VCVARS (
    echo [build] No Visual Studio MSVC toolchain found.
    echo [build] Install Visual Studio Build Tools with "Desktop development with C++".
    exit /b 1
)

call "%VCVARS%" >nul
if errorlevel 1 (
    echo [build] vcvars failed: %VCVARS%
    exit /b 1
)

cargo %*
exit /b %errorlevel%
