@ECHO OFF

Rem Get SARP version
for /f "tokens=2 delims==" %%A in ('findstr /b "VERSION" "%~dp0parsers\__init__.py"') do (
    set "ver=%%~A"
)

:: Trim spaces and quotes
set "ver=%ver: =%"
set "ver=%ver:'=%"

Rem Get Architecture info
if defined PROCESSOR_ARCHITEW6432 (
    set "arch=x64"
) else if /i "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    set "arch=x64"
) else (
    set "arch=x86"
)

set "BIN_DIR=..\bin\SARP_v%ver%_windows_%arch%"

Rem Clean
:clean
    setlocal enabledelayedexpansion

    call :clean_build_files

    REM Delete bin directory too if it exists
    for %%d in (%BIN_DIR%) do (
        echo Deleting folder: %%~fd
        rmdir /s /q "%%d"
    )

    Rem Delete user inputs
    Rem del config\user_inputs.json
    endlocal
    
    IF "%1"=="clean" (
        exit /b
    ) ELSE (
        call :build
        exit /b
    )

:clean_build_files

    REM List of folder names to delete
    for %%d in (__pycache__ build dist logs) do (
        for /d /r %%i in (%%d) do (
            if exist "%%i" (
                echo Deleting folder: %%i
                rmdir /s /q "%%i"
            )
        )
    )

    REM Optional: Delete orphaned files with specific extensions, like .pyc or .log
    for /r %%f in (*.pyc *.log) do (
        echo Deleting file: %%f
        del /f /q "%%f"
    )

    exit /b

Rem Build
:build
    pyinstaller --clean parse-cli.spec
    pyinstaller --clean parse-gui.spec

    Rem Copy config
    robocopy config dist\config /E /NFL /NDL /NJH /NJS /W:0 /R:0

    Rem Change all config files from LF to CRLF
    for /r "dist\config" %%F in (*.*) do (
        type "%%F" | more /p > "%%~pF\%%~nF-temp%%~xF"
        copy "%%~pF\%%~nF-temp%%~xF" "%%F"
        del "%%~pF\%%~nF-temp%%~xF"
    )

    Rem Copy dist contents to new directory
    robocopy dist "%BIN_DIR%" /E /NFL /NDL /NJH /NJS /W:0 /R:0

    Rem Delete the user_inputs.json and preflight_rules.py
    del "%BIN_DIR%\config\user_inputs*.json"
    del "%BIN_DIR%\config\preflight\preflight_rules.py"

    Rem Clean the build files
    call :clean_build_files
    
    echo:
    for %%I in ("%BIN_DIR%") do echo Build complete. Executables have been copied to %%~fI

    exit /b

call :clean
