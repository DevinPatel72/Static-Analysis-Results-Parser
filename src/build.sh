#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

shopt -s globstar  # Enable recursive ** globbing (bash 4+)

# Get arch info
osName=$(grep ^ID= /etc/os-release | cut -d= -f2 | tr -d '"')
if [ -z "$osName" ]; then
    osName="unknown"
fi
osName="${osName^,,}"
osArch=$(uname -m)

# Get SARP version
ver=$(head -n 3 "$SCRIPT_DIR/parsers/__init__.py" | grep "^VERSION" | cut -d= -f2 | tr -d " '")

# Create Bin Dir
BIN_DIR="../bin/SARP_v${ver}_${osName}_${osArch}"

# Function to check if file is text
is_text() {
    # Quick null byte test
    # if grep -q $'\x00' "$1"; then
    #     return 0  # not text
    # fi

    # MIME fallback
    mime=$(file -b --mime-type "$1" 2>/dev/null) || return 1
    echo "$mime"

    case "$mime" in
        text/*|application/json|application/xml|application/javascript|application/x-sh|*/xml)
            return 0 ;;  # not binary
        *)
            return 1 ;;  # binary
    esac
}

# Clean
clean() {
    rm -rf "$BIN_DIR"
    mkdir -p "$BIN_DIR"
    #rm -f config/user_inputs.json
    clean_build_files
}

# Clean build files only
clean_build_files() {
    find . -name "__pycache__" -exec rm -rf {} \;
    rm -rf build dist logs
}

# Main #
clean

# Exit if only clean is needed
if [[ "$1" == "clean" ]]; then
    exit 0
fi

# Determine dos2unix command
if ! command -v dos2unix >/dev/null 2>&1; then
    echo "dos2unix could not be found, using sed to convert line endings"
    sleep 2
    CONVERT_LINE_ENDINGS="sed -i 's/\r$//'"
else
    CONVERT_LINE_ENDINGS="dos2unix"
fi

# Build
pyinstaller --clean parse-cli.spec
pyinstaller --clean parse-gui.spec

# Copy config
cp -r config dist/config

# Convert config files from CRLF to LF
for file in dist/config/**/*; do
    [[ -f "$file" ]] || continue

    # Check if file is text
    if is_text "$file"; then
        eval "$CONVERT_LINE_ENDINGS '$file'"
    fi
done

# Copy files to bin dir
mkdir -p "$BIN_DIR"
cp -r dist/. "$BIN_DIR/"

# Delete the user_inputs.json and preflight_rules.py
rm "$BIN_DIR/config/user_inputs.json"
rm "$BIN_DIR/config/preflight/preflight_rules.py"

# Cleanup build files
clean_build_files

printf "\n"
echo Build complete. Executables have been copied into $(realpath "$BIN_DIR")
