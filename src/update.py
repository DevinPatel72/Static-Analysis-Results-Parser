#!/usr/bin/env python3

# Imports
import os
import sys
import traceback
import truststore
import requests
import platform
import tempfile
import shutil
import time
import logging
from urllib.parse import urlsplit, urlunsplit
import parsers

# Configure CA trust
truststore.inject_into_ssl()

# This gets overwritten when executing main()
logger = logging.getLogger(__name__)


################################
# Globals
################################

releases = None

################################
# Functions
################################

def ask(prompt_text, default=True):
    y = 'Y' if default else 'y'
    n = 'N' if not default else 'n'
    while True:
        uinput = input(f"\n{prompt_text}\n({y}/{n}): ").strip().lower()
        if len(uinput) == 0:
            return default
        elif uinput in ['y', 'yes', 'yuh', 'uh-huh']: return True
        elif uinput in ['n', 'no', 'nah', 'nuh-uh']: return False
        else:
            print("\n[ERROR]  Invalid input. Please enter yes or no. (Leave blank for {})".format('\"yes\"' if default else '\"no\"'))

def join_url(base, *segments):
    parts = urlsplit(base)
    path = "/".join(
        [parts.path.rstrip("/")] +
        [s.strip("/") for s in segments]
    )
    return str(urlunsplit(parts._replace(path=path)))

def version_key(version, parts=3):
    nums = version.removeprefix("v").split(".")
    nums.extend(["0"] * (parts - len(nums)))
    return tuple(map(int, nums[:parts]))

# Check repository for most recent version
def check_version(current_version):
    global release_assets_json

    latest_url = join_url(parsers.REPO_BASE_URL, "releases", "latest")
    release_assets_json = None

    try:
        # 1 second connect timeout, 3 second read timeout
        response = requests.get(latest_url, timeout=(1, 3))
        response.raise_for_status()

        release = response.json()
        latest_version = release["tag_name"]
        release_assets_json = release

    except requests.exceptions.ConnectTimeout:
        logger.warning("Timed out while connecting to GitHub.")
        return None

    except requests.exceptions.ConnectionError:
        logger.warning("Unable to connect to GitHub. Please check your network connection.")
        return None

    except requests.exceptions.ReadTimeout:
        logger.warning("GitHub took too long to respond.")
        return None

    except requests.exceptions.HTTPError as e:
        logger.warning("GitHub returned HTTP %d.", e.response.status_code)
        return None

    except (ValueError, KeyError) as e:
        logger.warning("Invalid release information received from GitHub: %s", e)
        return None

    except requests.exceptions.RequestException as e:
        logger.warning("Failed to check for updates: %s", e)
        return None

    if version_key(latest_version.lstrip("v")) > version_key(current_version):
        return latest_version

    return None

def get_platform():
    system = platform.system()

    if system == "Windows":
        return "windows"

    if system == "Darwin":
        return "macos"

    if system == "Linux":
        distro = "linux"

        try:
            with open("/etc/os-release", encoding="utf-8") as f:
                info = {}
                for line in f:
                    if "=" in line:
                        key, value = line.rstrip().split("=", 1)
                        info[key] = value.strip('"')

            distro_id = info.get("ID", "").lower()
            distro_like = info.get("ID_LIKE", "").lower()

            if distro_id in ("debian", "ubuntu", "linuxmint"):
                distro = "debian"
            elif distro_id in ("rhel", "centos", "fedora", "rocky", "almalinux"):
                distro = "redhat"
            elif distro_id == "arch":
                distro = "arch"
            elif "debian" in distro_like:
                distro = "debian"
            elif any(x in distro_like for x in ("rhel", "fedora")):
                distro = "redhat"

        except OSError:
            pass

        return distro

    raise RuntimeError(f"Unsupported operating system: {system}")

def get_current_platform():
    os_name = get_platform()
    machine = platform.machine().lower()
    
    if machine in ("x86_64", "amd64"):
        arch = "x86_64" if os_name != 'windows' else 'x64'
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    else:
        raise RuntimeError(f"Unsupported architecture: {machine}")
    
    return os_name, arch

def download_with_retries(url, path, retries=5, chunk_size=1024 * 1024, timeout=(10, 120)):
    for attempt in range(retries):
        try:
            with requests.get(url, stream=True, timeout=timeout) as r:
                r.raise_for_status()

                with open(path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=chunk_size):
                        if chunk:
                            f.write(chunk)

            return  # success

        except requests.RequestException as re:
            if attempt == retries - 1:
                raise
            time.sleep(2 ** attempt)  # exponential backoff
        except Exception:
            raise

def extract_archive(path, destination):
    if path.endswith(".zip"):
        import zipfile
        with zipfile.ZipFile(path) as zf:
            zf.extractall(destination)
    elif path.endswith((".tar.gz", ".tgz")):
        import tarfile
        with tarfile.open(path, "r:gz") as tf:
            tf.extractall(destination)
    else:
        raise ValueError(f"Unsupported archive format: {path}")
    
################################
# Main
################################

def main():
    # Do all imports here instead of at the module level
    # Configure root path and important dirs of script
    if getattr(sys, 'frozen', False):
        # Running as bundled executable
        parsers.EXE_ROOT_DIR = os.path.dirname(sys.executable)
        logname = os.path.splitext(os.path.basename(sys.executable))[0]+'.log'
    else:
        # Running as script
        print("Cannot execute via interpreter.")
        sys.exit(1)
        parsers.EXE_ROOT_DIR = os.path.dirname(__file__)
        logname = os.path.splitext(os.path.basename(__file__))[0]+'.log'

    # Capitalized drive letter if on Windows
    drive, rest = os.path.splitdrive(parsers.EXE_ROOT_DIR)
    if len(drive) > 0: drive = drive.upper()
    parsers.EXE_ROOT_DIR = os.path.join(drive, rest)

    # Set import directories
    parsers.CONFIG_DIR = os.path.join(parsers.EXE_ROOT_DIR, parsers.CONFIG_DIR)
    parsers.MAPPINGS_DIR = os.path.join(parsers.CONFIG_DIR, parsers.MAPPINGS_DIR)
    parsers.PREFLIGHT_DIR = os.path.join(parsers.CONFIG_DIR, parsers.PREFLIGHT_DIR)

    # Set inputs directory
    parsers.INPUTS_DIR = os.path.join(parsers.CONFIG_DIR, parsers.INPUTS_DIR)

    # Set log paths
    parsers.LOGS_DIR = os.path.join(parsers.EXE_ROOT_DIR, parsers.LOGS_DIR)
    os.makedirs(parsers.LOGS_DIR, exist_ok=True)
    logfile = os.path.join(parsers.LOGS_DIR, logname)
    parsers.LOGFILE = logfile
    
    # Configure logger
    logging.basicConfig(filename=logfile, level=logging.INFO, encoding='utf-8', format='%(name)-18s :: %(levelname)-8s :: %(message)s', filemode='w')
    consoleHandler = logging.StreamHandler()
    consoleHandler.setLevel(logging.CRITICAL)
    consoleHandler.setFormatter(logging.Formatter(fmt='\n[%(levelname)s]  %(message)s'))
    logging.getLogger().addHandler(consoleHandler)
    logger = logging.getLogger(__name__)

    from datetime import datetime
    logger.info(f"{parsers.PROG_NAME} {parsers.VERSION}")
    logger.info(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    ################################################################################################################################################
    
    
    # Check for most recent release
    latest_version = check_version(parsers.VERSION)
    if latest_version is None or not isinstance(latest_version, str):
        print(f'You are on the most recent version of {parsers.PROG_NAME_ABBR}')
        sys.exit(0)
    
    # Query to continue update
    print("A new version is available for {}: {} -> {}".format(parsers.PROG_NAME_ABBR, parsers.VERSION, latest_version.lstrip('v')))
    if not ask("Would you like to update to version {}?".format(latest_version.lstrip('v')), default=False):
        sys.exit(0)

    # Get OS name and arch
    try:
        os_name, arch = get_current_platform()
    except RuntimeError as re:
        logger.critical(f"fatal error: Cannot determining platform name: {re}")
        sys.exit(4)
    
    # Get correct asset download url
    for asset in release_assets_json["assets"]:
        asset_name = asset["name"]
        if f"_{os_name}_{arch}" in asset_name:
            download_url = asset["browser_download_url"]
            break
    else:
        logger.critical("fatal error: No releases compatible with this platform have been found.")
        sys.exit(4)
    
    # Create temp directory to load download into
    with tempfile.TemporaryDirectory() as temp_dir:
        download_path = os.path.join(temp_dir, asset_name)
        print('Downloading files...', end='\r')
        try:
            download_with_retries(download_url, download_path)
            print('Downloading files...Success')
        except Exception as e:
            logger.critical(f"fatal error: Download for {asset_name} failed: {e}")
            print()
            sys.exit(5)
        
        # Extract downloaded zip
        try:
            extract_archive(download_path, temp_dir)
        except ValueError as ve:
            logger.critical(f"fatal error: {ve}")
            sys.exit(5)
        
        # Set up temp paths
        t_base_path = os.path.join(temp_dir, os.path.splitext(asset_name)[0])
        
        print('Installing files...', end='\r')
        try:
            shutil.copytree(t_base_path, parsers.EXE_ROOT_DIR, dirs_exist_ok=True, ignore=shutil.ignore_patterns(os.path.basename(sys.executable)))
            print('Installing files...Success')
        except Exception as e:
            logger.critical(f"fatal error: Installation failed: {e}")
            print()
            sys.exit(5)
        
        print('\nUpdate complete!')
        
        
        



if __name__ == "__main__":
    exitcode = 0
    try:
        main()
    except SystemExit as se:
        exitcode = se.code
    except KeyboardInterrupt:
        print("\n\nProgram terminated by user...")
        logger.info("Program terminated by user...")
        exitcode = 6
    except PermissionError:
        logger.critical("File access error. Please do not open or lock an input file while the parser is running.")
        exitcode = 2
    except:
        logger.critical(f"Uncaught exception caused {parsers.PROG_NAME_ABBR} to crash. Exception trace has been output to the logfile.")
        logger.error("\n" + traceback.format_exc())
        exitcode = 1
    finally:
        logger.info(f"Program terminated with exit code {exitcode}")
        sys.exit(exitcode)