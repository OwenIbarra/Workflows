# Install Office 365 on MacOS with default install settings.
#!/usr/bin/env bash

# Description: Install Office 365 on MacOS with default install settings.

# Release Notes: Initial Release

print_help() {
  printf '\n### Below are all the (case sensitive) valid parameters for this script! ###\n'
  printf '\nPreset Parameter: --forcereboot \n'
  printf '\t%s\n' "--forcereboot: Reboot the device after the installation is complete."
}

# Determines whether or not help text is necessary and routes the output to stderr
die() {
  local _ret="${2:-1}"
  echo "$1" >&2
  test "${_PRINT_HELP:-no}" = yes && print_help >&2
  exit "${_ret}"
}

# THE DEFAULTS INITIALIZATION - OPTIONALS
_arg_forceReboot="off"
_reboot_time="1"                                  # Minutes
_reboot_message_giveup=$((_reboot_time * 60 / 2)) # Seconds
_reboot_message="A shutdown operation has been mandated by your IT staff and will occur in $((_reboot_time * 60)) seconds."
_install_url="https://go.microsoft.com/fwlink/p/?linkid=2009112"
_temp_file="/tmp/office.pkg"

# Grabbing the parameters and parsing through them.
parse_commandline() {
  while test $# -gt 0; do
    _key="$1"
    case "$_key" in
    --forcereboot)
      _arg_forceReboot="on"
      ;;
    --*)
      _PRINT_HELP=yes die "[Error] Got an unexpected argument '$1'" 1
      ;;
    *)
      _PRINT_HELP=yes die "[Error] Got an unexpected argument '$1'" 1
      ;;
    esac
    shift
  done
}

cleanup() {
  # Clean up the Office 365 installer

  # Check if the file exists
  if [[ -f "${_temp_file}" ]]; then
    if rm -f "${_temp_file}"; then
      echo "[Info] Cleaned up the Office 365 installer"
    else
      echo "[Error] Failed to clean up the Office 365 installer"
      exit 1
    fi
  else
    echo "[Info] Office 365 installer not found, nothing to clean up."
  fi
}

check_installed() {
  # Check if Office 365 is already installed
  if [[ -d "/Applications/Microsoft Word.app" ]] || [[ -d "/Applications/Microsoft Excel.app" ]] || [[ -d "/Applications/Microsoft PowerPoint.app" ]] || [[ -d "/Applications/Microsoft Outlook.app" ]]; then
    echo "[Error] Office 365 Suite or one of its components is already installed"
    echo "[Info] To remove the existing installation, please follow Microsoft's instructions found here:"
    echo "https://support.microsoft.com/en-us/office/troubleshoot-office-for-mac-issues-by-completely-uninstalling-before-you-reinstall-ec3aa66e-6a76-451f-9d35-cba2e14e94c0"
    exit 1
  fi
}

# Check if we are running as system/root
if [[ $EUID -ne 0 ]]; then
  echo "[Error] This script must be run as System from Ninja or root in the terminal" 1>&2
  exit 1
fi

# shellcheck disable=SC2154
if [[ "${forceReboot}" == "true" ]]; then
  _arg_forceReboot="on"
fi

parse_commandline "$@"

# Check if Office 365 is already installed
check_installed

# Install Office 365
echo "[Info] Downloading Office 365 installer"

# Download the Office 365 Suite
if curl -L -o "${_temp_file}" "${_install_url}"; then
  echo "[Info] Office 365 installer downloaded successfully"
else
  echo "[Error] Failed to download the Office 365 installer"
  exit 1
fi

# Install the Office 365 Suite
_results=$(installer -pkg "${_temp_file}" -target / -dumplog 2>&1)
# shellcheck disable=SC2181
if [[ $? -eq 0 ]]; then
  echo "[Info] Office 365 Suite installed successfully"
else
  echo "[Error] Failed to install the Office 365 Suite"
  _errors=$(echo "${_results}" | grep "Error")
  # Parse errors
  if (("$(echo "$_errors" | tail -2 | wc -l)" > 0)); then
    # Check type of error
    if echo "$_errors" | tail -2 | head -n 1 | grep -q "not enough space"; then
      # Disk space error
      echo "[Error] Not enough space to install Office 365 Suite"
      # Print the raw error message related to disk space and how much space is needed
      echo "$_errors" | tail -2 | head -n 1 | cut -d ":" -f 5 | cut -d "=" -f 5 | cut -d "," -f 1
    else
      # Other errors
      echo "[Error] Installer Errors:"
      echo "$_errors"
    fi
  fi
  cleanup
  exit 1
fi

cleanup

if [[ $_arg_forceReboot = "on" ]]; then
  echo "[Info] Sending message to user that a reboot has been initiated"
  osascript -e "display alert \"Reboot Initiated\" message \"${_reboot_message}\" with icon caution giving up after ${_reboot_message_giveup}" /dev/null 2>&1
  echo "[Info] Rebooting the device"
  shutdown -r "+${_reboot_time}" 2>&1
fi





