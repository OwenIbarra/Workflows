# Change's the mac's hostname (what you see in the Terminal), local hostname (what the Bonjour service shows) and computername (friendly name seen in Finder). Please note the hostname will update upon the next dhcp renewal.
#!/bin/bash

# Description: Change's the mac's hostname (what you see in the Terminal), local hostname (what the Bonjour service shows) and computername (friendly name seen in Finder). Please note the hostname will update upon the next dhcp renewal.
#
# Release Notes: Initial Release
#
# Below are all the valid parameters for this script only the new computer name is required!
# Preset Parameter: "ReplaceWithNewComputerName" --hostname "name" --localhostname "name" --computername "name"
# --hostname: Sets only the HostName (The one you see in the terminal)
# --localhostname: Sets only the LocalHostName (What the Bonjour service shows)
# --computername: Sets only the user-friendly ComputerName (The one you see in Finder)

# Help text function for when invalid input is encountered
print_help() {
  printf '\n### Below are all the (case sensitive) valid parameters for this script only the new computer name is required! ###\n'
  printf '\nPreset Parameter: "ReplaceWithNewComputerName" --hostname "name" --localhostname "name" --computername "name" \n'
  printf '\t%s\n' "--hostname: Sets only the HostName (The one you see in the terminal)"
  printf '\t%s\n' "--localhostname: Sets only the LocalHostName (What the Bonjour service shows)"
  printf '\t%s\n' "--computername: Sets only the user-friendly ComputerName (The one you see in Finder)"
}

# Determines whether or not help text is necessary and routes the output to stderr
die() {
  local _ret="${2:-1}"
  echo "$1" >&2
  test "${_PRINT_HELP:-no}" = yes && print_help >&2
  exit "${_ret}"
}

# THE DEFAULTS INITIALIZATION - OPTIONALS
_arg_name=""
_arg_hostname=""
_arg_localhostname_only=""
_arg_computername_only=""
_arg_forceReboot="off"
_reboot_time="1"                                  # Minutes
_reboot_message_giveup=$((_reboot_time * 60 / 2)) # Seconds
_reboot_message="A shutdown operation has been mandated by your IT staff and will occur in $((_reboot_time * 60)) seconds."

# Grabbing the parameters and parsing through them.
parse_commandline() {
  while test $# -gt 0; do
    _key="$1"
    case "$_key" in
    --hostname=*)
      _arg_hostname="${_key##--hostname=}"
      ;;
    --hostname)
      test $# -lt 2 && die "Missing value for the optional argument '$_key'." 1
      _arg_hostname="$2"
      shift
      ;;
    --localhostname=*)
      _arg_localhostname="${_key##--localhostname=}"
      ;;
    --localhostname)
      test $# -lt 2 && die "Missing value for the optional argument '$_key'." 1
      _arg_localhostname="$2"
      shift
      ;;
    --computername=*)
      _arg_computername="${_key##--computername=}"
      ;;
    --computername)
      test $# -lt 2 && die "Missing value for the optional argument '$_key'." 1
      _arg_computername="$2"
      shift
      ;;
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

# Determines if the hostname is valid.
validate_hostname() {
  pattern=" |'"
  if [[ $1 =~ $pattern ]]; then
    echo "[Warn] Hostnames DO NOT support spaces or most special characters, but dash '-' and period '.' are okay!"
    _arg_hostname=${_arg_hostname//[^a-zA-Z0-9-.]/}
  fi

  if [[ ${#1} -gt 15 ]]; then
    echo "[Warn] Hostnames CAN NOT be longer than 15 characters. Truncating to 15 characters."
    _arg_hostname=$(echo "$1" | cut -c 1-15)
  fi
}

# Determines if the local hostname is valid.
validate_localhostname() {
  pattern=" |'"
  if [[ $1 =~ $pattern ]]; then
    echo "[Warn] Hostnames DO NOT support spaces or most special characters, but dash '-' and period '.' are okay!"
    _arg_localhostname=${_arg_localhostname//[^a-zA-Z0-9-.]/}
  fi

  if [[ ${#1} -gt 253 ]]; then
    echo "[Warn] Local Hostnames CAN NOT be longer than 253 characters. Truncating to 253 characters."
    _arg_localhostname=$(echo "$1" | cut -c 1-253)
  fi
}

# Determines if the computer name is valid.
validate_computername() {
  if [[ ${#1} -gt 63 ]]; then
    echo "[Warn] Computer Names CAN NOT be longer than 63 characters. Truncating to 63 characters."
    _arg_computername=$(echo "$1" | cut -c 1-63)
  fi
}

# Initializes parameter processing
parse_commandline "$@"

if [[ -n $name ]]; then
  _arg_name=$name
fi

# shellcheck disable=SC2154
if [[ "${hostName}" == "true" ]]; then
  _arg_hostname=$_arg_name
fi

# shellcheck disable=SC2154
if [[ "${localHostName}" == "true" ]]; then
  _arg_localhostname=$_arg_name
fi

# shellcheck disable=SC2154
if [[ "${computerName}" == "true" ]]; then
  _arg_computername=$_arg_name
fi

# Sets the force reboot flag
if [[ -n $forceReboot && "${forceReboot}" == "true" ]]; then
  _arg_forceReboot="on"
fi

# If they didn't give me at lease one name I should error out
if [[ -z $_arg_hostname && -z $_arg_localhostname && -z $_arg_computername ]]; then
  _PRINT_HELP=yes die '[Error] No checkbox was set! Please enter in a name in the "Preset Parameter" box in Ninja and use at least one checkbox!' 1
fi

# Sets the unique HostName on the network
if [[ -n "${_arg_hostname}" ]]; then
  validate_hostname "$_arg_hostname"
  echo "Changing HostName to $_arg_hostname..."
  scutil --set HostName "$_arg_hostname"
  sleep 7
  new_hostname=$(scutil --get HostName)
  if [[ $new_hostname != "$_arg_hostname" ]]; then
    _PRINT_HELP=no die "[Error] failed to set Host Name to $_arg_hostname." 1
  else
    echo "Success!"
  fi
fi

# Sets the unique HostName seen with the Bonjour service
if [[ -n "${_arg_localhostname}" ]]; then
  validate_localhostname "$_arg_localhostname"
  echo "Changing LocalHostName to $_arg_localhostname..."
  scutil --set LocalHostName "$_arg_localhostname"
  sleep 7
  new_localhostname=$(scutil --get LocalHostName)
  if [[ $new_localhostname != "$_arg_localhostname" ]]; then
    _PRINT_HELP=no die "[Error] failed to set local hostname to $_arg_localhostname." 1
  else
    echo "Success!"
  fi
fi

# Sets the user friendly name
if [[ -n "${_arg_computername}" ]]; then
  validate_computername "$_arg_computername"
  echo "Changing ComputerName to $_arg_computername..."
  scutil --set ComputerName "$_arg_computername"
  sleep 7
  new_computername=$(scutil --get ComputerName)
  if [[ $new_computername != "$_arg_computername" ]]; then
    _PRINT_HELP=no die "[Error] failed to set Computer Name to $_arg_computername." 1
  else
    echo "Success"
  fi
fi

# Flushes the dns cache so that the mac is prepared to start handing out its new name
dscacheutil -flushcache

# Warns the user that it will take some time for the new name to show up
printf "\n[Warn] The devicename in Ninja will likely display the old name until the next dhcp renewal."
printf "\n\tOSX determines its devicename\hostname from the dhcp or dns server."
printf "\n\tTypically these services will update their records upon receiving a new DHCP request from the device."

if [[ $_arg_forceReboot = "on" ]]; then
  osascript -e "display alert \"Reboot Initiated\" message \"${_reboot_message}\" with icon caution giving up after ${_reboot_message_giveup}" /dev/null 2>&1
  shutdown -r "+${_reboot_time}" 2>&1
fi




