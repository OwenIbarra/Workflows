# Enable or disable the viewing of hidden files and folders for all users.
#!/usr/bin/env bash
#
# Description: Enable or disable the viewing of hidden files and folders for all users.
#
# Preset Parameter: --action "ReplaceMeWithYourDesiredAction"
#		Specify whether you would like to disable or enable the viewing of hidden files or folders.
#
# Preset Parameter: --restartFinder
#		You may need to restart Finder for this script to take effect immediately.
#
# Preset Parameter: --help
#		Displays some help text.
#
# Release Notes: Initial Release

# Initialize the variables used to store the action and the Finder restart flag
_arg_action=
_arg_restartFinder="off"

# This function prints the help menu with usage information and descriptions of the parameters
print_help() {
  printf '\n\n%s\n\n' 'Usage: [--action|-a <arg>] [--restartFinder|-r] [--help|-h]'
  printf '%s\n' 'Preset Parameter: --action "ReplaceMeWithYourDesiredAction"'
  printf '\t%s\n' "Specify whether you would like to disable or enable the viewing of hidden files or folders."
  printf '%s\n' 'Preset Parameter: --restartFinder'
  printf '\t%s\n' "You may need to restart Finder for this script to take effect immediately. Check this box to do so upon completion."
  printf '%s\n' 'Preset Parameter: --help'
  printf '\t%s\n' "Displays this help menu."
}

# This function is used to handle errors and terminate the script. 
die() {
  local _ret="${2:-1}"
  echo "$1" >&2
  test "${_PRINT_HELP:-no}" = yes && print_help >&2
  exit "${_ret}"
}

# This function processes the command-line arguments passed to the script.
parse_commandline() {
  while test $# -gt 0; do
    _key="$1"
    case "$_key" in
    --Action | --action | -a)
      test $# -lt 2 && die "[Error] Missing value for the required argument '$_key'." 1
      _arg_action=$2
      shift
      ;;
    --action=*)
      _arg_action="${_key##--action=}"
      ;;
    --restartFinder | --RestartFinder | --restartfinder | -r)
      _arg_restartFinder="on"
      ;;
    --help | -h)
      _PRINT_HELP=yes die "" 0
      ;;
    *)
      _PRINT_HELP=yes die "[Error] Got an unexpected argument '$1'" 1
      ;;
    esac
    shift
  done
}

# Parse the command-line arguments
parse_commandline "$@"

# If script form variables are used, replace the command line parameters with their value.
if [[ -n $action ]]; then
  _arg_action="$action"
fi
if [[ -n $restartFinder && $restartFinder == "true" ]]; then
  _arg_restartFinder="on"
fi

# If _arg_action is not empty, trim any whitespace and convert it to lowercase
if [[ -n $_arg_action ]]; then
  _arg_action=$(echo "$_arg_action" | xargs | tr '[:upper:]' '[:lower:]')
fi

# If no valid action was provided, print an error message and exit the script
if [[ -z $_arg_action ]]; then
  _PRINT_HELP=yes die "[Error] No valid action was provided. Please specify either 'Enable' or 'Disable'." 1
fi

# Validate the action. If it is not "enable" or "disable", print an error and exit
if [[ $_arg_action != "enable" && $_arg_action != "disable" ]]; then
  _PRINT_HELP=yes die "[Error] The action '$_arg_action' is invalid. Please specify either 'Enable' or 'Disable'." 1
fi

# Based on the action, set the value for showing hidden files and folders
case "$_arg_action" in
enable)
  echo "Enabling 'Show hidden files and folders' for all users."
  _arg_showHiddenFilesValue="TRUE"
  ;;
disable)
  echo "Disabling 'Show hidden files and folders' for all users."
  _arg_showHiddenFilesValue="FALSE"
  ;;
esac

# Read the current value of the hidden file setting from the global preferences
currentHiddenFileValue=$(defaults read /Library/Preferences/.GlobalPreferences AppleShowAllFiles 2>&1)

# If the current setting matches the requested value, print a message indicating that no change is needed
if [[ "$currentHiddenFileValue" == "$_arg_showHiddenFilesValue" ]]; then
  case "$_arg_action" in
  enable)
    echo "'Show hidden files and folders' has already been enabled for all users."
    ;;
  disable)
    echo "'Show hidden files and folders' has already been disabled for all users."
    ;;
  esac
fi

# If the current setting is different from the requested value, attempt to update it
if [[ "$currentHiddenFileValue" != "$_arg_showHiddenFilesValue" ]]; then
  if ! setHiddenFileValueOutput=$(defaults write /Library/Preferences/.GlobalPreferences AppleShowAllFiles "$_arg_showHiddenFilesValue" 2>&1); then
    echo "[Error] Failed to update the hidden files or folders setting." >&2
    _PRINT_HELP=no die "[Error] $setHiddenFileValueOutput" 1
  else
    case "$_arg_action" in
    enable)
      echo "'Show hidden files and folders' has been successfully enabled for all users."
      ;;
    disable)
      echo "'Show hidden files and folders' has been successfully disabled for all users."
      ;;
    esac
  fi
fi

# If the restartFinder flag is "on", restart Finder as requested and handle any errors
if [[ $_arg_restartFinder == "on" ]]; then
  echo "Restarting Finder as requested."

  if ! restartFinderOutput=$(killall Finder 2>&1); then
    echo "[Error] Failed to restart Finder." >&2
    _PRINT_HELP=no die "[Error] $restartFinderOutput" 1
  else
    echo "Successfully restarted Finder."
  fi
fi




