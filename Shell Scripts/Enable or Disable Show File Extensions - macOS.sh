# Enable or disable the visibility of File Extensions for all users (must be ran as 'System').
#!/usr/bin/env bash

# Description: Enable or disable the visibility of File Extensions for all users (must be ran as 'System').
#
# Release Notes: Initial Release
#
# Usage: [--action <Arg>] [--restartFinder] [--help|-h]
# <> are required
# [] are optional
#
# Example: Set-ExtensionVisibility.sh --action Enable
#   Enabling 'Show hidden files and folders' for all users.
#
# Example: Set-ExtensionVisibility.sh --action Enable --restartFinder
#   Enabling 'Show hidden files and folders' for all users.
#   Restarting Finder.
#
# Preset Parameter: --action "Enable"
#   Specify whether you would like to disable or enable the viewing of hidden files or folders. Valid actions are 'Enable' or 'Disable'.
#
# Preset Parameter: --restartFinder
#   You may need to restart Finder.app for the script to take effect immediately. Use this switch to do so upon completion.
#
# Preset Parameter: --help
#   Displays the help menu.

# Functions
# Print an error message and exit with a specific status code
die() {
    local _ret="${2:-1}"
    test "${_PRINT_HELP:-no}" = yes && print_help >&2
    echo "$1" >&2
    exit "${_ret}"
}

# Print the help message
print_help() {
    printf '\n\n%s\n\n' 'Usage: [-a|--action <Arg>] [-r|--restartFinder] [-h|--help]'
    printf '%s\n' 'Preset Parameter: --action "Enable"'
    printf '%s\n' 'Preset Parameter: --action "Disable"'
    printf '\t%s\n' "Specify whether you would like to disable or enable the viewing of hidden files or folders. Valid actions are 'Enable' or 'Disable'."
    printf '%s\n' 'Preset Parameter: --restartFinder'
    printf '\t%s\n' "You may need to restart Finder.app for the script to take effect immediately. Use this switch to do so upon completion."
    printf '%s\n' 'Preset Parameter: --help'
    printf '\t%s\n' "Displays the help menu."
}

# Parse the command-line arguments
parse_commandline() {
    while test $# -gt 0; do
        _key="$1"
        case "$_key" in
        -a | --action)
            test $# -lt 2 && die "Missing value for the optional argument '$_key'." 1
            _arg_action="$2"
            shift
            ;;
        --action=*)
            _arg_action="${_key##--action=}"
            ;;
        -a*)
            _arg_action="${_key##-a}"
            ;;
        --restartFinder | -r)
            _arg_restartFinder="true"
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

setExtensionVisibility() {
    user=$1
    if [[ "${_arg_action}" == "Enable" ]]; then
        if [[ $(sudo -u "$user" /usr/bin/defaults read NSGlobalDomain AppleShowAllExtensions 2>&1) == "1" ]]; then
            # If the visibility of File Extensions is already enabled, display a message indicating that it is already enabled
            echo "[Info] 'Show File Extensions' is already enabled for user '$user'."
            # If the restartFinder flag is "on", restart Finder as requested and handle any errors
            if [[ $_arg_restartFinder == "on" ]]; then
                restartFinder "$user"
            fi
        else
            # Enable the visibility of File Extensions for the user
            echo "[Info] Enabling 'Show File Extensions' for user '$user'."
            if sudo -u "$user" /usr/bin/defaults write NSGlobalDomain AppleShowAllExtensions -bool true 2>&1; then
                # If the restartFinder flag is "on", restart Finder as requested and handle any errors
                if [[ $_arg_restartFinder == "on" ]]; then
                    restartFinder "$user"
                fi
                echo "[Info] Successfully set 'Show File Extensions' to 'Enable' for user '$user'."
            else
                echo "[Error] Failed to set 'Show File Extensions' to 'Enable' for user '$user'."
            fi
        fi
    else
        if [[ $(sudo -u "$user" /usr/bin/defaults read NSGlobalDomain AppleShowAllExtensions 2>&1) == "1" ]]; then
            # Disable the visibility of File Extensions for the user
            echo "[Info] Disabling 'Show File Extensions' for user '$user'."
            if sudo -u "$user" /usr/bin/defaults write NSGlobalDomain AppleShowAllExtensions -bool false 2>&1; then
                # If the restartFinder flag is "on", restart Finder as requested and handle any errors
                if [[ $_arg_restartFinder == "on" ]]; then
                    restartFinder "$user"
                fi
                echo "[Info] Successfully set 'Show File Extensions' to 'Disable' for user '$user'."
            else
                echo "[Error] Failed to set 'Show File Extensions' to 'Disable' for user '$user'."
            fi
        else
            # If the visibility of File Extensions is already disabled, display a message indicating that it is already disabled
            echo "[Info] 'Show File Extensions' is already disabled for user '$user'."
            # If the restartFinder flag is "on", restart Finder as requested and handle any errors
            if [[ $_arg_restartFinder == "on" ]]; then
                restartFinder "$user"
            fi
        fi
    fi
}

restartFinder() {
    user=$1
    # Restart Finder for the user
    echo "[Info] Restarting Finder as requested for user '$user'."
    # Check if Finder is running for the user before restarting it
    if pgrep -u "$user" Finder 1>/dev/null 2>&1; then
        # Finder is running for the user, restart Finder
        echo "[Info] Finder is running for user '$user'."
        if pkill -u "$user" Finder 2>&1; then
            # Finder was successfully restarted
            echo "[Info] Restarted Finder for user '$user'."
        else
            # Finder failed to restart
            echo "[Warn] Failed to restart Finder for user '$user'."
        fi
    else
        # Finder is not running for the user
        echo "[Info] Finder is not running for user '$user'."
    fi
}

parse_commandline "$@"

# If script form variables are used, replace the command-line parameters with their value.
if [[ -n "${action}" ]]; then
    _arg_action="$action"
fi

if [[ -n $restartFinder && $restartFinder == "true" ]]; then
    _arg_restartFinder="on"
fi

# If $action has a value, trim any leading or trailing whitespace
if [[ -n "${_arg_action}" ]]; then
    _arg_action="$(echo -e "${_arg_action}" | xargs)"
fi

# If $action is empty or null after trimming, display an error message indicating that an action must be specified
if [[ -z "${_arg_action}" ]]; then
    die "[Error] You must specify an action (Enable or Disable)." 1
fi

# Check if the action is valid
if [[ "${_arg_action}" != "Enable" && "${_arg_action}" != "Disable" ]]; then
    die "[Error] Invalid action '${_arg_action}'. Please specify either 'Enable' or 'Disable'." 1
fi

if [[ $EUID -eq 0 ]]; then
    # Get all users with UID >= 500
    user_list=$(dscl . -list /Users UniqueID | awk '$2 > 499 {print $1}')

    # Set the visibility of File Extensions for all users
    for user in $user_list; do
        setExtensionVisibility "$user"
    done
else
    die "[Error] This script must be run as system or root." 1
fi





