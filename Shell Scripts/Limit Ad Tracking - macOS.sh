# This limits information that is sent to advertisers to be used for advertising tracking.
#!/usr/bin/env bash

#
# Description: This limits information that is sent to advertisers to be used for advertising tracking.
#
# Usage: "[Limit|Do Not Limit]"
#
# Release Notes: Initial Release
#
# Example Output (Limit):
#
# [Info] Limiting Ad Tracking
#
# Example Output (Do Not Limit):
#
# [Info] Not Limiting Ad Tracking

_arg_action=$1

# Determines whether or not help text is necessary and routes the output to stderr
die() {
    local _ret="${2:-1}"
    echo "$1" >&2
    test "${_PRINT_HELP:-no}" = yes && print_help >&2
    exit "${_ret}"
}

# Prints the help text
print_help() {
    printf "%s\n" "Description: This limits information that is sent to advertisers to be used for advertising tracking."
    printf "%s\n" "Usage: \"[Limit|Do Not Limit]\""
}

if [[ -n "${action}" ]]; then
    _arg_action="${action}"
fi

# Check if --help or -h is passed as an argument
for _arg in "$@"; do
    _optarg=""
    _long_opt=""
    case "$_arg" in
    --help)
        _PRINT_HELP="yes" die 0
        ;;
    -h)
        _PRINT_HELP="yes" die 0
        ;;
    esac
done

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    # Get a list of all users on the system
    user_list=$(dscl . -list /Users UniqueID | awk '$2 > 499 {print $1}')

    # Loop through each user and set the Ad Tracking preference
    for user in $user_list; do
        if [[ "${_arg_action}" == "Limit" ]]; then
            # Limit Ad Tracking
            echo "[Info] Limiting Ad Tracking for user: $user"
            sudo -u "$user" defaults write /Users/"$user"/Library/Preferences/com.apple.AdLib forceLimitAdTracking -bool yes
            sudo -u "$user" defaults write /Users/"$user"/Library/Preferences/com.apple.AdLib AD_DEVICE_IDFA -string '00000000-0000-0000-0000-000000000000'
        elif [[ "${_arg_action}" == "Do Not Limit" ]]; then
            # Do Not Limit Ad Tracking
            echo "[Info] Not Limiting Ad Tracking for user: $user"
            sudo -u "$user" defaults write /Users/"$user"/Library/Preferences/com.apple.Adlib forceLimitAdTracking -bool no
            sudo -u "$user" defaults write /Users/"$user"/Library/Preferences/com.apple.AdLib AD_DEVICE_IDFA -string ''
        else
            die '[Error] Invalid action. Please use "Limit" or "Do Not Limit"' 1
        fi
    done

    # New users
    if [[ "${_arg_action}" == "Limit" ]]; then
        # Limit Ad Tracking
        echo "[Info] Limiting Ad Tracking for new users"
        defaults write /Library/Preferences/com.apple.AdLib forceLimitAdTracking -bool yes
        defaults write /Library/Preferences/com.apple.AdLib AD_DEVICE_IDFA -string '00000000-0000-0000-0000-000000000000'
    elif [[ "${_arg_action}" == "Do Not Limit" ]]; then
        # Do Not Limit Ad Tracking
        echo "[Info] Not Limiting Ad Tracking for new users"
        defaults write /Library/Preferences/com.apple.Adlib forceLimitAdTracking -bool no
        defaults write /Library/Preferences/com.apple.AdLib AD_DEVICE_IDFA -string ''
    else
        die '[Error] Invalid action. Please use "Limit" or "Do Not Limit"' 1
    fi

    # Restart the adprivacyd and cfprefsd processes
    sleep 5
    killall adprivacyd 2>/dev/null
    killall -SIGHUP cfprefsd 2>/dev/null
    sleep 5
else
    if [[ "${_arg_action}" == "Limit" ]]; then
        # Limit Ad Tracking
        echo "[Info] Limiting Ad Tracking"
        defaults write com.apple.AdLib forceLimitAdTracking -bool yes
        defaults write com.apple.AdLib AD_DEVICE_IDFA -string '00000000-0000-0000-0000-000000000000'
    elif [[ "${_arg_action}" == "Do Not Limit" ]]; then
        # Do Not Limit Ad Tracking
        echo "[Info] Not Limiting Ad Tracking"
        defaults write com.apple.Adlib forceLimitAdTracking -bool no
        defaults write com.apple.AdLib AD_DEVICE_IDFA -string ''
    else
        die '[Error] Invalid action. Please use "Limit" or "Do Not Limit"' 1
    fi

    # Restart the adprivacyd and cfprefsd processes
    sleep 5
    killall adprivacyd 2>/dev/null
    killall -SIGHUP cfprefsd 2>/dev/null
    sleep 5
fi

exit 0





