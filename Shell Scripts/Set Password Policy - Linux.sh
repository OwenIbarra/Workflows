# Sets the password policy for linux devices.
#!/usr/bin/env bash
#
# Description: Sets the password policy for linux devices.
#
# Preset Parameter: --maxLoginAttempts "replaceMeWithANumber"
#		Define how many incorrect password attempts are allowed before the device locks.
#
# Preset Parameter: --loginAttemptLockTime "replaceMeWithANumber"
#		Set the lock duration (in minutes) after the maximum login attempts is reached. Max Login Attempts is required (if not previously set).
#
# Preset Parameter: --daysUntilPasswordExpiration "replaceMeWithANumber"
#		Specify how many days before a password expires.
#
# Preset Parameter: --minimumPasswordLength "replaceMeWithANumber"
#		Define the minimum number of characters required for a password.
#
# Preset Parameter: --passwordHistory "replaceMeWithANumber"
#		Define how many previous passwords must be remembered before reuse.
#   This option is only available on Debian-based or RHEL 8+-based distributions.
#   https://bugzilla.redhat.com/show_bug.cgi?id=1271804
#
# Preset Parameter: --help
#		Displays some help text.
#
# Minimum OS Architecture Supported: Debian 11 (Bullseye)+, Red Hat Enterprise Linux (RHEL) 8+
#
# Release Notes: Initial Release

# Initialize variables for various password policy parameters with default values
_arg_maxLoginAttempts=
_arg_loginAttemptLockTime=
_arg_daysUntilPasswordExpiration=
_arg_minimumPasswordLength=
_arg_passwordHistory=

print_help() {
  printf '\n\n%s\n\n' 'Usage: [--maxLoginAttempts|-a <arg>] [--loginAttemptLockTime|-t <arg>] [--daysUntilPasswordExpiration|-e <arg>] 
  [--minimumPasswordLength|-l <arg>] [--passwordHistory|-ph <arg>] [--help|-h]'
  printf '%s\n' 'Preset Parameter: --maxLoginAttempts "replaceMeWithANumber"'
  printf '\t%s\n' "Define how many incorrect password attempts are allowed before the device locks."
  printf '%s\n' 'Preset Parameter: --loginAttemptLockTime "replaceMeWithANumber"'
  printf '\t%s\n' "Set the lock duration (in minutes) after the maximum login attempts is reached. Max Login Attempts is required (if not previously set)."
  printf '%s\n' 'Preset Parameter: --daysUntilPasswordExpiration "replaceMeWithANumber"'
  printf '\t%s\n' "Specify how many days before a password expires."
  printf '%s\n' 'Preset Parameter: --minimumPasswordLength "replaceMeWithANumber"'
  printf '\t%s\n' "Define the minimum number of characters required for a password."
  printf '%s\n' 'Preset Parameter: --passwordHistory "replaceMeWithANumber"'
  printf '\t%s\n' "Define how many previous passwords must be remembered before reuse."
  printf '\t%s\n' "This option is only available on Debian-based or RHEL 8+-based distributions."
  printf '\t%s\n' "https://bugzilla.redhat.com/show_bug.cgi?id=1271804"
  printf '%s\n' 'Preset Parameter: --help'
  printf '\t%s\n' "Displays this help menu."
}

die() {
  local _ret="${2:-1}"
  echo "$1" >&2
  test "${_PRINT_HELP:-no}" = yes && print_help >&2
  exit "${_ret}"
}

parse_commandline() {
  while test $# -gt 0; do
    _key="$1"
    case "$_key" in
    --maxLoginAttempts | --maxloginattempts | --attempts | -a)
      test $# -lt 2 && die "[Error] Missing value for the optional argument '$_key'." 1
      _arg_maxLoginAttempts=$2
      shift
      ;;
    --maxLoginAttempts=*)
      _arg_maxLoginAttempts="${_key##--maxLoginAttempts=}"
      ;;
    --loginAttemptLockTime | --loginattemptlocktime | --locktime | -t)
      test $# -lt 2 && die "[Error] Missing value for the optional argument '$_key'." 1
      _arg_loginAttemptLockTime=$2
      shift
      ;;
    --loginAttemptLockTime=*)
      _arg_loginAttemptLockTime="${_key##--loginAttemptLockTime=}"
      ;;
    --daysUntilPasswordExpiration | --daysuntilpasswordexpiration | --expiration | -e)
      test $# -lt 2 && die "[Error] Missing value for the optional argument '$_key'." 1
      _arg_daysUntilPasswordExpiration=$2
      shift
      ;;
    --daysUntilPasswordExpiration=*)
      _arg_daysUntilPasswordExpiration="${_key##--daysUntilPasswordExpiration=}"
      ;;
    --minimumPasswordLength | --minimumpasswordlength | --length | -l)
      test $# -lt 2 && die "[Error] Missing value for the optional argument '$_key'." 1
      _arg_minimumPasswordLength=$2
      shift
      ;;
    --minimumPasswordLength=*)
      _arg_minimumPasswordLength="${_key##--minimumPasswordLength=}"
      ;;
    --passwordHistory | --passwordhistory | --history | -ph)
      test $# -lt 2 && die "[Error] Missing value for the optional argument '$_key'." 1
      _arg_passwordHistory=$2
      shift
      ;;
    --passwordHistory=*)
      _arg_passwordHistory="${_key##--passwordHistory=}"
      ;;
    --help | -h)
      _PRINT_HELP=yes die
      ;;
    *)
      _PRINT_HELP=yes die "[Error] Got an unexpected argument '$1'" 1
      ;;
    esac
    shift
  done
}

echo ""
parse_commandline "$@"

# If environment variables for the script parameters are set, override the command line argument values
if [[ -n "$maxLoginAttempts" ]]; then
  _arg_maxLoginAttempts="$maxLoginAttempts"
fi
if [[ -n "$loginAttemptLockTime" ]]; then
  _arg_loginAttemptLockTime="$loginAttemptLockTime"
fi
if [[ -n "$daysUntilPasswordExpiration" ]]; then
  _arg_daysUntilPasswordExpiration="$daysUntilPasswordExpiration"
fi
if [[ -n "$minimumPasswordLength" ]]; then
  _arg_minimumPasswordLength="$minimumPasswordLength"
fi
if [[ -n "$passwordHistory" ]]; then
  _arg_passwordHistory="$passwordHistory"
fi

# Check if the script is being run as root. If not, exit with an error message.
if [[ $(id -u) -ne 0 ]]; then
  _PRINT_HELP=no die "[Error] This script must be run with root permissions. Try running it with sudo or as the system/root user." 1
fi

# Validate max login attempts. Ensure it is a positive integer greater than zero.
if [[ -n "$_arg_maxLoginAttempts" ]]; then
  _arg_maxLoginAttempts=$(echo "$_arg_maxLoginAttempts" | xargs)

  if [[ -z "$_arg_maxLoginAttempts" ]]; then
    _PRINT_HELP=yes die "[Error] An invalid number of max login attempts was given. Please specify a positive whole number that is greater than 0." 1
  fi
fi
if [[ "$_arg_maxLoginAttempts" =~ [^0-9] ]]; then
  _PRINT_HELP=yes die "[Error] An invalid value for max login attempts was given: '$_arg_maxLoginAttempts'. Please specify a positive whole number that is greater than 0." 1
fi
if [[ "$_arg_maxLoginAttempts" == 0 ]]; then
  _PRINT_HELP=yes die "[Error] An invalid value for max login attempts was given: '$_arg_maxLoginAttempts'. Please specify a positive whole number that is greater than 0." 1
fi

# Validate login attempt lock time. Ensure it is a positive integer greater than zero.
if [[ -n "$_arg_loginAttemptLockTime" ]]; then
  _arg_loginAttemptLockTime=$(echo "$_arg_loginAttemptLockTime" | xargs)

  if [[ -z "$_arg_loginAttemptLockTime" ]]; then
    _PRINT_HELP=yes die "[Error] An invalid lock time was given. Please specify a positive whole number that is greater than 0." 1
  fi
fi
if [[ "$_arg_loginAttemptLockTime" =~ [^0-9] ]]; then
  _PRINT_HELP=yes die "[Error] An invalid value for lock time was given: '$_arg_loginAttemptLockTime'. Please specify a positive whole number that is greater than 0." 1
fi
if [[ "$_arg_loginAttemptLockTime" == 0 ]]; then
  _PRINT_HELP=yes die "[Error] An invalid value for lock time was given: '$_arg_loginAttemptLockTime'. Please specify a positive whole number that is greater than 0." 1
fi

# Validate password expiration time. Ensure it is a positive whole number or 99999 for no expiration.
if [[ -n "$_arg_daysUntilPasswordExpiration" ]]; then
  _arg_daysUntilPasswordExpiration=$(echo "$_arg_daysUntilPasswordExpiration" | xargs)

  if [[ -z "$_arg_daysUntilPasswordExpiration" ]]; then
    _PRINT_HELP=yes die "[Error] An invalid expiration time was given. Please specify a positive whole number or '99999' for no expiration." 1
  fi

  if [[ "$_arg_daysUntilPasswordExpiration" =~ [^0-9] ]]; then
    _PRINT_HELP=yes die "[Error] An invalid value for password expiration was given: '$_arg_daysUntilPasswordExpiration'. Please specify a positive whole number that is greater than 0 and less than or equal to 99999." 1
  fi

  if [[ "$_arg_daysUntilPasswordExpiration" == 0 || "$_arg_daysUntilPasswordExpiration" -gt 99999 ]]; then
    _PRINT_HELP=yes die "[Error] An invalid value for password expiration was given: '$_arg_daysUntilPasswordExpiration'. Please specify a positive whole number that is greater than 0 and less than or equal to 99999." 1
  fi
fi

# Validate minimum password length. Ensure it is a positive whole number greater than or equal to 8.
if [[ -n "$_arg_minimumPasswordLength" ]]; then
  _arg_minimumPasswordLength=$(echo "$_arg_minimumPasswordLength" | xargs)

  if [[ -z "$_arg_minimumPasswordLength" ]]; then
    _PRINT_HELP=yes die "[Error] An invalid minimum password length was given. Please specify a positive whole number that is greater than or equal to '8'." 1
  fi
fi
if [[ "$_arg_minimumPasswordLength" =~ [^0-9] ]]; then
  _PRINT_HELP=yes die "[Error] An invalid value for minimum password length was given: '$_arg_minimumPasswordLength'. Please specify a positive whole number that is greater than or equal to 8." 1
fi
if [[ -n "$_arg_minimumPasswordLength" && "$_arg_minimumPasswordLength" -lt 8 ]]; then
  _PRINT_HELP=yes die "[Error] An invalid value for minimum password length was given: '$_arg_minimumPasswordLength'. Please specify a positive whole number that is greater than or equal to 8." 1
fi

# Validate password history setting. Ensure it is a positive whole number greater than zero.
if [[ -n "$_arg_passwordHistory" ]]; then
  _arg_passwordHistory=$(echo "$_arg_passwordHistory" | xargs)

  if [[ -z "$_arg_passwordHistory" ]]; then
    _PRINT_HELP=yes die "[Error] An invalid number of passwords to remember was given. Please specify a positive whole number that is greater than 0." 1
  fi
fi
if [[ "$_arg_passwordHistory" =~ [^0-9] ]]; then
  _PRINT_HELP=yes die "[Error] An invalid value for the number of passwords to remember was given: '$_arg_passwordHistory'. Please specify a positive whole number that is greater than 0." 1
fi
if [[ "$_arg_passwordHistory" == 0 ]]; then
  _PRINT_HELP=yes die "[Error] An invalid value for the number of passwords to remember was given: '$_arg_passwordHistory'. Please specify a positive whole number that is greater than 0." 1
fi

today=$(date "+%s")

# Ensure that at least one password policy is being set. If none are provided and the reset flag is off, throw an error.
if [[ -z "$_arg_maxLoginAttempts" && -z "$_arg_loginAttemptLockTime" && -z "$_arg_daysUntilPasswordExpiration" && -z "$_arg_minimumPasswordLength" && -z "$_arg_passwordHistory" ]]; then
  _PRINT_HELP=yes die "[Error] You must specify the password policy you are trying to set." 1
fi

# Check if authselect and authconfig commands are available
authselectAvailable=$(command -v authselect)
authconfigAvailable=$(command -v authconfig)

# Proceed only if authconfig is available but authselect is not
if [[ -n "$authconfigAvailable" && -z "$authselectAvailable" ]]; then
  echo "Detected the command authconfig. Setting the password policy using authconfig."

  # If maximum login attempts or login attempt lock time arguments are provided
  if [[ -n "$_arg_maxLoginAttempts" || -n "$_arg_loginAttemptLockTime" ]]; then
    echo ""
    echo "Checking the current status of the login attempt lock and lock time."

    # Check current status of faillock settings
    failLockStatus=$(authconfig --test | grep "pam_faillock" | grep -v "disabled")

    # Extract current maximum login attempts and lock time values
    currentAttempts=$(authconfig --test | grep "pam_faillock" | grep -o -e "deny[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*" | xargs)
    currentLockTime=$(authconfig --test | grep "pam_faillock" | grep -o -e "unlock_time[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*" | xargs)

    # Convert lock time from seconds to minutes if available
    if [[ -n "$currentLockTime" ]]; then
      currentLockTimeMinutes=$((currentLockTime / 60))
    fi

    # If login attempt lock time is provided, convert to seconds
    if [[ -n "$_arg_loginAttemptLockTime" ]]; then
      loginAttemptLockTimeMinutes="$_arg_loginAttemptLockTime"
      _arg_loginAttemptLockTime=$((_arg_loginAttemptLockTime * 60))
    fi

    echo "Successfully retrieved the current lock status and lock time."

    # If faillock module is not enabled, enable it
    if [[ -z "$failLockStatus" ]]; then
      echo "Enabling faillock PAM module."
      if ! authconfig --enablefaillock --update; then
        _PRINT_HELP=no die "[Error] Failed to enable faillock. This is required to set the max login attempts allowed as well as the lock time." 1
      fi

      # Verify that faillock has been enabled successfully
      failLockStatus=$(authconfig --test | grep "pam_faillock" | grep -v "disabled")
      if [[ -z "$failLockStatus" ]]; then
        _PRINT_HELP=no die "[Error] Failed to enable faillock. This is required to set the max login attempts allowed as well as the lock time." 1
      fi
    fi

    # Check if max login attempts value is already set correctly
    if [[ -n "$_arg_maxLoginAttempts" && -n "$currentAttempts" && "$_arg_maxLoginAttempts" == "$currentAttempts" ]]; then
      echo "The maximum login attempts is already set to '$_arg_maxLoginAttempts'. Skipping."
      _arg_maxLoginAttempts=
    fi

    # Check if lock time value is already set correctly
    if [[ -n "$_arg_loginAttemptLockTime" && -n "$currentLockTime" && "$_arg_loginAttemptLockTime" == "$currentLockTime" ]]; then
      echo "The lock time is already set to '$loginAttemptLockTimeMinutes' minutes. Skipping."
      _arg_loginAttemptLockTime=
    fi
  fi

  # Exit with error if only max login attempts or lock time is provided without the other
  if [[ -n "$_arg_maxLoginAttempts" && -z "$_arg_loginAttemptLockTime" && -z "$currentLockTime" ]]; then
    _PRINT_HELP=yes die "[Error] When specifying the maximum number of login attempts, you must also specify the login attempt lock time." 1
  fi

  if [[ -n "$_arg_loginAttemptLockTime" && -z "$_arg_maxLoginAttempts" && -z "$currentAttempts" ]]; then
    _PRINT_HELP=yes die "[Error] When specifying a login attempt lock time you must also specify the maximum login attempts." 1
  fi

  # If both maximum login attempts and lock time arguments are provided, update authconfig policy
  if [[ -n "$_arg_maxLoginAttempts" && -n "$_arg_loginAttemptLockTime" ]]; then
    echo "Setting the maximum login attempts and lock time in the authconfig policy."

    # Update authconfig with max login attempts and lock time
    if ! authconfig --faillockargs="deny=$_arg_maxLoginAttempts unlock_time=$_arg_loginAttemptLockTime" --update; then
      _PRINT_HELP=no die "[Error] Failed to set the maximum login attempts and lock time in the authconfig policy." 1
    fi

    # Verify the updated values
    newAttempts=$(authconfig --test | grep "pam_faillock" | grep -o -e "deny[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*" | xargs)
    newLockTime=$(authconfig --test | grep "pam_faillock" | grep -o -e "unlock_time[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*" | xargs)

    if [[ -n "$newAttempts" && "$newAttempts" == "$_arg_maxLoginAttempts" ]]; then
      echo "Successfully added the max login attempts to the authconfig policy."
    else
      _PRINT_HELP=no die "[Error] Failed to add the max login attempts to the authconfig policy." 1
    fi

    if [[ -n "$newLockTime" && "$newLockTime" == "$_arg_loginAttemptLockTime" ]]; then
      echo "Successfully set the lock time in the authconfig policy."
    else
      _PRINT_HELP=no die "[Error] Failed to set the lock time in the authconfig policy." 1
    fi
  fi

  # Update only maximum login attempts if lock time is not provided
  if [[ -n "$_arg_maxLoginAttempts" && -z "$_arg_loginAttemptLockTime" ]]; then
    echo "Modifying the maximum login attempts from '$currentAttempts' to '$_arg_maxLoginAttempts' in the authconfig policy."

    # Update max login attempts in authconfig
    if ! authconfig --faillockargs="deny=$_arg_maxLoginAttempts unlock_time=$currentLockTime" --update; then
      _PRINT_HELP=no die "[Error] Failed to modify the max login attempts in the authconfig policy." 1
    fi

    # Verify the new maximum login attempts value
    newAttempts=$(authconfig --test | grep "pam_faillock" | grep -o -e "deny[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*" | xargs)

    if [[ -n "$newAttempts" && "$newAttempts" == "$_arg_maxLoginAttempts" ]]; then
      echo "Successfully modified the max login attempts in the authconfig policy."
    else
      _PRINT_HELP=no die "[Error] Failed to modify the max login attempts in the authconfig policy." 1
    fi
  fi

  # Update only lock time if max login attempts is not provided
  if [[ -n "$_arg_loginAttemptLockTime" && -z "$_arg_maxLoginAttempts" ]]; then
    echo "Modifying the current lock time from '$currentLockTimeMinutes' minutes to '$loginAttemptLockTimeMinutes' minutes in the authconfig policy."

    # Update lock time in authconfig
    if ! authconfig --faillockargs="deny=$currentAttempts unlock_time=$_arg_loginAttemptLockTime" --update; then
      _PRINT_HELP=no die "[Error] Failed to modify the lock time in the authconfig policy." 1
    fi

    # Verify the new lock time value
    newLockTime=$(authconfig --test | grep "pam_faillock" | grep -o -e "unlock_time[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*" | xargs)

    if [[ -n "$newLockTime" && "$newLockTime" == "$_arg_loginAttemptLockTime" ]]; then
      echo "Successfully modified the lock time of the authconfig policy."
    else
      _PRINT_HELP=no die "[Error] Failed to set the lock time in the authconfig policy." 1
    fi
  fi

  # If minimum password length is specified, retrieve and update the policy
  if [[ -n "$_arg_minimumPasswordLength" ]]; then
    echo ""
    echo "Retrieving the current password quality policy."

    # Check if the password quality configuration file exists
    if [[ ! -f "/etc/security/pwquality.conf" ]]; then
      _PRINT_HELP=no die "[Error] The file '/etc/security/pwquality.conf' does not exist. Unable to read the current password quality policy." 1
    fi

    # Get the current minimum password length value
    currentMinimumLength=$(grep -v "^#" /etc/security/pwquality.conf | grep -v '^\s*$' | grep -o -e "minlen[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*" | xargs)
    echo "Successfully retrieved the current password quality policy."

    # If the minimum password length is already set correctly, skip the update
    if [[ -n "$currentMinimumLength" && "$currentMinimumLength" == "$_arg_minimumPasswordLength" ]]; then
      echo "The minimum password length is already '$_arg_minimumPasswordLength'. Skipping."
      _arg_minimumPasswordLength=
    fi
  fi

  # Set or update the minimum password length in the policy
  if [[ -n "$_arg_minimumPasswordLength" ]]; then
    if [[ -n "$currentMinimumLength" ]]; then
      echo "Updating the minimum password length from '$currentMinimumLength' to '$_arg_minimumPasswordLength'."
    else
      echo "Setting the minimum password length to '$_arg_minimumPasswordLength'."
    fi

    # Update the password quality policy with the new minimum length
    if ! authconfig --passminlen="$_arg_minimumPasswordLength" --update; then
      _PRINT_HELP=no die "[Error] Failed to modify the password length in the authconfig policy." 1
    fi

    # Verify the updated minimum password length value
    newMinimumLength=$(grep -v "^#" /etc/security/pwquality.conf | grep -v '^\s*$' | grep -o -e "minlen[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*" | xargs)
    if [[ -n "$newMinimumLength" && "$newMinimumLength" == "$_arg_minimumPasswordLength" ]]; then
      echo "Successfully set the minimum password length."
    else
      _PRINT_HELP=no die "[Error] Failed to modify the minimum password length in '/etc/security/pwquality.conf'." 1
    fi
  fi
fi

# Check if authselect is available
if [[ -n "$authselectAvailable" ]]; then
  echo "The command authselect was detected. Setting the password policy using authselect."

  # Check if max login attempts or lock time arguments are provided
  if [[ -n "$_arg_maxLoginAttempts" || -n "$_arg_loginAttemptLockTime" ]]; then
    echo ""
    echo "Checking the current status of the login attempt lock and lock time."

    # Check if the faillock module is enabled in authselect
    failLockStatus=$(authselect current | grep "with-faillock")

    # Exit if faillock.conf file does not exist
    if [[ ! -f "/etc/security/faillock.conf" ]]; then
      _PRINT_HELP=no die "[Error] The file '/etc/security/faillock.conf' does not exist. Unable to read the current faillock policy." 1
    fi

    # Retrieve current maximum login attempts and lock time from faillock.conf
    currentAttempts=$(grep -v "^#" /etc/security/faillock.conf | grep -v '^\s*$' | grep -o -e "deny[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")
    currentLockTime=$(grep -v "^#" /etc/security/faillock.conf | grep -v '^\s*$' | grep -o -e "unlock_time[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")

    # Convert lock time to minutes if it exists
    if [[ -n "$currentLockTime" ]]; then
      currentLockTimeMinutes=$((currentLockTime / 60))
    fi

    # Convert provided lock time to seconds for internal use
    if [[ -n "$_arg_loginAttemptLockTime" ]]; then
      loginAttemptLockTimeMinutes="$_arg_loginAttemptLockTime"
      _arg_loginAttemptLockTime=$((_arg_loginAttemptLockTime * 60))
    fi

    echo "Successfully retrieved the current lock status and lock time."

    # Enable faillock if not currently enabled
    if [[ -z "$failLockStatus" ]]; then
      echo "Enabling faillock PAM module."
      if ! authselect enable-feature with-faillock; then
        _PRINT_HELP=no die "[Error] Failed to enable faillock. This is required to set the max login attempts allowed as well as the lock time." 1
      fi

      if ! authselect apply-changes; then
        _PRINT_HELP=no die "[Error] Failed to enable faillock. This is required to set the max login attempts allowed as well as the lock time." 1
      fi

      # Confirm if faillock has been enabled successfully
      failLockStatus=$(authselect current | grep "with-faillock")
      if [[ -z "$failLockStatus" ]]; then
        _PRINT_HELP=no die "[Error] Failed to enable faillock. This is required to set the max login attempts allowed as well as the lock time." 1
      fi
    fi

    # Skip updating if max login attempts or lock time are already set to the desired values
    if [[ -n "$_arg_maxLoginAttempts" && -n "$currentAttempts" && "$_arg_maxLoginAttempts" == "$currentAttempts" ]]; then
      echo "The maximum login attempts is already set to '$_arg_maxLoginAttempts'. Skipping."
      _arg_maxLoginAttempts=
    fi

    if [[ -n "$_arg_loginAttemptLockTime" && -n "$currentLockTime" && "$_arg_loginAttemptLockTime" == "$currentLockTime" ]]; then
      echo "The lock time is already set to '$loginAttemptLockTimeMinutes' minutes. Skipping."
      _arg_loginAttemptLockTime=
    fi
  fi

  # Exit with error if only max login attempts or lock time is provided without the other
  if [[ -n "$_arg_maxLoginAttempts" && -z "$_arg_loginAttemptLockTime" && -z "$currentLockTime" ]]; then
    _PRINT_HELP=yes die "[Error] When specifying the maximum number of login attempts, you must also specify the login attempt lock time." 1
  fi

  if [[ -n "$_arg_loginAttemptLockTime" && -z "$_arg_maxLoginAttempts" && -z "$currentAttempts" ]]; then
    _PRINT_HELP=yes die "[Error] When specifying a login attempt lock time you must also specify the maximum login attempts." 1
  fi

  # Backup faillock.conf if changes are to be made
  if [[ -n "$_arg_maxLoginAttempts" || -n "$_arg_loginAttemptLockTime" ]]; then
    faillockBackup="/etc/security/$today-faillock.conf.backup"
    echo "Backing up '/etc/security/faillock.conf' to '$faillockBackup'"

    # Exit if backup file already exists to avoid overwriting
    if [[ -f "$faillockBackup" ]]; then
      _PRINT_HELP=no die "[Error] The backup file '$faillockBackup' already exists. Unable to backup faillock policy." 1
    fi

    # Attempt to create backup of faillock.conf, exit if it fails
    if ! cp /etc/security/faillock.conf "$faillockBackup"; then
      _PRINT_HELP=no die "[Error] Unable to backup faillock policy. Failed to save file to '$faillockBackup'" 1
    fi

    # Confirm if the backup was successful
    if [[ -f "$faillockBackup" ]]; then
      echo "Backup created successfully."
    else
      _PRINT_HELP=no die "[Error] Unable to backup faillock. Failed to save the file to '$faillockBackup'" 1
    fi
  fi

  # Configure maximum login attempts and lock time in faillock policy if they are not set already
  if [[ -n "$_arg_maxLoginAttempts" && -n "$_arg_loginAttemptLockTime" && -z "$currentAttempts" && -z "$currentLockTime" ]]; then
    echo "Configuring the maximum login attempts and lock time in the faillock policy."

    # Define the new faillock policy values
    faillockPolicy="silent
deny = $_arg_maxLoginAttempts
unlock_time = $_arg_loginAttemptLockTime"

    # Append new policy to faillock.conf, exit if it fails
    if ! echo "$faillockPolicy" >>"/etc/security/faillock.conf"; then
      _PRINT_HELP=no die "[Error] Failed to configure the maximum login attempts and lock time in the faillock policy." 1
    fi

    # Confirm if the values were correctly set in faillock.conf
    newAttempts=$(grep -v "^#" /etc/security/faillock.conf | grep -v '^\s*$' | grep -o -e "deny[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")
    newLockTime=$(grep -v "^#" /etc/security/faillock.conf | grep -v '^\s*$' | grep -o -e "unlock_time[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")

    # Verify if new max login attempts were set correctly
    if [[ -n "$newAttempts" && "$newAttempts" == "$_arg_maxLoginAttempts" ]]; then
      echo "Successfully set the maximum login attempts in the faillock policy."
    else
      _PRINT_HELP=no die "[Error] Unable to configure the maximum login attempts in the faillock policy." 1
    fi

    if [[ -n "$newLockTime" && "$newLockTime" == "$_arg_loginAttemptLockTime" ]]; then
      echo "Successfully added the lock time to the faillock policy."
    else
      _PRINT_HELP=no die "[Error] Failed to add the lock time to the faillock policy." 1
    fi
  fi

  # Update max login attempts in faillock.conf if the current attempts differ from desired setting
  if [[ -n "$_arg_maxLoginAttempts" && -n "$currentAttempts" ]]; then
    echo "Updating the current maximum login attempts from '$currentAttempts' to '$_arg_maxLoginAttempts' in the faillock policy."

    # Update deny value in faillock.conf using sed, exit if it fails
    if ! sed -i "s/^[^#]*deny[[:space:]]*=[[:space:]]*[0-9]*/deny = $_arg_maxLoginAttempts/g" "/etc/security/faillock.conf"; then
      _PRINT_HELP=no die "[Error] Failed to modify the max login attempts in the faillock policy." 1
    fi

    # Confirm if the updated max login attempts value was set correctly
    newAttempts=$(grep -v "^#" /etc/security/faillock.conf | grep -v '^\s*$' | grep -o -e "deny[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")
    if [[ -n "$newAttempts" && "$newAttempts" == "$_arg_maxLoginAttempts" ]]; then
      echo "Successfully updated the maximum login attempts in the faillock policy."
    else
      _PRINT_HELP=no die "[Error] Failed to modify the max login attempts in the faillock policy." 1
    fi
  fi

  # Check if a new lock time argument is provided and differs from the current setting
  if [[ -n "$_arg_loginAttemptLockTime" && -n "$currentLockTime" ]]; then
    echo "Updating the lock time from '$currentLockTimeMinutes' minutes to '$loginAttemptLockTimeMinutes' minutes in the faillock policy."

    # Modify the unlock_time value in faillock.conf, exiting with error if the operation fails
    if ! sed -i "s/^[^#]*unlock_time[[:space:]]*=[[:space:]]*[0-9]*/unlock_time = $_arg_loginAttemptLockTime/g" "/etc/security/faillock.conf"; then
      _PRINT_HELP=no die "[Error] Failed to modify the lock time in the faillock policy." 1
    fi

    # Retrieve and verify the updated lock time from faillock.conf
    newLockTime=$(grep -v "^#" /etc/security/faillock.conf | grep -v '^\s*$' | grep -o -e "unlock_time[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")
    if [[ -n "$newLockTime" && "$newLockTime" == "$_arg_loginAttemptLockTime" ]]; then
      echo "Successfully modified the lock time in the faillock policy."
    else
      _PRINT_HELP=no die "[Error] Failed to modify the lock time in the faillock policy." 1
    fi
  fi

  # Check if a minimum password length argument is provided
  if [[ -n "$_arg_minimumPasswordLength" ]]; then
    echo ""
    echo "Retrieving the current password quality policy."

    # Exit with error if pwquality.conf does not exist
    if [[ ! -f "/etc/security/pwquality.conf" ]]; then
      _PRINT_HELP=no die "[Error] The file '/etc/security/pwquality.conf' does not exist. Unable to read the current password quality policy." 1
    fi

    # Retrieve the current minimum password length setting from pwquality.conf
    currentMinimumLength=$(grep -v "^#" /etc/security/pwquality.conf | grep -v '^\s*$' | grep -o -e "minlen[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")
    echo "Successfully retrieved the current password quality policy."

    # Skip updating if the current minimum length matches the desired setting
    if [[ -n "$currentMinimumLength" && "$currentMinimumLength" == "$_arg_minimumPasswordLength" ]]; then
      echo "The minimum password length is already '$_arg_minimumPasswordLength'. Skipping."
      _arg_minimumPasswordLength=
    fi
  fi

  # Back up pwquality.conf if changes are to be made
  if [[ -n "$_arg_minimumPasswordLength" ]]; then
    passwordQualityBackup="/etc/security/$today-pwquality.conf.backup"
    echo "Backing up '/etc/security/pwquality.conf' to '$passwordQualityBackup'"

    # Exit if backup file already exists to prevent overwriting
    if [[ -f "$passwordQualityBackup" ]]; then
      _PRINT_HELP=no die "[Error] The backup file '$passwordQualityBackup' already exists. Unable to backup password quality policy." 1
    fi

    # Attempt to create the backup, exiting if it fails
    if ! cp "/etc/security/pwquality.conf" "$passwordQualityBackup"; then
      _PRINT_HELP=no die "[Error] Failed to back up the password quality policy to '$passwordQualityBackup'." 1
    fi

    # Confirm if the backup was successful
    if [[ -f "$passwordQualityBackup" ]]; then
      echo "Backup created successfully."
    else
      _PRINT_HELP=no die "[Error] Failed to back up the password quality policy to '$passwordQualityBackup'." 1
    fi
  fi

  # Set minimum password length if no current setting exists
  if [[ -n "$_arg_minimumPasswordLength" && -z "$currentMinimumLength" ]]; then
    echo "Setting the minimum password length to '$_arg_minimumPasswordLength'."

    # Append new minlen value to pwquality.conf, exiting with error if the operation fails
    if ! echo "minlen = $_arg_minimumPasswordLength" >>"/etc/security/pwquality.conf"; then
      _PRINT_HELP=no die "[Error] Unable to set the minimum password length in '/etc/security/pwquality.conf'." 1
    fi

    # Confirm the updated minimum password length value
    newMinimumLength=$(grep -v "^#" /etc/security/pwquality.conf | grep -v '^\s*$' | grep -o -e "minlen[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")
    if [[ -n "$newMinimumLength" && "$newMinimumLength" == "$_arg_minimumPasswordLength" ]]; then
      echo "Successfully set the minimum password length."
    else
      _PRINT_HELP=no die "[Error] Unable to set the minimum password length in '/etc/security/pwquality.conf'." 1
    fi
  fi

  # Update the minimum password length if a current setting already exists
  if [[ -n "$_arg_minimumPasswordLength" && -n "$currentMinimumLength" ]]; then
    echo "Updating the minimum password length from '$currentMinimumLength' to '$_arg_minimumPasswordLength'."

    # Modify minlen value in pwquality.conf using sed, exit if the operation fails
    if ! sed -i "s/^[^#]*minlen[[:space:]]*=[[:space:]]*[0-9]*/minlen = $_arg_minimumPasswordLength/g" "/etc/security/pwquality.conf"; then
      _PRINT_HELP=no die "[Error] Failed to update the password length policy." 1
    fi

    # Verify if the update was successful
    newMinimumLength=$(grep -v "^#" /etc/security/pwquality.conf | grep -v '^\s*$' | grep -o -e "minlen[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")
    if [[ -n "$newMinimumLength" && "$newMinimumLength" == "$_arg_minimumPasswordLength" ]]; then
      echo "Successfully updated the minimum password length."
    else
      _PRINT_HELP=no die "[Error] Failed to update the minimum password length in '/etc/security/pwquality.conf'." 1
    fi
  fi

  # Check if a password history argument is provided
  if [[ -n "$_arg_passwordHistory" ]]; then
    echo ""
    echo "Retrieving the current password history policy."

    # Exit with error if pwhistory.conf does not exist
    if [[ ! -f "/etc/security/pwhistory.conf" ]]; then
      errorMessage="[Error] The file '/etc/security/pwhistory.conf' does not exist.
[Error] This system may not support changing the password history.
[Error] https://bugzilla.redhat.com/show_bug.cgi?id=2063379
[Error] Unable to read the current password history policy.
"
      _PRINT_HELP=no die "$errorMessage" 1
    fi

    # Retrieve current password history setting from pwhistory.conf
    currentPasswordHistory=$(grep -v "^#" /etc/security/pwhistory.conf | grep -v '^\s*$' | grep -o -e "remember[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")
    echo "Successfully retrieved the current password history policy."

    # Skip updating if current password history matches desired setting
    if [[ -n "$currentPasswordHistory" && "$currentPasswordHistory" == "$_arg_passwordHistory" ]]; then
      echo "The minimum password history is already set to remember the past '$_arg_passwordHistory' passwords. Skipping."
      _arg_passwordHistory=
    fi
  fi

  # Back up pwhistory.conf if changes are to be made
  if [[ -n "$_arg_passwordHistory" ]]; then
    passwordHistoryBackup="/etc/security/$today-pwhistory.conf.backup"
    echo "Backing up '/etc/security/pwhistory.conf' to '$passwordHistoryBackup'"

    # Exit if backup file already exists
    if [[ -f "$passwordHistoryBackup" ]]; then
      _PRINT_HELP=no die "[Error] The backup file '$passwordHistoryBackup' already exists. Unable to backup the password history policy." 1
    fi

    # Attempt to create backup, exiting if it fails
    if ! cp "/etc/security/pwhistory.conf" "$passwordHistoryBackup"; then
      _PRINT_HELP=no die "[Error] Failed to back up the password history policy to '$passwordHistoryBackup'." 1
    fi

    # Confirm if the backup was successful
    if [[ -f "$passwordHistoryBackup" ]]; then
      echo "Backup created successfully."
    else
      _PRINT_HELP=no die "[Error] Failed to back up the password history policy to '$passwordHistoryBackup'." 1
    fi
  fi

  # Set password history requirement if no current setting exists
  if [[ -n "$_arg_passwordHistory" && -z "$currentPasswordHistory" ]]; then
    echo "Setting the password history requirement."

    # Append remember value to pwhistory.conf, exit if operation fails
    if ! echo "remember = $_arg_passwordHistory" >>"/etc/security/pwhistory.conf"; then
      _PRINT_HELP=no die "[Error] Failed to configure the password history requirement in '/etc/security/pwhistory.conf'." 1
    fi

    # Verify if the password history setting was added successfully
    newPasswordHistory=$(grep -v "^#" /etc/security/pwhistory.conf | grep -v '^\s*$' | grep -o -e "remember[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")
    if [[ -n "$newPasswordHistory" && "$newPasswordHistory" == "$_arg_passwordHistory" ]]; then
      echo "Successfully set the password history requirement."
    else
      _PRINT_HELP=no die "[Error] Failed to set the password history requirement in the file '/etc/security/pwhistory.conf'." 1
    fi
  fi

  # Update password history requirement if current setting already exists
  if [[ -n "$_arg_passwordHistory" && -n "$currentPasswordHistory" ]]; then
    echo "Updating the password history requirement from remembering the last '$currentPasswordHistory' passwords to the last '$_arg_passwordHistory' passwords."

    # Modify remember value in pwhistory.conf, exit if operation fails
    if ! sed -i "s/^[^#]*remember[[:space:]]*=[[:space:]]*[0-9]*/remember = $_arg_passwordHistory/g" "/etc/security/pwhistory.conf"; then
      _PRINT_HELP=no die "[Error] Failed to update the password history policy." 1
    fi

    # Verify if the update was successful
    newPasswordHistory=$(grep -v "^#" /etc/security/pwhistory.conf | grep -v '^\s*$' | grep -o -e "remember[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")
    if [[ -n "$newPasswordHistory" && "$newPasswordHistory" == "$_arg_passwordHistory" ]]; then
      echo "Successfully updated the password history requirement."
    else
      _PRINT_HELP=no die "[Error] Failed to update the password history requirement in the file '/etc/security/pwhistory.conf'." 1
    fi
  fi
fi

# Check if a days until password expiration argument is provided
if [[ -n "$_arg_daysUntilPasswordExpiration" ]]; then
  echo ""
  echo "Retrieving the current password expiration policy."

  # Exit with error if login.defs file does not exist
  if [[ ! -f "/etc/login.defs" ]]; then
    _PRINT_HELP=no die "[Error] The file '/etc/login.defs' does not exist. Unable to read the current password expiration policy." 1
  fi

  # Exit with error if login.defs file is empty
  if [[ ! -s "/etc/login.defs" ]]; then
    _PRINT_HELP=no die "[Error] The file '/etc/login.defs' is empty. Unable to read the current password expiration policy." 1
  fi

  # Retrieve current maximum password age setting from login.defs
  currentMaxAge=$(grep "^PASS_MAX_DAYS" "/etc/login.defs" | grep -o -e "[0-9]*")

  echo "Successfully retrieved the current password expiration policy."

  # Skip updating if current max age matches desired setting
  if [[ -n "$currentMaxAge" && "$currentMaxAge" == "$_arg_daysUntilPasswordExpiration" ]]; then
    echo "The current password expiration policy is already set to a maximum of '$_arg_daysUntilPasswordExpiration' days. Skipping."
    skipMaxAge="on"
  fi
fi

# Back up login.defs if changes to password expiration are needed
if [[ -n "$_arg_daysUntilPasswordExpiration" && "$skipMaxAge" != "on" ]]; then
  loginDefsBackup="/etc/$today-login.defs.backup"
  echo "Backing up '/etc/login.defs' to '$loginDefsBackup'"

  # Exit if backup file already exists to prevent overwriting
  if [[ -f "$loginDefsBackup" ]]; then
    _PRINT_HELP=no die "[Error] The backup file '$loginDefsBackup' already exists. Unable to backup login.defs." 1
  fi

  # Attempt to create backup, exiting if it fails
  if ! cp /etc/login.defs "$loginDefsBackup"; then
    _PRINT_HELP=no die "[Error] Unable to backup login.defs. Failed to save file to '$loginDefsBackup'" 1
  fi

  # Confirm if the backup was successful
  if [[ -f "$loginDefsBackup" ]]; then
    echo "Backup created successfully."
  else
    _PRINT_HELP=no die "[Error] Unable to backup login.defs. Failed to save file to '$loginDefsBackup'" 1
  fi
fi

# Set maximum password age if there is no existing setting
if [[ -n "$_arg_daysUntilPasswordExpiration" && -z "$currentMaxAge" && "$skipMaxAge" != "on" ]]; then
  echo "Configuring the maximum password age in '/etc/login.defs'."

  # Append new PASS_MAX_DAYS value to login.defs, exiting if the operation fails
  if ! echo "PASS_MAX_DAYS   $_arg_daysUntilPasswordExpiration" >>"/etc/login.defs"; then
    _PRINT_HELP=no die "[Error] Failed to configure the password expiration policy in '/etc/login.defs'." 1
  fi

  # Verify if the maximum age setting was added successfully
  newMaxAge=$(grep "^PASS_MAX_DAYS" "/etc/login.defs" | grep -o -e "[0-9]*")
  if [[ -n "$newMaxAge" && "$newMaxAge" == "$_arg_daysUntilPasswordExpiration" ]]; then
    echo "Successfully added a password expiration of '$_arg_daysUntilPasswordExpiration' days for new users."
  else
    _PRINT_HELP=no die "[Error] Failed to configure the password expiration policy in '/etc/login.defs'." 1
  fi
fi

# Update existing maximum password age if a current setting is already present
if [[ -n "$_arg_daysUntilPasswordExpiration" && -n "$currentMaxAge" && "$skipMaxAge" != "on" ]]; then
  echo "Updating the maximum password age from '$currentMaxAge' to '$_arg_daysUntilPasswordExpiration'."

  # Modify PASS_MAX_DAYS value in login.defs using sed, exiting if the operation fails
  if ! sed -i "s/^PASS_MAX_DAYS[[:space:]]*[0-9]*/PASS_MAX_DAYS   $_arg_daysUntilPasswordExpiration/g" "/etc/login.defs"; then
    _PRINT_HELP=no die "[Error] Failed to set the maximum password age in '/etc/login.defs'." 1
  fi

  # Confirm the update was successful
  newMaxAge=$(grep "^PASS_MAX_DAYS" "/etc/login.defs" | grep -o -e "[0-9]*")
  if [[ -n "$newMaxAge" && "$newMaxAge" == "$_arg_daysUntilPasswordExpiration" ]]; then
    echo "Successfully modified the maximum password age for new users."
  else
    _PRINT_HELP=no die "[Error] Failed to configure the password expiration policy in '/etc/login.defs'." 1
  fi
fi

# Apply password expiration policy to existing accounts if a days until expiration argument is provided
if [[ -n "$_arg_daysUntilPasswordExpiration" ]]; then
  echo "Retrieving list of existing accounts."

  # Retrieve user information, exiting if the operation fails
  if ! allUsers=$(cut -f 1,3 -d ':' "/etc/passwd"); then
    _PRINT_HELP=no die "[Error] Failed to retrieve existing users from '/etc/passwd'." 1
  fi

  # Retrieve minimum and maximum user IDs from login.defs, exiting if retrieval fails
  if ! minId=$(grep "^UID_MIN" "/etc/login.defs" | grep -o -e "[0-9]*"); then
    _PRINT_HELP=no die "[Error] Failed to find the minimum user ID in '/etc/login.defs'." 1
  fi

  if ! maxId=$(grep "^UID_MAX" "/etc/login.defs" | grep -o -e "[0-9]*"); then
    _PRINT_HELP=no die "[Error] Failed to find the minimum user ID in '/etc/login.defs'." 1
  fi

  # Ensure both minimum and maximum IDs were found, otherwise exit with error
  if [[ -z "$minId" || -z "$maxId" ]]; then
    _PRINT_HELP=no die "[Error] Failed to find the minimum or maximum user ID in '/etc/login.defs'." 1
  fi

  echo "Setting the maximum password age for existing accounts."

  # Loop through each user to apply the expiration policy if the user ID is within the range
  for user in $allUsers; do
    uid=$(echo "$user" | cut -f 2 -d ":")

    # Check if the user ID is within the defined range
    if [[ "$uid" -ge "$minId" && "$uid" -le "$maxId" ]]; then
      usernameToModify=$(echo "$user" | cut -f 1 -d ":")
      currentMaxAge=$(chage -l "$usernameToModify" | grep Max | grep -o -e "[0-9]*" | xargs)

      # Skip updating if the user's maximum password age already matches the desired setting
      if [[ -n "$currentMaxAge" && "$currentMaxAge" == "$_arg_daysUntilPasswordExpiration" ]]; then
        echo "The user '$usernameToModify' already has a maximum password age of '$_arg_daysUntilPasswordExpiration'. Skipping."
        continue
      fi

      echo "Updating the maximum password age for the user '$usernameToModify'."

      # Attempt to apply the expiration policy, exiting with error if it fails
      if ! chage --maxdays "$_arg_daysUntilPasswordExpiration" "$usernameToModify"; then
        _PRINT_HELP=no die "[Error] Failed to update the maximum password age for the user '$usernameToModify'." 1
      fi

      # Confirm the update was successful
      newMaxAge=$(chage -l "$usernameToModify" | grep Max | grep -o -e "[0-9]*" | xargs)
      if [[ -z "$newMaxAge" || "$newMaxAge" != "$_arg_daysUntilPasswordExpiration" ]]; then
        _PRINT_HELP=no die "[Error] Failed to update the maximum password age for the user '$usernameToModify'." 1
      else
        echo "Successfully updated the maximum password age for the user '$usernameToModify'."
      fi
    fi
  done
fi

# Check if authselect or authconfig is available
if [[ -n "$authselectAvailable" || -n "$authconfigAvailable" ]]; then
  # If password history is specified and only authconfig is available, exit with error
  if [[ -n "$_arg_passwordHistory" && -n "$authconfigAvailable" && -z "$authselectAvailable" ]]; then
    errorMessage="
[Error] This system uses authconfig to modify the PAM configuration files.
[Error] Unfortunately, authconfig does not provide an option to implement a password history requirement and will overwrite all manual changes every time it is run.
[Error] Please upgrade your system to a distribution that supports authselect or allows manual edits of PAM configuration files.
[Error] https://bugzilla.redhat.com/show_bug.cgi?id=1271804"
    _PRINT_HELP=no die "$errorMessage" 1
  fi

  exit
fi

# Check if max login attempts or lock time is provided
if [[ -n "$_arg_maxLoginAttempts" || -n "$_arg_loginAttemptLockTime" ]]; then
  echo ""
  echo "Attempting to retrieve the current PAM authentication policy."

  # Check if common-auth file exists and is not empty
  if [[ ! -f "/etc/pam.d/common-auth" ]]; then
    _PRINT_HELP=no die "[Error] The file '/etc/pam.d/common-auth' does not exist. Cannot read the current PAM authentication policy." 1
  fi
  if [[ ! -s "/etc/pam.d/common-auth" ]]; then
    _PRINT_HELP=no die "[Error] The file '/etc/pam.d/common-auth' is empty. Cannot read the current PAM authentication policy." 1
  fi

  # Retrieve current max login attempts and lock time from common-auth
  currentAttempts=$(grep -v "^#" /etc/pam.d/common-auth | grep -v '^\s*$' | grep "pam_faillock.so" | grep "preauth" | grep -o -e "deny[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")
  currentLockTime=$(grep -v "^#" /etc/pam.d/common-auth | grep -v '^\s*$' | grep "pam_faillock.so" | grep "preauth" | grep -o -e "unlock_time[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")

  # Convert lock time to minutes if it exists
  if [[ -n "$currentLockTime" ]]; then
    currentLockTimeMinutes=$((currentLockTime / 60))
  fi

  # Convert provided lock time to seconds if specified
  if [[ -n "$_arg_loginAttemptLockTime" ]]; then
    loginAttemptLockTimeMinutes="$_arg_loginAttemptLockTime"
    _arg_loginAttemptLockTime=$((_arg_loginAttemptLockTime * 60))
  fi

  echo "Current PAM authentication policy retrieved successfully."

  # Skip max login attempts setting if it matches the current configuration
  if [[ -n "$_arg_maxLoginAttempts" && -n "$currentAttempts" && "$_arg_maxLoginAttempts" == "$currentAttempts" ]]; then
    echo "The maximum login attempts is already set to '$_arg_maxLoginAttempts'. Skipping."
    _arg_maxLoginAttempts=
  fi

  # Skip lock time setting if it matches the current configuration
  if [[ -n "$_arg_loginAttemptLockTime" && -n "$currentLockTime" && "$_arg_loginAttemptLockTime" == "$currentLockTime" ]]; then
    echo "The lock time is already set to '$loginAttemptLockTimeMinutes' minutes. Skipping."
    _arg_loginAttemptLockTime=
  fi
fi

# Check for missing lock time or max attempts arguments
if [[ -n "$_arg_maxLoginAttempts" && -z "$_arg_loginAttemptLockTime" && -z "$currentLockTime" ]]; then
  _PRINT_HELP=yes die "[Error] When specifying the maximum number of login attempts, you must also specify the login attempt lock time." 1
fi
if [[ -n "$_arg_loginAttemptLockTime" && -z "$_arg_maxLoginAttempts" && -z "$currentAttempts" ]]; then
  _PRINT_HELP=yes die "[Error] When specifying a login attempt lock time you must also specify the maximum login attempts." 1
fi

# Create a backup of the common-auth file if settings need to be applied
if [[ -n "$_arg_maxLoginAttempts" || -n "$_arg_loginAttemptLockTime" ]]; then
  commonAuthBackup="/etc/pam.d/$today-common-auth.backup"
  echo "Creating a backup of '/etc/pam.d/common-auth' to '$commonAuthBackup'."

  # Exit if a backup file already exists
  if [[ -f "$commonAuthBackup" ]]; then
    _PRINT_HELP=no die "[Error] Backup file '$commonAuthBackup' already exists. Cannot create a backup of the common-auth policy." 1
  fi

  # Attempt to create a backup, exiting if it fails
  if ! cp /etc/pam.d/common-auth "$commonAuthBackup"; then
    _PRINT_HELP=no die "[Error] Failed to create a backup of the common-auth policy to '$commonAuthBackup'." 1
  fi

  # Confirm successful backup creation
  if [[ -f "$commonAuthBackup" ]]; then
    echo "Backup created successfully."
  else
    _PRINT_HELP=no die "[Error] Unable to backup common-auth. Failed to save file to '$commonAuthBackup'" 1
  fi
fi

# Apply max login attempts and lock time settings if none exist in the current policy
if [[ -n "$_arg_maxLoginAttempts" && -n "$_arg_loginAttemptLockTime" && -z "$currentAttempts" && -z "$currentLockTime" ]]; then
  echo "Configuring the maximum login attempts and lock time in the PAM authentication policy."

  # Prepend authfail and preauth lines to common-auth for faillock, exiting if any operation fails
  if ! sed -i "1i auth  required  pam_faillock.so  authfail  deny=$_arg_maxLoginAttempts  unlock_time=$_arg_loginAttemptLockTime" "/etc/pam.d/common-auth"; then
    _PRINT_HELP=no die "[Error] Failed to configure the maximum login attempts and lock time in the PAM authentication policy." 1
  fi
  if ! sed -i "1i auth  required  pam_faillock.so  preauth  silent  deny=$_arg_maxLoginAttempts  unlock_time=$_arg_loginAttemptLockTime" "/etc/pam.d/common-auth"; then
    _PRINT_HELP=no die "[Error] Failed to configure the maximum login attempts and lock time in the PAM authentication policy." 1
  fi

  # Verify if the settings were applied successfully
  newAttempts=$(grep -v "^#" /etc/pam.d/common-auth | grep -v '^\s*$' | grep "pam_faillock.so" | grep "preauth" | grep -o -e "deny[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")
  newLockTime=$(grep -v "^#" /etc/pam.d/common-auth | grep -v '^\s*$' | grep "pam_faillock.so" | grep "preauth" | grep -o -e "unlock_time[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")

  if [[ -n "$newAttempts" && "$newAttempts" == "$_arg_maxLoginAttempts" ]]; then
    echo "Successfully configured the maximum login attempts in the PAM authentication policy."
  else
    _PRINT_HELP=no die "[Error] Failed to add the max login attempts to the PAM authentication policy." 1
  fi
  if [[ -n "$newLockTime" && "$newLockTime" == "$_arg_loginAttemptLockTime" ]]; then
    echo "Successfully added the lock time to the PAM authentication policy."
  else
    _PRINT_HELP=no die "[Error] Failed to configure the lock time in the PAM authentication policy." 1
  fi
fi

# Modify existing max login attempts setting if it doesn't match the desired setting
if [[ -n "$_arg_maxLoginAttempts" && -n "$currentAttempts" ]]; then
  echo "Modifying the current max login attempts from '$currentAttempts' to '$_arg_maxLoginAttempts' in the PAM authentication policy."

  # Update max login attempts in preauth and authfail lines, exiting if any operation fails
  existingPreAuthLine=$(grep -v "^#" /etc/pam.d/common-auth | grep -v '^\s*$' | grep -e "pam_faillock\.so [[:space:]]*preauth")
  newAttemptPreAuthLine=$(echo "$existingPreAuthLine" | sed "s/deny[[:space:]]*=[[:space:]]*[0-9]*/deny=$_arg_maxLoginAttempts/g")
  if ! sed -i "s/$existingPreAuthLine/$newAttemptPreAuthLine/g" "/etc/pam.d/common-auth"; then
    _PRINT_HELP=no die "[Error] Failed to modify the max login attempts in the PAM authentication policy 1." 1
  fi

  existingAuthFailLine=$(grep -v "^#" /etc/pam.d/common-auth | grep -v '^\s*$' | grep -e "pam_faillock\.so [[:space:]]*authfail")
  newAttemptAuthFailLine=$(echo "$existingAuthFailLine" | sed "s/deny[[:space:]]*=[[:space:]]*[0-9]*/deny=$_arg_maxLoginAttempts/g")
  if ! sed -i "s/$existingAuthFailLine/$newAttemptAuthFailLine/g" "/etc/pam.d/common-auth"; then
    _PRINT_HELP=no die "[Error] Failed to modify the max login attempts in the PAM authentication policy 2." 1
  fi

  # Confirm the new max attempts setting was applied
  newAttempts=$(grep -v "^#" /etc/pam.d/common-auth | grep -v '^\s*$' | grep "pam_faillock.so" | grep "preauth" | grep -o -e "deny[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")
  if [[ -n "$newAttempts" && "$newAttempts" == "$_arg_maxLoginAttempts" ]]; then
    echo "Successfully modified the max login attempts."
  else
    _PRINT_HELP=no die "[Error] Failed to modify the max login attempts in the PAM authentication policy." 1
  fi
fi

# Check if a new lock time is specified and differs from the current one
if [[ -n "$_arg_loginAttemptLockTime" && -n "$currentLockTime" ]]; then
  echo "Modifying the current lock time from '$currentLockTimeMinutes' minutes to '$loginAttemptLockTimeMinutes' minutes in the PAM authentication policy template."

  # Find and replace the unlock_time in the preauth line
  existingPreAuthLine=$(grep -v "^#" /etc/pam.d/common-auth | grep -v '^\s*$' | grep -e "pam_faillock\.so [[:space:]]*preauth")
  newLockTimePreAuthLine=$(echo "$existingPreAuthLine" | sed "s/unlock_time[[:space:]]*=[[:space:]]*[0-9]*/unlock_time=$_arg_loginAttemptLockTime/g")
  if ! sed -i "s/$existingPreAuthLine/$newLockTimePreAuthLine/g" "/etc/pam.d/common-auth"; then
    _PRINT_HELP=no die "[Error] Failed to modify the lock time in the PAM authentication policy." 1
  fi

  # Find and replace the unlock_time in the authfail line
  existingAuthFailLine=$(grep -v "^#" /etc/pam.d/common-auth | grep -v '^\s*$' | grep -e "pam_faillock\.so [[:space:]]*authfail")
  newLockTimeAuthFailLine=$(echo "$existingAuthFailLine" | sed "s/unlock_time[[:space:]]*=[[:space:]]*[0-9]*/unlock_time=$_arg_loginAttemptLockTime/g")
  if ! sed -i "s/$existingAuthFailLine/$newLockTimeAuthFailLine/g" "/etc/pam.d/common-auth"; then
    _PRINT_HELP=no die "[Error] Failed to modify the lock time in the PAM authentication policy." 1
  fi

  # Confirm the lock time modification
  echo "Successfully modified the current lock time."
  newLockTime=$(grep -v "^#" /etc/pam.d/common-auth | grep -v '^\s*$' | grep "pam_faillock.so" | grep "preauth" | grep -o -e "unlock_time[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")
  if [[ -n "$newLockTime" && "$newLockTime" == "$_arg_loginAttemptLockTime" ]]; then
    echo "Successfully added the lock time to the PAM authentication policy."
  else
    _PRINT_HELP=no die "[Error] Failed to configure the lock time in the PAM authentication policy." 1
  fi
fi

# Check if minimum password length or password history arguments are specified
if [[ -n "$_arg_minimumPasswordLength" || -n "$_arg_passwordHistory" ]]; then
  echo ""
  echo "Retrieving the current PAM common password policy."

  # Check if common-password file exists and is not empty
  if [[ ! -f "/etc/pam.d/common-password" ]]; then
    _PRINT_HELP=no die "[Error] The file '/etc/pam.d/common-password' does not exist. Cannot read the current PAM common password policy." 1
  fi
  if [[ ! -s "/etc/pam.d/common-password" ]]; then
    _PRINT_HELP=no die "[Error] The file '/etc/pam.d/common-password' is empty. Cannot read the current PAM common password policy." 1
  fi

  # Check if pam_unix.so module is present in the file
  if ! grep -v "^#" /etc/pam.d/common-password | grep -v '^\s*$' | grep "pam_unix.so" 1>/dev/null; then
    _PRINT_HELP=no die "[Error] The 'pam_unix.so' module is missing. Cannot append the minimum password length." 1
  fi

  # Retrieve current settings for minimum length and password history
  currentMinimumLength=$(grep -v "^#" /etc/pam.d/common-password | grep -v '^\s*$' | grep "pam_unix.so" | grep -o -e "minlen[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")
  currentPasswordHistory=$(grep -v "^#" /etc/pam.d/common-password | grep -v '^\s*$' | grep "pam_unix.so" | grep -o -e "remember[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")

  echo "Successfully retrieved the current PAM common password policy."

  # Skip minimum length setting if it matches the current configuration
  if [[ -n "$_arg_minimumPasswordLength" && -n $currentMinimumLength && "$_arg_minimumPasswordLength" == "$currentMinimumLength" ]]; then
    echo "The minimum password length is already '$_arg_minimumPasswordLength'. Skipping."
    _arg_minimumPasswordLength=
  fi

  # Skip password history setting if it matches the current configuration
  if [[ -n "$_arg_passwordHistory" && -n $currentPasswordHistory && "$_arg_passwordHistory" == "$currentPasswordHistory" ]]; then
    echo "The password history requirement is already set to remember the past '$_arg_passwordHistory' passwords. Skipping."
    _arg_passwordHistory=
  fi
fi

# Create a backup of common-password file if either minimum length or password history needs to be set
if [[ -n "$_arg_minimumPasswordLength" || -n "$_arg_passwordHistory" ]]; then
  commonPasswordBackup="/etc/pam.d/$today-common-password.backup"
  echo "Creating a backup of '/etc/pam.d/common-password' to '$commonPasswordBackup'."

  # Exit if a backup file already exists
  if [[ -f "$commonPasswordBackup" ]]; then
    _PRINT_HELP=no die "[Error] The backup file '$commonPasswordBackup' already exists. Unable to backup common-password." 1
  fi

  # Attempt to create a backup, exiting if it fails
  if ! cp /etc/pam.d/common-password "$commonPasswordBackup"; then
    _PRINT_HELP=no die "[Error] Failed to create a backup of 'common-password' to '$commonPasswordBackup'." 1
  fi

  # Confirm successful backup creation
  if [[ -f "$commonPasswordBackup" ]]; then
    echo "Backup created successfully."
  else
    _PRINT_HELP=no die "[Error] Failed to create a backup of 'common-password' to '$commonPasswordBackup'." 1
  fi
fi

# Set the minimum password length if it does not currently exist in the file
if [[ -n "$_arg_minimumPasswordLength" && -z "$currentMinimumLength" ]]; then
  echo "Setting the minimum password length to '$_arg_minimumPasswordLength'."

  # Find the line with pam_unix.so and append minlen setting
  currentPasswordLine=$(grep -v "^#" /etc/pam.d/common-password | grep -v '^\s*$' | grep "pam_unix.so")
  currentPasswordLine=$(echo "$currentPasswordLine" | sed 's/\[/\\[/g' | sed 's/\]/\\]/g')
  newMinLengthLine="$currentPasswordLine minlen=$_arg_minimumPasswordLength"
  newMinLengthLine=${newMinLengthLine//\\/}

  if ! sed -i "s/$currentPasswordLine/$newMinLengthLine/g" "/etc/pam.d/common-password"; then
    _PRINT_HELP=no die "[Error] Unable to set the minimum password length in '/etc/pam.d/common-password'." 1
  fi

  # Verify the setting was applied successfully
  newMinimumLength=$(grep -v "^#" /etc/pam.d/common-password | grep -v '^\s*$' | grep "pam_unix.so" | grep -o -e "minlen[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")
  if [[ -n "$newMinimumLength" && "$newMinimumLength" == "$_arg_minimumPasswordLength" ]]; then
    echo "Successfully set the minimum password length."
  else
    _PRINT_HELP=no die "[Error] Unable to set the minimum password length in '/etc/pam.d/common-password'." 1
  fi
fi

# Update minimum password length if it already exists but differs from desired value
if [[ -n "$_arg_minimumPasswordLength" && -n "$currentMinimumLength" ]]; then
  echo "Updating the minimum password length from '$currentMinimumLength' to '$_arg_minimumPasswordLength'."

  # Modify the existing minlen setting
  currentMinLengthLine=$(grep -v "^#" /etc/pam.d/common-password | grep -v '^\s*$' | grep "pam_unix.so" | grep "minlen")
  currentMinLengthLine=$(echo "$currentMinLengthLine" | sed 's/\[/\\[/g' | sed 's/\]/\\]/g')
  newMinLengthLine=$(echo "$currentMinLengthLine" | sed "s/minlen[[:space:]]*=[[:space:]]*[0-9]*/minlen=$_arg_minimumPasswordLength/g")
  newMinLengthLine=${newMinLengthLine//\\/}

  if ! sed -i "s/$currentMinLengthLine/$newMinLengthLine/g" "/etc/pam.d/common-password"; then
    _PRINT_HELP=no die "[Error] Unable to update the minimum password length in '/etc/pam.d/common-password'." 1
  fi

  # Verify the updated setting
  newMinimumLength=$(grep -v "^#" /etc/pam.d/common-password | grep -v '^\s*$' | grep "pam_unix.so" | grep -o -e "minlen[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")
  if [[ -n "$newMinimumLength" && "$newMinimumLength" == "$_arg_minimumPasswordLength" ]]; then
    echo "Successfully modified the minimum password length required."
  else
    _PRINT_HELP=no die "[Error] Unable to update the minimum password length in '/etc/pam.d/common-password'." 1
  fi
fi

# Set or modify the password history requirement
if [[ -n "$_arg_passwordHistory" && -z "$currentPasswordHistory" ]]; then
  echo "Setting the password history requirement."

  currentPasswordLine=$(grep -v "^#" /etc/pam.d/common-password | grep -v '^\s*$' | grep "pam_unix.so")
  currentPasswordLine=$(echo "$currentPasswordLine" | sed 's/\[/\\[/g' | sed 's/\]/\\]/g')
  newPasswordHistoryLine="$currentPasswordLine remember=$_arg_passwordHistory"
  newPasswordHistoryLine=${newPasswordHistoryLine//\\/}

  if ! sed -i "s/$currentPasswordLine/$newPasswordHistoryLine/g" "/etc/pam.d/common-password"; then
    _PRINT_HELP=no die "[Error] Failed to set the password history requirement in '/etc/pam.d/common-password'." 1
  fi

  # Confirm the new setting
  newPasswordHistory=$(grep -v "^#" /etc/pam.d/common-password | grep -v '^\s*$' | grep "pam_unix.so" | grep -o -e "remember[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")
  if [[ -n "$newPasswordHistory" && "$newPasswordHistory" == "$_arg_passwordHistory" ]]; then
    echo "Successfully set the password history requirement."
  else
    _PRINT_HELP=no die "[Error] Failed to set the password history requirement in '/etc/pam.d/common-password'." 1
  fi
fi

# Modify the password history setting if it already exists but differs from the new desired value
if [[ -n "$_arg_passwordHistory" && -n "$currentPasswordHistory" && "$_arg_passwordHistory" != "$currentPasswordHistory" ]]; then
  echo "Updating the password history requirement from remembering the last '$currentPasswordHistory' passwords to the last '$_arg_passwordHistory' passwords."

  currentPasswordLine=$(grep -v "^#" /etc/pam.d/common-password | grep -v '^\s*$' | grep "pam_unix.so" | grep "minlen")
  currentPasswordLine=$(echo "$currentPasswordLine" | sed 's/\[/\\[/g' | sed 's/\]/\\]/g')
  newPasswordHistoryLine=$(echo "$currentPasswordLine" | sed "s/remember[[:space:]]*=[[:space:]]*[0-9]*/remember=$_arg_passwordHistory/g")
  newPasswordHistoryLine=${newPasswordHistoryLine//\\/}

  if ! sed -i "s/$currentPasswordLine/$newPasswordHistoryLine/g" "/etc/pam.d/common-password"; then
    _PRINT_HELP=no die "[Error] Failed to change the password history requirement in '/etc/pam.d/common-password'." 1
  fi

  # Confirm the updated setting
  newPasswordHistory=$(grep -v "^#" /etc/pam.d/common-password | grep -v '^\s*$' | grep "pam_unix.so" | grep -o -e "remember[[:space:]]*=[[:space:]]*[0-9]*" | grep -o -e "[0-9]*")
  if [[ -n "$newPasswordHistory" && "$newPasswordHistory" == "$_arg_passwordHistory" ]]; then
    echo "Successfully modified the password history requirement."
  else
    _PRINT_HELP=no die "[Error] Failed to change the password history requirement in '/etc/pam.d/common-password'." 1
  fi
fi




