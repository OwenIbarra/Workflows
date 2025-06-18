# Create a new account on a Linux device with a randomly generated password.
#!/usr/bin/env bash
#
# Description: Create a new account on a Linux device with a randomly generated password.
#
# Preset Parameter: --usernameToAdd "replaceMeWithDesiredUsername"
#         The username to be created on the system. For compatibility reasons the username can only contain lowercase letters, numbers, or a hyphen. Usernames should be no more than 31 characters, and start with a lowercase letter.
#
#  Preset Parameter: --displayName "replaceMeWithDesiredDisplayName"
#         The display name of the user to be created, e.g. John Smith.
#
#  Preset Parameter: --passwordCustomField "replaceMeWithSecureCustomFieldName"
#         Enter the name of a secure custom field to save the randomly generated password.
#
#  Preset Parameter: --passwordLength "20"
#         The length of the randomly generated password.
#
#  Preset Parameter: --dateAndTimeToEnable "2042-10-01T00:00:00.000-07:00"
#         The date and time when the user will be enabled. Leave blank to enable the user during creation.
#
#  Preset Parameter: --disableAfterDays "30"
#         The number of days the user remains active before being disabled. The count starts from when the user is enabled. Leave blank to not schedule a disable date.
#
#  Preset Parameter: --addToSudoGroup
#         Add the user to the 'sudo' group. 
#
#  Preset Parameter: --addToWheelGroup
#         Add the user to the 'wheel' group.
#
#  Preset Parameter: --userMustChangePassword
#         Require the user to change their password at the next login.
#
#  Preset Parameter: --help
#     Displays this help menu.
#
# Release Notes: Removed plaintext password prompt, brought up to feature parity with the Windows script, and implemented input validation.

# Default values for the script.
_arg_usernameToAdd=
_arg_displayName=
_arg_passwordCustomField=
_arg_passwordLength=20
_arg_dateAndTimeToEnable=
_arg_disableAfterDays=
_arg_addToSudoGroup="off"
_arg_addToWheelGroup="off"
_arg_userMustChangePassword="off"

# Print the help message and usage instructions.
print_help() {
  printf '\n%s\n\n' 'Usage: [--usernameToAdd|-u <arg>] [--displayName|-d <arg>] [--passwordCustomField|-p <arg>] 
       [--passwordLength|-l <arg>] [--dateAndTimeToEnable|-e <arg>] [--disableAfterDays|--disable <arg>] 
       [--addToSudoGroup] [--addToWheelGroup] [--userMustChangePassword] [--help|-h]'
  printf '%s\n' 'Preset Parameter: --usernameToAdd "replaceMeWithDesiredUsername"'
  printf '\t%s\n' "The username to be created on the system. For compatibility reasons the username can only contain lowercase letters, numbers, or a hyphen. Usernames should be no more than 31 characters, and start with a lowercase letter."
  printf '%s\n' 'Preset Parameter: --displayName "replaceMeWithDesiredDisplayName"'
  printf '\t%s\n' "The display name of the user to be created, e.g. John Smith."
  printf '%s\n' 'Preset Parameter: --passwordCustomField "replaceMeWithSecureCustomFieldName"'
  printf '\t%s\n' "Enter the name of a secure custom field to save the randomly generated password."
  printf '%s\n' 'Preset Parameter: --passwordLength "20"'
  printf '\t%s\n' "The length of the randomly generated password."
  printf '%s\n' 'Preset Parameter: --dateAndTimeToEnable "2042-10-01T00:00:00.000-07:00"'
  printf '\t%s\n' "The date and time when the user will be enabled. Leave blank to enable the user during creation."
  printf '%s\n' 'Preset Parameter: --disableAfterDays "30"'
  printf '\t%s\n' "The number of days the user remains active before being disabled. The count starts from when the user is enabled. Leave blank to not schedule a disable date."
  printf '%s\n' 'Preset Parameter: --addToSudoGroup'
  printf '\t%s\n' "Add the user to the 'sudo' group."
  printf '%s\n' 'Preset Parameter: --addToWheelGroup'
  printf '\t%s\n' "Add the user to the 'wheel' group."
  printf '%s\n' 'Preset Parameter: --userMustChangePassword'
  printf '\t%s\n' "Require the user to change their password at the next login."
  printf '%s\n' 'Preset Parameter: --help'
  printf '\t%s\n' "Displays this help menu."
}

# Display an error message and exit the script with a provided exit code.
die() {
  local _ret="${2:-1}"
  echo "$1" >&2
  test "${_PRINT_HELP:-no}" = yes && print_help >&2
  exit "${_ret}"
}

# Parse command-line arguments and assign them to respective variables.
parse_commandline() {
  while test $# -gt 0; do
    _key="$1"
    case "$_key" in
    --usernameToAdd | --usernametoadd | --username | -u)
      test $# -lt 2 && die "[Error] Missing value for the required argument '$_key'." 1
      _arg_usernameToAdd=$2
      shift
      ;;
    --usernameToAdd=*)
      _arg_usernameToAdd="${_key##--usernameToAdd=}"
      ;;
    --displayName | --displayname | -d)
      test $# -lt 2 && die "[Error] Missing value for the optional argument '$_key'." 1
      _arg_displayName=$2
      shift
      ;;
    --displayName=*)
      _arg_displayName="${_key##--displayName=}"
      ;;
    --passwordCustomField | --passwordcustomfield | --password | -p)
      test $# -lt 2 && die "[Error] Missing value for the required argument '$_key'." 1
      _arg_passwordCustomField=$2
      shift
      ;;
    --passwordCustomField=*)
      _arg_passwordCustomField="${_key##--passwordCustomField=}"
      ;;
    --passwordLength | --passwordlength | --length | -l)
      test $# -lt 2 && die "[Error] Missing value for the optional argument '$_key'." 1
      _arg_passwordLength=$2
      shift
      ;;
    --passwordLength=*)
      _arg_passwordLength="${_key##--passwordLength=}"
      ;;
    --dateAndTimeToEnable | --dateandtimetoenable | --enable | -e)
      test $# -lt 2 && die "[Error] Missing value for the optional argument '$_key'." 1
      _arg_dateAndTimeToEnable=$2
      shift
      ;;
    --dateAndTimeToEnable=*)
      _arg_dateAndTimeToEnable="${_key##--dateAndTimeToEnable=}"
      ;;
    --disableAfterDays | --disableafterdays | --disable)
      test $# -lt 2 && die "[Error] Missing value for the optional argument '$_key'." 1
      _arg_disableAfterDays=$2
      shift
      ;;
    --disableAfterDays=*)
      _arg_disableAfterDays="${_key##--disableAfterDays=}"
      ;;
    --addToSudoGroup | --addtosudogroup)
      _arg_addToSudoGroup="on"
      ;;
    --addToWheelGroup | --addtowheelgroup)
      _arg_addToWheelGroup="on"
      ;;
    --userMustChangePassword | --usermustchangepassword)
      _arg_userMustChangePassword="on"
      ;;
    --help | -h)
      _PRINT_HELP=yes die 0
      ;;
    *)
      _PRINT_HELP=yes die "[Error] Got an unexpected argument '$1'." 1
      ;;
    esac
    shift
  done
}

# Function to generate a secure password.
# The password can be of a specified length and may include special characters.
securePasswordGenerator() {
  local _arg_length=16
  local _arg_include_special_characters="off"
  local base_chars='abcdefghjknpqrstuvwxyzABCDEFGHIJKMNPQRSTUVWXYZ0123456789'
  local special_chars='!@#$%&-'
  local password_chars="$base_chars"

  # Process the input arguments to customize the password generation.
  # This allows the user to specify length and whether to include special characters.
  while [[ "$#" -gt 0 ]]; do
    case $1 in
    --length)
      _arg_length="$2"
      shift 2
      ;;
    --includeSpecialCharacters)
      _arg_include_special_characters="on"
      shift
      ;;
    *)
      echo "[Error] Invalid parameter: $1" >&2
      return 1
      ;;
    esac
  done

  # Add special characters to the password pool if the user opted for them.
  if [[ $_arg_include_special_characters == "on" ]]; then
    password_chars+="$special_chars"
  fi

  # Generate the password character by character based on the specified length.
  local password=""
  for ((i = 0; i < _arg_length; i++)); do
    # Generate a random index to select a character from the password pool.
    local rand_index=$(od -An -N1 -i /dev/urandom | xargs)
    pass_index=$((rand_index % ${#password_chars}))
    local char="${password_chars:$pass_index:1}"
    password+="$char"
  done

  echo "$password"
}

echo ""

# Parse the command-line arguments
parse_commandline "$@"

# Ensure the script is run as root. Otherwise, it terminates with an error.
if [[ $(id -u) -ne 0 ]]; then
  _PRINT_HELP=no die "[Error] This script must be run with root permissions. Try running it with sudo or as the system/root user." 1
fi

# Locate the path to ninjarmm-cli using environment variable or default paths.
if [[ -n $NINJA_DATA_PATH && -f "$NINJA_DATA_PATH/ninjarmm-cli" ]]; then
  ninjarmmcliPath="$NINJA_DATA_PATH/ninjarmm-cli"
elif [[ -f "/opt/NinjaRMMAgent/programdata/ninjarmm-cli" ]]; then
  ninjarmmcliPath=/opt/NinjaRMMAgent/programdata/ninjarmm-cli
else
  _PRINT_HELP=no die "[Error] Unable to locate ninjarmm-cli." 1
fi

# If script form variables are used, replace the command-line parameters with their value.
if [[ -n $usernameToAdd ]]; then
  _arg_usernameToAdd="$usernameToAdd"
fi
if [[ -n $displayName ]]; then
  _arg_displayName="$displayName"
fi
if [[ -n $customFieldToStorePassword ]]; then
  _arg_passwordCustomField="$customFieldToStorePassword"
fi
if [[ -n $passwordLength ]]; then
  _arg_passwordLength="$passwordLength"
fi
if [[ -n $dateAndTimeToEnable ]]; then
  _arg_dateAndTimeToEnable="$dateAndTimeToEnable"
fi
if [[ -n $disableAfterDays ]]; then
  _arg_disableAfterDays="$disableAfterDays"
fi
if [[ -n $addToTheLocalAdminGroup ]]; then
  case "$addToTheLocalAdminGroup" in
    "Add to the sudo group")
      _arg_addToSudoGroup="on"
      ;;
    "Add to the wheel group")
      _arg_addToWheelGroup="on"
      ;;
    "Add to both the wheel and sudo groups")
      _arg_addToWheelGroup="on"
      _arg_addToSudoGroup="on"
      ;;
  esac
fi
if [[ -n $userMustChangePassword && $userMustChangePassword == "true" ]]; then
  _arg_userMustChangePassword="on"
fi

# Trim whitespace from the username to add, if provided.
if [[ -n "$_arg_usernameToAdd" ]]; then
  _arg_usernameToAdd=$(echo "$_arg_usernameToAdd" | xargs)
fi

# Ensure that a valid username has been provided; otherwise, display an error.
if [[ -z "$_arg_usernameToAdd" ]]; then
  _PRINT_HELP=yes die "[Error] You must provide a valid username to create the user." 1
fi

# Validate that the username is in the correct format (lowercase letters, numbers, or hyphen, starting with a letter).
if [[ ! "$_arg_usernameToAdd" =~ ^[a-z][a-z0-9-]{0,30}$ ]]; then
  _PRINT_HELP=yes die "[Error] An invalid username of '$_arg_usernameToAdd' was provided. For compatibility reasons, this script only supports usernames that contain lowercase letters, numbers, or a hyphen. Usernames should be no more than 31 characters, and start with a lowercase letter." 1
fi

# Check if the username already exists in the system.
currentUsers=$(cut -f 1 -d ':' /etc/passwd)
if echo "$currentUsers" | grep -w "$_arg_usernameToAdd" >/dev/null; then
  _PRINT_HELP=yes die "[Error] An invalid username of '$_arg_usernameToAdd' was provided. An account with the username '$_arg_usernameToAdd' already exists." 1
fi

# Trim whitespace from the display name, if provided, and check for validity.
if [[ -n "$_arg_displayName" ]]; then
  _arg_displayName=$(echo "$_arg_displayName" | xargs)

  if [[ -z "$_arg_displayName" ]]; then
    _PRINT_HELP=yes die "[Error] An invalid display name was provided. Please provide a valid display name (or leave it blank to use the username as the display name)." 1
  fi
fi

# If no display name is provided, default to using the username as the display name.
if [[ -z "$_arg_displayName" ]]; then
  _arg_displayName="$_arg_usernameToAdd"
fi

# Ensure that the display name does not contain invalid characters.
if [[ $_arg_displayName =~ [:,] ]]; then
  _PRINT_HELP=yes die "[Error] An invalid display name was provided. Display names cannot contain the following characters: \":,\"" 1
fi

# Check if the display name already exists in the system.
currentDisplayNames=$(cut -f 5 -d ':' /etc/passwd | cut -f 1 -d ',')
if echo "$currentDisplayNames" | grep -w "$_arg_displayName" >/dev/null; then
  _PRINT_HELP=yes die "[Error] An invalid display name was provided. An account with the display name of '$_arg_displayName' already exists." 1
fi

# Trim whitespace from the custom password field, if provided.
if [[ -n "$_arg_passwordCustomField" ]]; then
  _arg_passwordCustomField=$(echo "$_arg_passwordCustomField" | xargs)
fi

# Ensure a valid custom field for storing the password has been provided.
if [[ -z "$_arg_passwordCustomField" ]]; then
  _PRINT_HELP=yes die "[Error] You must provide a valid custom field for storing the password." 1
fi

# Trim whitespace from the password length, if provided.
if [[ -n "$_arg_passwordLength" ]]; then
  _arg_passwordLength=$(echo "$_arg_passwordLength" | xargs)
fi

# Ensure that a valid password length is provided.
if [[ -z "$_arg_passwordLength" ]]; then
  _PRINT_HELP=yes die "[Error] You must provide a valid password length to create the user." 1
fi

# Validate that the password length is a positive whole number.
if [[ "$_arg_passwordLength" =~ [^0-9] ]]; then
  _PRINT_HELP=yes die "[Error] An invalid password length of '$_arg_passwordLength' was provided. The password length must be a positive whole number that is greater than or equal to 8 and less than or equal to 128." 1
fi

# Ensure that the password length falls within the acceptable range (8 to 128 characters).
if [[ "$_arg_passwordLength" -lt 8 || "$_arg_passwordLength" -gt 128 ]]; then
  _PRINT_HELP=yes die "[Error] An invalid password length of '$_arg_passwordLength' was provided. Password length must be greater than or equal to 8 and less than or equal to 128." 1
fi

# Check if either the sudo or wheel groups should be added and verify that sudo is available on the system.
if [[ $_arg_addToSudoGroup == "on" || $_arg_addToWheelGroup == "on" ]]; then
  if ! command -v sudo >/dev/null; then
    _PRINT_HELP=yes die "[Error] The 'sudo' application was not found. It is required to grant the user administrator privileges." 1
  fi
fi

# If the sudo group is selected, verify that it exists on the system.
if [[ $_arg_addToSudoGroup == "on" ]]; then
  if ! grep -w "sudo" /etc/group >/dev/null; then
    _PRINT_HELP=yes die "[Error] The sudo group does not exist." 1
  fi
fi

# If the wheel group is selected, verify that it exists on the system.
if [[ $_arg_addToWheelGroup == "on" ]]; then
  if ! grep -w "wheel" /etc/group >/dev/null; then
    _PRINT_HELP=yes die "[Error] The wheel group does not exist." 1
  fi
fi

# Trim whitespace from the enable date and time, if provided, and check for validity.
if [[ -n "$_arg_dateAndTimeToEnable" ]]; then
  _arg_dateAndTimeToEnable=$(echo "$_arg_dateAndTimeToEnable" | xargs)

  if [[ -z "$_arg_dateAndTimeToEnable" ]]; then
    _PRINT_HELP=yes die "[Error] An invalid enable date and time was provided. Please provide a valid enable date (or leave it blank to enable the account immediately)." 1
  fi
fi

# Ensure that the enable date is in ISO 8601 format.
if [[ -n "$_arg_dateAndTimeToEnable" && ! "$_arg_dateAndTimeToEnable" =~ - ]]; then
  _PRINT_HELP=yes die "[Error] An invalid enable date and time of '$_arg_dateAndTimeToEnable' was provided. Please provide a valid enable date in ISO 8601 format (or leave it blank to enable the account immediately)." 1
fi

# Validate that the enable date is not in the past.
if [[ -n "$_arg_dateAndTimeToEnable" ]]; then
  if ! _arg_dateAndTimeToEnableSeconds=$(date --date "$_arg_dateAndTimeToEnable" "+%s"); then
    _PRINT_HELP=yes die "[Error] An invalid enable date and time of '$_arg_dateAndTimeToEnable' was provided. Please provide a valid enable date (or leave it blank to enable the account immediately)." 1
  fi

  todayInSeconds=$(date "+%s")
  if [[ $todayInSeconds -gt $_arg_dateAndTimeToEnableSeconds ]]; then
    _PRINT_HELP=yes die "[Error] An invalid enable date and time of '$_arg_dateAndTimeToEnable' was provided. Please provide a date and time that is in the future (or leave it blank to enable the account immediately)." 1
  fi
fi

# Trim whitespace from the disable after days value, if provided, and validate it.
if [[ -n "$_arg_disableAfterDays" ]]; then
  _arg_disableAfterDays=$(echo "$_arg_disableAfterDays" | xargs)

  if [[ -z "$_arg_disableAfterDays" ]]; then
    _PRINT_HELP=yes die "[Error] An invalid disable after days was given. Please specify a positive whole number that is greater than 0 or leave blank to not schedule an expiration." 1
  fi

  # Ensure that the disable after days value is a positive whole number.
  if [[ "$_arg_disableAfterDays" =~ [^0-9] ]]; then
    _PRINT_HELP=yes die "[Error] An invalid disable after days was given: \"$_arg_disableAfterDays\". Please specify a positive whole number that is greater than 0 or leave blank to not schedule an expiration." 1
  fi

  if [[ "$_arg_disableAfterDays" -lt 1 ]]; then
    _PRINT_HELP=yes die "[Error] An invalid disable after days was given: \"$_arg_disableAfterDays\". Please specify a positive whole number that is greater than 0 or leave blank to not schedule an expiration." 1
  fi

  # Calculate the disable date based on the enable date and disable after days value.
  if [[ -n "$_arg_dateAndTimeToEnable" ]]; then
    if ! _dateToDisable=$(date --date "$_arg_dateAndTimeToEnable + $_arg_disableAfterDays days" "+%Y-%m-%d"); then
      _PRINT_HELP=yes die "[Error] Failed to apply '$_arg_disableAfterDays' days after the enable date of '$_arg_dateAndTimeToEnable'." 1
    fi
  else
    if ! _dateToDisable=$(date --date "$_arg_dateAndTimeToEnable + $_arg_disableAfterDays days" "+%Y-%m-%d"); then
      _PRINT_HELP=yes die "[Error] Failed to add disable after days to $_arg_disableAfterDays after today." 1
    fi
  fi

  # Ensure the disable date is calculated successfully.
  if [[ -z "$_dateToDisable" ]]; then
    _PRINT_HELP=yes die "[Error] Failed to calculate the date to expire the account."
  fi
fi

# Generate a secure password for the user being created.
echo "Generating a password for the user '$_arg_usernameToAdd'."

# Initialize loop counter and password variable.
i=0
password=

# Attempt to generate a password that meets the required criteria:
# It must contain at least one special character, one uppercase letter, one lowercase letter, and one number.
while [[ $i -lt 1000 && ! ("$password" =~ [@!#$\%\&-] && "$password" =~ [A-Z] && "$password" =~ [a-z] && "$password" =~ [0-9]) ]]; do
  # Use the secure password generator function to create a password with the specified length and special characters, if required.
  password=$(securePasswordGenerator --length "$_arg_passwordLength" --includeSpecialCharacters)
  # Increment the loop counter.
  i=$((i + 1))
done

# If a valid password cannot be generated after 1000 attempts, display an error message and exit.
if [[ $i -ge 999 ]]; then
  _PRINT_HELP=no die "[Error] Failed to generate a password that contains at least 1 special character, 1 uppercase letter, 1 lowercase letter, and 1 number. Please try again." 1
fi

# Attempt to save the generated password to the specified secure custom field.
# This field is used to store the password securely before proceeding with account creation.
echo "Attempting to save the generated password to the secure custom field '$_arg_passwordCustomField' before proceeding with account creation."
if ! output=$("$ninjarmmcliPath" set "$_arg_passwordCustomField" "$password" 2>&1); then
  _PRINT_HELP=no die "[Error] $output" 1
fi
echo "Successfully saved the generated password to the secure custom field '$_arg_passwordCustomField'."

# Initialize the arguments for account creation.
# This includes adding the username, display name, and password.
accountCreationArgs=("-m" "$_arg_usernameToAdd" "-c" "$_arg_displayName")
echo "Creating the account '$_arg_usernameToAdd'."

# If a disable-after-days value is provided, add an account expiration date to the account creation arguments.
if [[ -n $_arg_disableAfterDays ]]; then
  echo "Adding an account expiration date of '$_dateToDisable' to the account creation."
  accountCreationArgs+=("-e" "$_dateToDisable")
fi

# If the bash shell exists on the system, set it as the default shell for the user.
if [[ -f "/bin/bash" ]]; then
  accountCreationArgs+=("-s" "/bin/bash")
fi

# Create the user with the provided arguments. Exit with an error if account creation fails.
if ! useradd "${accountCreationArgs[@]}"; then
  _PRINT_HELP=no die "[Error] Failed to create the account." 1
fi

# Verify that the user was successfully created by checking the /etc/passwd file.
if ! cut -f 1 -d ':' /etc/passwd | grep -w "$_arg_usernameToAdd" >/dev/null; then
  _PRINT_HELP=no die "[Error] Failed to find the account in /etc/passwd. Account creation failed." 1
else
  echo "Successfully created the account."
fi

# Set the password for the user. Exit with an error if the password cannot be set.
echo "Setting the password for '$_arg_usernameToAdd'."
if ! echo "$_arg_usernameToAdd:$password" | chpasswd; then
  _PRINT_HELP=no die "[Error] Failed to set the password. Account creation failed." 1
fi

# If a future enable date is provided, temporarily disable the account until that date.
if [[ -n "$_arg_dateAndTimeToEnable" ]]; then
  echo "Disabling the account."

  # Store the user's default shell and temporarily set the shell to /sbin/nologin, locking the account.
  defaultShell=$(grep -w "$_arg_usernameToAdd" /etc/passwd | cut -d ":" -f7 | xargs)
  if ! usermod -s /sbin/nologin -L "$_arg_usernameToAdd"; then
    _PRINT_HELP=no die "[Error] Failed to disable the account." 1
  fi

  # Verify that the account is locked by checking its status.
  if ! passwd -S "$_arg_usernameToAdd" | cut -f2 -d " " | grep "L" >/dev/null; then
    _PRINT_HELP=no die "[Error] Failed to disable the account." 1
  else
    echo "Successfully disabled the user '$_arg_usernameToAdd'."
  fi
fi

# Add the display name (GECOS field) to the account if it was not previously set.
if ! grep -w "$_arg_usernameToAdd" /etc/passwd | cut -f 5 -d ':' | cut -f 1 -d ',' >/dev/null; then
  echo "Adding the display name '$_arg_displayName' to the GECOS field."

  # Use chfn to set the display name. Exit with an error if this operation fails.
  if ! chfn -f "$_arg_displayName" "$_arg_usernameToAdd"; then
    _PRINT_HELP=no die "[Error] Failed to add the display name '$_arg_displayName' for the user '$_arg_usernameToAdd'." 1
  fi
fi

# If the sudo group option is enabled, add the user to the sudo group.
if [[ "$_arg_addToSudoGroup" == "on" ]]; then
  echo "Adding the user to the sudo group."

  # Add the user to the sudo group. Exit with an error if the operation fails.
  if ! usermod -a -G sudo "$_arg_usernameToAdd"; then
    _PRINT_HELP=no die "[Error] Failed to add '$_arg_usernameToAdd' to the sudo group." 1
  fi

  # Verify that the user was successfully added to the sudo group.
  if ! groups "$_arg_usernameToAdd" | grep -w sudo >/dev/null; then
    _PRINT_HELP=no die "[Error] Failed to add '$_arg_usernameToAdd' to the sudo group." 1
  else
    echo "Successfully added the user to the sudo group."
  fi
fi

# If the wheel group option is enabled, add the user to the wheel group.
if [[ "$_arg_addToWheelGroup" == "on" ]]; then
  echo "Adding the user to the wheel group."

  # Add the user to the wheel group. Exit with an error if the operation fails.
  if ! usermod -a -G wheel "$_arg_usernameToAdd"; then
    _PRINT_HELP=no die "[Error] Failed to add '$_arg_usernameToAdd' to the wheel group." 1
  fi

  # Verify that the user was successfully added to the wheel group.
  if ! groups "$_arg_usernameToAdd" | grep -w wheel >/dev/null; then
    _PRINT_HELP=no die "[Error] Failed to add '$_arg_usernameToAdd' to the wheel group." 1
  else
    echo "Successfully added the user to the wheel group."
  fi
fi

# If the user must change their password on the next login, enforce that requirement.
if [[ "$_arg_userMustChangePassword" == "on" ]]; then
  echo "Requiring the user '$_arg_usernameToAdd' to change their password at the next login."

  # Use passwd to set the password expiration. Exit with an error if the operation fails.
  if ! passwd --expire "$_arg_usernameToAdd"; then
    _PRINT_HELP=no die "[Error] Failed to require '$_arg_usernameToAdd' to change their password at the next login." 1
  fi

  # Verify that the password change requirement was successfully set.
  if ! chage -l "$_arg_usernameToAdd" | grep "Password expires" | cut -f 2 -d ":" | grep "password must be changed" >/dev/null; then
    _PRINT_HELP=no die "[Error] Failed to require '$_arg_usernameToAdd' to change their password at the next login." 1
  else
    echo "Successfully set password change requirement."
  fi
fi

# If no future enable date is provided, exit the script.
if [[ -z "$_arg_dateAndTimeToEnable" ]]; then
  exit
fi

# Create a systemd service file and timer to re-enable the account at the specified future date.
echo "Creating a systemd service file and timer to enable the account at '$_arg_dateAndTimeToEnable'."

# Verify that the systemd directory exists.
if [[ ! -d "/etc/systemd/system" ]]; then
  _PRINT_HELP=no die "[Error] The systemd service file directory was not found at /etc/systemd/system." 1
fi

# Check if systemd timer or service files already exist for the user, and exit with an error if they do.
if [[ -f "/etc/systemd/system/$todayInSeconds-$_arg_usernameToAdd.timer" || -f "/etc/systemd/system/$todayInSeconds-$_arg_usernameToAdd.service" ]]; then
  _PRINT_HELP=no die "[Error] systemd timer or service files already exist at /etc/systemd/system/$todayInSeconds-$_arg_usernameToAdd." 1
fi

# Locate the path to the usermod command.
usermodPath=$(command -v usermod)

# Create a systemd service file that will re-enable the user account by restoring the default shell.
# The service uses the `usermod` command to unlock the account and reset the shell to its original value.
echo "[Unit]
Description=Enable $_arg_usernameToAdd

[Service]
ExecStart=$usermodPath -s $defaultShell -U '$_arg_usernameToAdd'" >"/etc/systemd/system/$todayInSeconds-$_arg_usernameToAdd.service"

# Calculate the date and time for when the account should be enabled, using the ISO 8601 format.
systemdTimerDate=$(date --date "$_arg_dateAndTimeToEnable" "+%Y-%m-%d %H:%M:%S")

# Create a systemd timer file that schedules the execution of the service at the specified date and time.
echo "[Unit]
Description=Run $todayInSeconds-$_arg_usernameToAdd.service at $systemdTimerDate.

[Timer]
OnCalendar=$systemdTimerDate
Unit=$todayInSeconds-$_arg_usernameToAdd.service

[Install]
WantedBy=timers.target" >"/etc/systemd/system/$todayInSeconds-$_arg_usernameToAdd.timer"

# Inform the user that the systemd timer is being enabled to re-enable the account at the specified time.
echo "Enabling the systemd timer to schedule enabling the account '$_arg_usernameToAdd'."

# Verify that both the systemd timer and service files were created successfully.
if [[ ! -f "/etc/systemd/system/$todayInSeconds-$_arg_usernameToAdd.timer" || ! -f "/etc/systemd/system/$todayInSeconds-$_arg_usernameToAdd.service" ]]; then
  _PRINT_HELP=no die "[Error] Failed to create systemd service files at /etc/systemd/system." 1
fi

# Use systemd-analyze to check the validity of the timer file and ensure it was created correctly.
if systemd-analyze verify "/etc/systemd/system/$todayInSeconds-$_arg_usernameToAdd.timer" 2>&1 | grep "$_arg_usernameToAdd"; then
  _PRINT_HELP=no die "[Error] An invalid systemd file was created at /etc/systemd/system/$todayInSeconds-$_arg_usernameToAdd.timer." 1
fi

# Use systemd-analyze to check the validity of the service file and ensure it was created correctly.
if systemd-analyze verify "/etc/systemd/system/$todayInSeconds-$_arg_usernameToAdd.service" 2>&1 | grep "$_arg_usernameToAdd"; then
  _PRINT_HELP=no die "[Error] An invalid systemd file was created at /etc/systemd/system/$todayInSeconds-$_arg_usernameToAdd.service." 1
fi

# Enable the systemd timer so that it starts at boot and runs at the specified time to re-enable the account.
if ! systemctl enable "$todayInSeconds-$_arg_usernameToAdd.timer"; then
  _PRINT_HELP=no die "[Error] Failed to enable the systemd timer." 1

fi

# Start the systemd timer immediately so that it will trigger the service at the correct time.
if ! systemctl start "$todayInSeconds-$_arg_usernameToAdd.timer"; then
  _PRINT_HELP=no die "[Error] Failed to start the systemd timer." 1
fi

echo "Successfully scheduled the account enabling for $systemdTimerDate."




