# Create a new account for macOS with a randomly generated password. To create the new account with a secure token, please provide either an existing username and password to generate a token, or select prompt end-user.
#!/usr/bin/env bash
#
# Description: Create a new account for macOS with a randomly generated password. To create the new account with a secure token, please provide either an existing username and password to generate a token, or select prompt end-user.
#
# More info on secure tokens: https://support.apple.com/guide/deployment/use-secure-and-bootstrap-tokens-dep24dbdcf9e/web
#
# Preset Parameter: --usernameToAdd "replaceMeWithDesiredUsername"
#		The username to be created on the system.
#
# Preset Parameter: --displayName "replaceMeWithDesiredDisplayname"
#		The display name of the user to be created, e.g. John Smith.
#
# Preset Parameter: --passwordCustomField "replaceMeWithNameOfSecureCustomField"
#		Enter the name of a secure custom field to save the randomly generated password.
#
# Preset Parameter: --passwordLength "20"
#		The length of the randomly generated password.
#
# Preset Parameter: --dateAndTimeToEnable "2042-10-16T14:00:00.000-07:00"
#		The date and time when the user will be enabled. Leave blank to enable the user during creation.
#
# Preset Parameter: --optionalAuthenticationUsername "replaceMeWithExistingAdminUsername"
#		Optionally specify the username of a local administrator to use for granting the secure token. This field does not pull from a custom field.
#
# Preset Parameter: --optionalAuthenticationPasswordField "replaceMeWithNameOfSecureCustomField"
#		Optionally specify the name of a secure custom field to retrieve the password for the user specified in the Optional Authentication Account Username.
#
# Preset Parameter: --promptEndUser
#		If selected the end user will be prompted to provide an admin account to create the secure token.
#
# Preset Parameter: --addToLocalAdminGroup
#		Add the user to the local administrators group.
#
# Preset Parameter: --requirePasswordChange
#		Require the user to change their password at the next login.
#
# Preset Parameter: --help
#		Displays some help text.
#
# Release Notes: Removed plaintext password prompt, brought up to feature parity with the Windows script, added secure token support, and implemented input validation.

# Initialize variables for the script's arguments and default values.
_arg_usernameToAdd=
_arg_displayName=
_arg_passwordCustomField=
_arg_passwordLength=20
_arg_dateAndTimeToEnable=
_arg_addToLocalAdminGroup="off"
_arg_optionalAuthenticationUsername=
_arg_optionalAuthenticationPassword=
_arg_optionalAuthenticationPassCustomField=
_arg_promptEndUser="off"
_arg_requirePasswordChange="off"

echo ""
exitCode=0

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

# Function to print the help menu with usage instructions.
# It describes the available parameters and their descriptions.
print_help() {
  printf '\n%s\n\n' 'Usage: [--usernameToAdd|-u <arg>] [--displayName|-f <arg>] [--passwordCustomField|-p <arg>] [--passwordLength|-l <arg>] [--dateAndTimeToEnable|-e <arg>] [--optionalAuthenticationUsername|-au <arg>] [--optionalAuthenticationPasswordField|-af <arg>] [--promptEndUser|--prompt] [--requirePasswordChange|-rp] [--addToLocalAdminGroup|-a] [--help|-h]'
  printf '%s\n\n' 'More info on secure tokens: https://support.apple.com/guide/deployment/use-secure-and-bootstrap-tokens-dep24dbdcf9e/web'
  printf '%s\n' 'Preset Parameter: --usernameToAdd "replaceMeWithDesiredUsername"'
  printf '\t%s\n' "The username to be created on the system."
  printf '%s\n' 'Preset Parameter: --displayName "replaceMeWithDesiredDisplayname"'
  printf '\t%s\n' "The display name of the user to be created, e.g. John Smith."
  printf '%s\n' 'Preset Parameter: --passwordCustomField "replaceMeWithNameOfSecureCustomField"'
  printf '\t%s\n' "Enter the name of a secure custom field to save the randomly generated password."
  printf '%s\n' 'Preset Parameter: --passwordLength "20"'
  printf '\t%s\n' "The length of the randomly generated password."
  printf '%s\n' 'Preset Parameter: --dateAndTimeToEnable "2042-10-16T14:00:00.000-07:00"'
  printf '\t%s\n' "The date and time when the user will be enabled. Leave blank to enable the user during creation."
  printf '%s\n' 'Preset Parameter: --optionalAuthenticationUsername "replaceMeWithExistingAdminUsername"'
  printf '\t%s\n' "Optionally specify the username of a local administrator to use for granting the secure token. This field does not pull from a custom field."
  printf '%s\n' 'Preset Parameter: --optionalAuthenticationPasswordField "replaceMeWithNameOfSecureCustomField"'
  printf '\t%s\n' "Optionally specify the name of a secure custom field to retrieve the password for the user specified in the Optional Authentication Account Username."
  printf '%s\n' 'Preset Parameter: --promptEndUser'
  printf '\t%s\n' "If selected the end user will be prompted to provide an admin account to create the secure token."
  printf '%s\n' 'Preset Parameter: --addToLocalAdminGroup'
  printf '\t%s\n' "Add the user to the local administrators group."
  printf '%s\n' 'Preset Parameter: --requirePasswordChange'
  printf '\t%s\n' "Require the user to change their password at the next login."
  printf '%s\n' 'Preset Parameter: --help'
  printf '\t%s\n' "Displays this help menu."
}

# Function to display an error message and terminate the script.
# Optionally, it prints the help menu if the _PRINT_HELP variable is set.
die() {
  local _ret="${2:-1}"
  echo "$1" >&2
  test "${_PRINT_HELP:-no}" = yes && print_help >&2
  exit "${_ret}"
}

# Function to parse the command-line arguments passed to the script.
# It maps various argument keys (like --usernameToAdd) to the appropriate variables.
parse_commandline() {
  while test $# -gt 0; do
    _key="$1"
    case "$_key" in
    --usernameToAdd | --usernametoadd | --username | --user | -u)
      test $# -lt 2 && die "[Error] Missing value for the required argument '$_key'." 1
      _arg_usernameToAdd=$2
      shift
      ;;
    --usernameToAdd=*)
      _arg_usernameToAdd="${_key##--usernameToAdd=}"
      ;;
    --displayName | --displayname | --fullname | -f)
      test $# -lt 2 && die "[Error] Missing value for the required argument '$_key'." 1
      _arg_displayName=$2
      shift
      ;;
    --displayName=*)
      _arg_displayName="${_key##--displayName=}"
      ;;
    --passwordCustomField | --passwordcustomfield | --passwordfield | -p)
      test $# -lt 2 && die "[Error] Missing value for the required argument '$_key'." 1
      _arg_passwordCustomField=$2
      shift
      ;;
    --passwordCustomField=*)
      _arg_passwordCustomField="${_key##--passwordCustomField=}"
      ;;
    --passwordLength | --passwordlength | --passlength | --length | -l)
      test $# -lt 2 && die "[Error] Missing value for the required argument '$_key'." 1
      _arg_passwordLength=$2
      shift
      ;;
    --passwordLength=*)
      _arg_passwordLength="${_key##--passwordLength=}"
      ;;
    --dateAndTimeToEnable | --dateandtimetoenable | --enable | -e)
      test $# -lt 2 && die "[Error] Missing value for the required argument '$_key'." 1
      _arg_dateAndTimeToEnable=$2
      shift
      ;;
    --dateAndTimeToEnable=*)
      _arg_dateAndTimeToEnable="${_key##--dateAndTimeToEnable=}"
      ;;
    --optionalAuthenticationUsername | --optionalauthenticationusername | --authusername | -au)
      test $# -lt 2 && die "[Error] Missing value for the required argument '$_key'." 1
      _arg_optionalAuthenticationUsername=$2
      shift
      ;;
    --optionalAuthenticationUsername=*)
      _arg_optionalAuthenticationUsername="${_key##--optionalAuthenticationUsername=}"
      ;;
    --optionalAuthenticationPasswordField | --optionalauthenticationpassword | --authcustomfield | -af)
      test $# -lt 2 && die "[Error] Missing value for the required argument '$_key'." 1
      _arg_optionalAuthenticationPassCustomField=$2
      shift
      ;;
    --optionalAuthenticationPassword=*)
      _arg_optionalAuthenticationPassCustomField="${_key##--optionalAuthenticationPassword=}"
      ;;
    --promptEndUser | --promptenduser | --prompt)
      _arg_promptEndUser="on"
      ;;
    --requirePasswordChange | --requirepasswordchange | -rp)
      _arg_requirePasswordChange="on"
      ;;
    --addToLocalAdminGroup | --addtolocaladmingroup | -a)
      _arg_addToLocalAdminGroup="on"
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

parse_commandline "$@"

# Ensure the script is run as root. Otherwise, it terminates with an error.
if [[ $(id -u) -ne 0 ]]; then
  _PRINT_HELP=no die "[Error] This script must be run with root permissions. Try running it with sudo or as the system/root user." 1
fi

# Locate the path to ninjarmm-cli using environment variable or default paths.
if [[ -n $NINJA_DATA_PATH && -f "$NINJA_DATA_PATH/ninjarmm-cli" ]]; then
  ninjarmmcliPath="$NINJA_DATA_PATH/ninjarmm-cli"
elif [[ -f "/Applications/NinjaRMMAgent/programdata/ninjarmm-cli" ]]; then
  ninjarmmcliPath=/Applications/NinjaRMMAgent/programdata/ninjarmm-cli
else
  _PRINT_HELP=no die "[Error] Unable to locate ninjarmm-cli." 1
fi

# If script variables are used, replace the commandline parameters with their value.
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
if [[ -n $optionalAuthenticationAccountUsername ]]; then
  _arg_optionalAuthenticationUsername="$optionalAuthenticationAccountUsername"
fi
if [[ -n $optionalAuthenticationAccountPasswordCustomField ]]; then
  _arg_optionalAuthenticationPassCustomField="$optionalAuthenticationAccountPasswordCustomField"
fi
if [[ -n $promptEndUserToCreateTheSecureToken && $promptEndUserToCreateTheSecureToken == "true" ]]; then
  _arg_promptEndUser="on"
fi
if [[ -n $addToLocalAdminGroup && $addToLocalAdminGroup == "true" ]]; then
  _arg_addToLocalAdminGroup="on"
fi
if [[ -n $userMustChangePassword && $userMustChangePassword == "true" ]]; then
  _arg_requirePasswordChange="on"
fi

# Remove trailing whitespace from the username.
if [[ -n "$_arg_usernameToAdd" ]]; then
  _arg_usernameToAdd=$(echo "$_arg_usernameToAdd" | xargs)
fi

# Validate that the username is not an empty string.
if [[ -z "$_arg_usernameToAdd" ]]; then
  _PRINT_HELP=yes die "[Error] You must provide a valid username to create the user." 1
fi

# Check if the username exceeds the 20-character limit.
if [[ "$_arg_usernameToAdd" =~ .{21,} ]]; then
  _PRINT_HELP=yes die "[Error] An invalid username of '$_arg_usernameToAdd' was provided. Usernames cannot be greater than 20 characters." 1
fi

# Ensure the username only contains allowed characters: letters, numbers, or specific symbols.
if [[ "$_arg_usernameToAdd" =~ [^a-zA-Z0-9._-] ]]; then
  _PRINT_HELP=yes die "[Error] An invalid username of '$_arg_usernameToAdd' was provided. Usernames can only contain letters, numbers, or one of these symbols '-_.'." 1
fi

# Verify the username does not start with a period.
if [[ "$_arg_usernameToAdd" =~ ^\. ]]; then
  _PRINT_HELP=yes die "[Error] An invalid username of '$_arg_usernameToAdd' was provided. Usernames cannot start with a '.' symbol." 1
fi

currentUsers=$(dscl . list /Users)
# Verify that the provided username does not exists on the system.
if echo "$currentUsers" | grep -w "$_arg_usernameToAdd" >/dev/null; then
  _PRINT_HELP=yes die "[Error] An invalid username of '$_arg_usernameToAdd' was provided. An account with the username '$_arg_usernameToAdd' already exists." 1
fi

# Validate and clean up the display name, ensuring it is not empty if provided.
if [[ -n "$_arg_displayName" ]]; then
  _arg_displayName=$(echo "$_arg_displayName" | xargs)

  if [[ -z "$_arg_displayName" ]]; then
    _PRINT_HELP=yes die "[Error] An invalid display name was provided. Please provide a valid display name (or leave it blank to use the username as the display name)." 1
  fi
else
  # Use the username as the display name if no display name is provided.
  _arg_displayName="$_arg_usernameToAdd"
fi

# Loop through each user and retrieve their display name
for user in $currentUsers; do
  displayName=$(dscl . -read /Users/"$user" RealName | tail -1 | cut -d' ' -f2-)

  # Ensure all display names are unique
  if [[ "$_arg_displayName" == "$displayName" ]]; then
    _PRINT_HELP=yes die "[Error] An invalid display name was provided. An account with the display name of '$_arg_displayName' already exists." 1
  fi
done

# Remove trailing whitespace from the password custom field if provided.
if [[ -n "$_arg_passwordCustomField" ]]; then
  _arg_passwordCustomField=$(echo "$_arg_passwordCustomField" | xargs)
fi

# Ensure a custom field for storing the password is provided.
if [[ -z "$_arg_passwordCustomField" ]]; then
  _PRINT_HELP=yes die "[Error] You must provide a valid custom field for storing the password." 1
fi

# Remove trailing whitespace from the password custom field.
if [[ -n "$_arg_passwordLength" ]]; then
  _arg_passwordLength=$(echo "$_arg_passwordLength" | xargs)
fi

# Validate that the password length is provided.
if [[ -z "$_arg_passwordLength" ]]; then
  _PRINT_HELP=yes die "[Error] You must provide a valid password length to create the user." 1
fi

# Validate that the password length only contains digits
if [[ "$_arg_passwordLength" =~ [^0-9] ]]; then
  _PRINT_HELP=yes die "[Error] An invalid password length of '$_arg_passwordLength' was provided. The password length must be a positive whole number that's greater than or equal to 8 and less than or equal to 128." 1
fi

# Validate that the password length meets the minimum length requirements
if [[ "$_arg_passwordLength" -lt 8 || "$_arg_passwordLength" -gt 128 ]]; then
  _PRINT_HELP=yes die "[Error] An invalid password length of '$_arg_passwordLength' was provided. Password length must be greater than or equal to 8 and less than or equal to 128." 1
fi

# If an enable date and time are provided, clean up and format the input to ensure it is valid.
if [[ -n "$_arg_dateAndTimeToEnable" ]]; then
  # Trim any leading/trailing whitespace and remove milliseconds from the date and time.
  _arg_dateAndTimeToEnable=$(echo "$_arg_dateAndTimeToEnable" | xargs)
  _arg_dateAndTimeToEnable=${_arg_dateAndTimeToEnable//\.[0-9][0-9][0-9]/}

  # Remove any trailing colons from the time part of the date.
  _arg_dateAndTimeToEnable=$(echo "$_arg_dateAndTimeToEnable" | sed 's/:\([0-9]\{2\}\)$/\1/')

  # Ensure that the enable date and time is not left empty after the cleanup process.
  if [[ -z "$_arg_dateAndTimeToEnable" ]]; then
    _PRINT_HELP=yes die "[Error] An invalid enable date and time was provided. Please provide a valid enable date (or leave it blank to enable the account immediately)." 1
  fi
fi

# If the enable date contains a dash, process it as a valid ISO 8601 date format.
if [[ -n "$_arg_dateAndTimeToEnable" && "$_arg_dateAndTimeToEnable" =~ - ]]; then
  # Convert the enable date to Unix timestamp format.
  if ! _arg_dateAndTimeToEnableSeconds=$(date -j -f "%Y-%m-%dT%H:%M:%S%z" "$_arg_dateAndTimeToEnable" "+%s"); then
    _PRINT_HELP=yes die "[Error] An invalid enable date and time of '$_arg_dateAndTimeToEnable' was provided. Please provide a valid enable date (or leave it blank to enable the account immediately)." 1
  fi

  # Convert the enable date to an NSDate-compatible format for macOS policies.
  if ! _arg_dateAndTimeToEnableNSDate=$(date -j -f "%Y-%m-%dT%H:%M:%S%z" -u "$_arg_dateAndTimeToEnable" +"%Y-%m-%dT%H:%M:%SZ"); then
    _PRINT_HELP=yes die "[Error] An invalid enable date and time of '$_arg_dateAndTimeToEnable' was provided. Please provide a valid enable date (or leave it blank to enable the account immediately)." 1
  fi
elif [[ -n "$_arg_dateAndTimeToEnable" ]]; then
  _PRINT_HELP=yes die "[Error] An invalid enable date and time of '$_arg_dateAndTimeToEnable' was provided. Please provide a valid enable date (or leave it blank to enable the account immediately)." 1
fi

# Ensure the enable date is in the future by comparing it to the current time.
today=$(date "+%s")
if [[ -n $_arg_dateAndTimeToEnableSeconds && $today -gt $_arg_dateAndTimeToEnableSeconds ]]; then
  _PRINT_HELP=yes die "[Error] An invalid enable date and time of '$_arg_dateAndTimeToEnable' was provided. Please provide a date and time that is in the future (or leave it blank to enable the account immediately)." 1
fi

if [[ $_arg_promptEndUser == "on" && (-n "$_arg_optionalAuthenticationUsername" || -n "$_arg_optionalAuthenticationPassword") ]]; then
  _PRINT_HELP=yes die "[Error] You cannot prompt the user and use a different set of credentials at the same time." 1
fi

# If an optional authentication username is provided, ensure that related fields are also present.
if [[ -n "$_arg_optionalAuthenticationUsername" ]]; then
  # Ensure the password custom field is provided if an authentication username is specified.
  if [[ -z "$_arg_optionalAuthenticationPassCustomField" ]]; then
    _PRINT_HELP=yes die "[Error] Missing the optional authentication password field. In order to generate a secure token for the user '$_arg_usernameToAdd' you must either provide both an authentication username and password or specify neither to prompt the user." 1
  fi

  # Clean up the optional authentication username input by removing any leading/trailing whitespace.
  _arg_optionalAuthenticationUsername=$(echo "$_arg_optionalAuthenticationUsername" | xargs)

  # Ensure the authentication username is not empty after cleanup.
  if [[ -z "$_arg_optionalAuthenticationUsername" ]]; then
    _PRINT_HELP=yes die "[Error] An invalid optional authentication username was provided to create a secure token." 1
  fi

  # Check if the username exceeds the 20-character limit.
  if [[ "$_arg_optionalAuthenticationUsername" =~ .{21,} ]]; then
    _PRINT_HELP=yes die "[Error] An invalid optional authentication username of '$_arg_optionalAuthenticationUsername' was provided. Usernames cannot exceed 20 characters." 1
  fi

  # Ensure that the authentication username only contains valid characters (letters, numbers, symbols).
  if [[ "$_arg_optionalAuthenticationUsername" =~ [^a-zA-Z0-9._-] ]]; then
    _PRINT_HELP=yes die "[Error] An invalid optional authentication username of '$_arg_optionalAuthenticationUsername' was provided. Usernames can only contain letters, numbers, or one of these symbols '-_.'." 1
  fi

  # Ensure the authentication username does not start with a period.
  if [[ "$_arg_optionalAuthenticationUsername" =~ ^\. ]]; then
    _PRINT_HELP=yes die "[Error] An invalid optional authentication username of '$_arg_optionalAuthenticationUsername' was provided. Usernames cannot start with a '.' symbol." 1
  fi

  # Verify that the provided username exists on the system.
  if ! echo "$currentUsers" | grep -w "$_arg_optionalAuthenticationUsername" >/dev/null; then
    _PRINT_HELP=yes die "[Error] An invalid optional authentication username of '$_arg_optionalAuthenticationUsername' was provided. The admin account used to generate the secure token must already exist." 1
  fi

  # Ensure that the provided authentication username belongs to a user in the 'admin' group.
  if ! groups "$_arg_optionalAuthenticationUsername" | grep -o -w "admin" >/dev/null; then
    _PRINT_HELP=yes die "[Error] An invalid optional authentication username of '$_arg_optionalAuthenticationUsername' was provided. This account must be a member of the 'admin' group in order to generate a secure token." 1
  fi

  # Check if the authentication username already has a secure token enabled.
  if ! sysadminctl -secureTokenStatus "$_arg_optionalAuthenticationUsername" 2>&1 | grep -q "ENABLED"; then
    _PRINT_HELP=yes die "[Error] An invalid optional authentication username of '$_arg_optionalAuthenticationUsername' was provided. The account used to grant a secure token must already have a secure token." 1
  fi
fi

# Check if the optional authentication password custom field is provided.
if [[ -n "$_arg_optionalAuthenticationPassCustomField" ]]; then

  # Ensure that an optional authentication username is provided when the password custom field is specified.
  if [[ -z "$_arg_optionalAuthenticationUsername" ]]; then
    _PRINT_HELP=yes die "[Error] Missing optional authentication username. To generate a secure token for the user '$_arg_usernameToAdd', you must provide both an optional authentication username and password, or specify neither to prompt the user." 1
  fi

  # Clean up the password custom field input by removing leading/trailing whitespace.
  _arg_optionalAuthenticationPassCustomField=$(echo "$_arg_optionalAuthenticationPassCustomField" | xargs)

  # Ensure the password custom field is not empty after cleanup.
  if [[ -z "$_arg_optionalAuthenticationPassCustomField" ]]; then
    _PRINT_HELP=yes die "[Error] An invalid optional authentication password custom field was provided. Please provide the name of a valid secure custom field that contains the password." 1
  fi

  # Retrieve the password from the custom field using ninjarmm-cli and handle any errors.
  if ! output=$("$ninjarmmcliPath" get "$_arg_optionalAuthenticationPassCustomField" 2>&1); then
    _PRINT_HELP=yes die "[Error] $output" 1
  fi

  # Ensure that the retrieved password is not empty.
  if [[ -z "$output" ]]; then
    _PRINT_HELP=yes die "[Error] The optional authentication secure custom field '$_arg_optionalAuthenticationPassCustomField' is empty." 1
  else
    # Store the retrieved password for later use.
    _arg_optionalAuthenticationPassword=$output
  fi

  # Attempt to authenticate the user with the retrieved password.
  if ! dscl /Local/Default -authonly "$_arg_optionalAuthenticationUsername" "$_arg_optionalAuthenticationPassword"; then
    _PRINT_HELP=yes die "[Error] Failed to authenticate with the credentials provided for '$_arg_optionalAuthenticationUsername'. Please verify that they are valid and that the sign-in is not being blocked." 1
  fi
fi

# If the script is set to prompt the end user, ensure a user is signed in and get their details.
if [[ "$_arg_promptEndUser" == "on" ]]; then
  # Get the username of the user currently signed in at the console.
  signedInUser=$(stat -f%Su /dev/console)

  # Ensure that a user is currently signed in.
  if [[ -z "$signedInUser" ]]; then
    _PRINT_HELP=yes die "[Error] No user is currently signed in to prompt." 1
  fi

  # Get the user ID of the signed-in user.
  signedInUID=$(id -u "$signedInUser")

  # Ensure that the user ID could be retrieved.
  if [[ -z "$signedInUID" ]]; then
    _PRINT_HELP=yes die "[Error] Failed to get the user ID of '$signedInUser'." 1
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
  # Use the secure password generator function to create a password with the specified length and special characters.
  password=$(securePasswordGenerator --length "$_arg_passwordLength" --includeSpecialCharacters)

  # Increment the loop counter.
  i=$((i + 1))
done

# If a valid password cannot be generated after 1000 attempts, display an error message and exit.
if [[ $i -ge 999 ]]; then
  _PRINT_HELP=no die "[Error] Failed to generate a password that contains at least 1 special character, 1 capital letter, 1 lowercase letter, and 1 number. Please try again." 1
fi

# Attempt to save the generated password to the specified secure custom field.
# This field is used to store the password securely before proceeding with account creation.
echo "Attempting to save the generated password to the secure custom field '$_arg_passwordCustomField' before proceeding with account creation."
if ! output=$("$ninjarmmcliPath" set "$_arg_passwordCustomField" "$password" 2>&1); then
  _PRINT_HELP=no die "[Error] $output" 1
fi

# Confirm that the password was successfully saved to the secure custom field.
echo "Successfully saved the generated password to the secure custom field '$_arg_passwordCustomField'."

# Initialize the arguments for account creation.
# This includes adding the username, display name, and password.
accountCreationArgs=("-addUser" "$_arg_usernameToAdd" "-fullName" "$_arg_displayName" "-password" "$password")

# If the user should be added to the local admin group, append the "-admin" flag to the arguments.
if [[ "$_arg_addToLocalAdminGroup" == "on" ]]; then
  accountCreationArgs+=("-admin")
fi

# Determine whether the account will be created with a secure token based on provided input.
if [[ "$_arg_promptEndUser" == "on" || -n "$_arg_optionalAuthenticationUsername" ]]; then
  echo "Creating the account '$_arg_usernameToAdd' with a secure token."
else
  # Warn the user that creating an account without a secure token will limit its functionality with FileVault.
  echo "Creating the account '$_arg_usernameToAdd' without a secure token."
  echo "[Warning] This account will not be able to decrypt FileVault volumes (FDE). To avoid this in the future, provide the optional authentication account or prompt the end user."
  echo "[Warning] https://support.apple.com/guide/deployment/use-secure-and-bootstrap-tokens-dep24dbdcf9e/web"
fi

# If the end user should be prompted for admin credentials, add the "interactive" flag to the arguments.
if [[ "$_arg_promptEndUser" == "on" && -z "$_arg_optionalAuthenticationUsername" ]]; then
  echo "Prompting the end-user for the admin password."
  accountCreationArgs+=("interactive")
fi

# If an admin username and password are provided, include them in the account creation arguments.
if [[ -n "$_arg_optionalAuthenticationUsername" ]]; then
  echo "The admin password was provided, no prompt is necessary."
  accountCreationArgs+=("-adminUser" "$_arg_optionalAuthenticationUsername" "-adminPassword" "$_arg_optionalAuthenticationPassword")
fi

# Run the sysadminctl command to create the account based on the provided arguments.
# Use launchctl to run the command as the signed-in user if end-user prompting is enabled.
if [[ $_arg_promptEndUser != "on" ]]; then
  if ! sysadminctl "${accountCreationArgs[@]}"; then
    _PRINT_HELP=no die "[Error] Failed to create the account." 1
  fi
else
  if ! launchctl asuser "$signedInUID" sysadminctl "${accountCreationArgs[@]}"; then
    _PRINT_HELP=no die "[Error] Failed to create the account." 1
  fi
fi

# Verify that the account was successfully created by checking its presence in the /Users directory.
if ! dscl . list /Users | grep -o -w "$_arg_usernameToAdd" >/dev/null; then
  _PRINT_HELP=no die "[Error] Failed to find the account in /Users. Account creation failed." 1
else
  echo "Account creation was successful."
fi

# If an admin username or end-user prompting was used, check for secure token status.
if [[ -n "$_arg_optionalAuthenticationUsername" || "$_arg_promptEndUser" == "on" ]]; then
  # Check if the new account has a secure token enabled.
  if ! sysadminctl -secureTokenStatus "$_arg_usernameToAdd" 2>&1 | grep -q "ENABLED"; then
    exitCode=1
    echo ""

    # Display an error if the account does not have a secure token.
    echo "[Error] '$_arg_usernameToAdd' does not have a secure token. The user will not be able to unlock FileVault volumes (FDE)."
    if [[ -n "$_arg_optionalAuthenticationUsername" ]]; then
      echo "[Error] Verify that the optional authentication account information is valid and belongs to an admin with an existing secure token."
    elif [[ "$_arg_promptEndUser" == "on" ]]; then
      echo "[Error] Verify that the user prompted is an admin with an existing secure token."
    fi
    echo "[Error] https://support.apple.com/guide/deployment/use-secure-and-bootstrap-tokens-dep24dbdcf9e/web"
    echo ""
  fi
fi

# Exit the script if no password change is required and no enable date is set.
if [[ $_arg_requirePasswordChange != "on" && -z $_arg_dateAndTimeToEnable ]]; then
  exit $exitCode
fi

echo ""
# Retrieve the current password policy template for the newly created user.
echo "Retrieving password policy template for user '$_arg_usernameToAdd'."

# Define paths to store the primary and secondary password policy templates.
_policyTemplateFilePath="/tmp/PwPolicy.plist"
_policyTemplateFilePath2="/tmp/PwPolicy2.plist"

# Extract the current password policy from the user account and store it in the template file.
# If this operation fails, display an error and terminate the script.
if ! pwpolicy -u "$_arg_usernameToAdd" -getaccountpolicies | tail -n "+2" >"$_policyTemplateFilePath"; then
  _PRINT_HELP=no die "[Error] Failed to get the current password policy for the new user." 1
fi

# If the policy template is empty, create a basic template structure for authentication and password change policies.
if [[ ! -s "$_policyTemplateFilePath" ]]; then
  echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
  <key>policyCategoryAuthentication</key>
  <array>
  </array>
	<key>policyCategoryPasswordChange</key>
  <array>
  </array>
</dict>
</plist>" >"$_policyTemplateFilePath"
fi

# Read the current password policy from the template file into a variable for manipulation.
# This allows us to check for specific policy categories and modify them if necessary.
currentPolicy=$(defaults read "$_policyTemplateFilePath" 2>/dev/null)
echo "Template created."

# Check if the current policy includes the Authentication category.
# If it's missing, we will add it.
echo "Verifying that the template contains the Authentication category and adding an insertion point."
passwordAuthenticationKey=$(echo "$currentPolicy" | grep "policyCategoryAuthentication")
if [[ -z "$passwordAuthenticationKey" ]]; then
  # Add a placeholder for inserting the authentication category into the policy template.
  if ! sed -i '' '/<plist version="1.0">/a\
    <- dictionary line will be replaced ->' "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi

  # Define the structure for the Authentication category.
  newPasswordAuthenticationCategory="
  <key>policyCategoryAuthentication<\/key>
  <array>
  <\/array>"

  # Format the new authentication category to be added to the policy template.
  newPasswordAuthenticationCategory=$(echo "$newPasswordAuthenticationCategory" | tr '\n' '`')
  if ! sed -i '' "s/<- dictionary line will be replaced ->.*<dict.*/<- dictionary line will be replaced -><dict>$newPasswordAuthenticationCategory/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi

  # Convert the modified template back to its original format and replace the template file.
  if ! tr '`' '\n' <"$_policyTemplateFilePath" >"$_policyTemplateFilePath2"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi
  if ! mv -f "$_policyTemplateFilePath2" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi

  # Clean up by removing the placeholder once the category has been added.
  if ! sed -i '' "s/<- dictionary line will be replaced ->//g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi
fi

# Check if the current policy includes the Password Change category.
# If it's missing, add it to the policy template.
echo "Verifying that the template contains the Password Change category and adding an insertion point."
passwordChangeKey=$(echo "$currentPolicy" | grep "policyCategoryPasswordChange")
if [[ -z "$passwordChangeKey" ]]; then
  if ! sed -i '' '/<plist version="1.0">/a\
    <- dictionary line will be replaced ->' "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi

  # Define the structure for the Password Change category.
  newPasswordChangeCategory="
  <key>policyCategoryPasswordChange<\/key>
  <array>
  <\/array>"

  # Format the new Password Change category to be added to the policy template.
  newPasswordChangeCategory=$(echo "$newPasswordChangeCategory" | tr '\n' '`')
  if ! sed -i '' "s/<- dictionary line will be replaced ->.*<dict.*/<- dictionary line will be replaced -><dict>$newPasswordChangeCategory/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi

  # Convert the modified template back to its original format and replace the template file.
  if ! tr '`' '\n' <"$_policyTemplateFilePath" >"$_policyTemplateFilePath2"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi

  if ! mv -f "$_policyTemplateFilePath2" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi

  # Clean up by removing the placeholder once the Password Change category has been added.
  if ! sed -i '' "s/<- dictionary line will be replaced ->//g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi
fi

# Add insertion points for new password authentication and password change policies within the template.
if ! sed -i '' '/<key>policyCategoryAuthentication<\/key>/a\
  <- PasswordAuthentication line will be replaced ->' "$_policyTemplateFilePath"; then
  _PRINT_HELP=no die "[Error] Failed to add insertion point for new password authentication policies." 1
fi
if ! sed -i '' '/<key>policyCategoryPasswordChange<\/key>/a\
  <- PasswordChange line will be replaced ->' "$_policyTemplateFilePath"; then
  _PRINT_HELP=no die "[Error] Failed to add insertion point for new password change policies." 1
fi

# Ensure the Password Authentication category has both opening and closing array tags.
echo "Verifying that the Password Authentication category contains both opening and closing tags for the array."
passwordAuthenticationClosingArray=$(grep '<- PasswordAuthentication line will be replaced ->.*<array/>' "$_policyTemplateFilePath")

# If the closing tag for the Password Authentication array is missing, insert it.
if [[ -n $passwordAuthenticationClosingArray ]]; then
  if ! sed -i '' '/<- PasswordAuthentication line will be replaced ->/a\
  <\/array>' "$_policyTemplateFilePath"; then
    # Print an error message and exit if adding the closing tag fails.
    _PRINT_HELP=no die "[Error] Failed to add insertion point for new password authentication policies." 1
  fi

  # Correct the opening tag for the array if needed.
  if ! sed -i '' 's/<- PasswordAuthentication line will be replaced ->.*<array\/>/<- PasswordAuthentication line will be replaced -> <array>/g' "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to add insertion point for new password authentication policies." 1
  fi
fi

# Ensure the Password Change category has both opening and closing array tags.
echo "Verifying that the Password Change category contains both opening and closing tags for the array."
passwordChangeClosingArray=$(grep '<- PasswordChange line will be replaced ->.*<array/>' "$_policyTemplateFilePath")

# If the closing tag for the Password Change array is missing, insert it.
if [[ -n $passwordChangeClosingArray ]]; then
  if ! sed -i '' '/<- PasswordChange line will be replaced ->/a\
  <\/array>' "$_policyTemplateFilePath"; then
    # Print an error message and exit if adding the closing tag fails.
    _PRINT_HELP=no die "[Error] Failed to add insertion point for new password change policies." 1
  fi

  # Correct the opening tag for the array if needed.
  if ! sed -i '' 's/<- PasswordChange line will be replaced ->.*<array\/>/<- PasswordChange line will be replaced -> <array>/g' "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to add insertion point for new password change policies." 1
  fi
fi

# Enable the account after a specified date
if [[ -n "$_arg_dateAndTimeToEnable" ]]; then
  # Retrieve the current enable date from the policy, if present.
  currentEnableDate=$(echo "$currentPolicy" | grep "policyAttributeEnableOnDate" | grep -E -o '".*-.*"' | sed 's/"//g' | xargs)
fi

# If the enable date exists, attempt to update it to the new specified date.
if [[ -n "$_arg_dateAndTimeToEnable" && -n "$currentEnableDate" ]]; then
  echo "Attempting to change the password policy to enable the account after $currentEnableDate, updating it to $_arg_dateAndTimeToEnable."

  # Insert the new enable date into the policy template.
  if ! sed -i '' '/<key>policyAttributeEnableOnDate<\/key>/a\
    <- This date line will be replaced ->' "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to modify the enable date in the password policy." 1
  fi

  # Replace the placeholder with the actual new enable date.
  if ! sed -i '' "s/<- This date line will be replaced ->.*<date>.*<\/date>/<date>$_arg_dateAndTimeToEnableNSDate<\/date>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to modify the enable date in the password policy." 1
  fi

  echo "Successfully modified the password policy template."
elif [[ -n "$_arg_dateAndTimeToEnable" ]]; then
  # If no existing enable date is found, add a new policy for enabling the account after the specified date.
  echo "Attempting to set the password policy to enable the account '$_arg_usernameToAdd' after $_arg_dateAndTimeToEnable."

  # Define the new password enable policy to be inserted.
  new_passwordEnablePolicy="
<dict>
  <key>policyContent<\/key>
  <string>policyAttributeCurrentDate \&gt; policyAttributeEnableOnDate<\/string>
	<key>policyIdentifier<\/key>
	<string>Enable after date<\/string>
	<key>policyParameters<\/key>
	<dict>
		<key>policyAttributeEnableOnDate<\/key>
		<date>$_arg_dateAndTimeToEnableNSDate<\/date>
	<\/dict>
<\/dict>"

  # Format the new enable policy for insertion into the template.
  new_passwordEnablePolicy=$(echo "$new_passwordEnablePolicy" | tr '\n' '`')

  # Add the new enable policy to the Password Authentication section of the template.
  if ! sed -i '' "s/<- PasswordAuthentication line will be replaced ->.*<array>/<- PasswordAuthentication line will be replaced -><array>$new_passwordEnablePolicy/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to update the new password enable date." 1
  fi

  # Convert the modified template back to its original format and replace the file.
  if ! tr '`' '\n' <"$_policyTemplateFilePath" >"$_policyTemplateFilePath2"; then
    _PRINT_HELP=no die "[Error] Failed to update the new password enable date." 1
  fi

  if ! mv -f "$_policyTemplateFilePath2" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to update the new password enable date." 1
  fi

  echo "The new policy was successfully added to the password template."
fi

# Set the policy to require a password change at the next login.
if [[ "$_arg_requirePasswordChange" == "on" ]]; then
  # Retrieve the current password change time from the policy (if it exists) and convert it into a readable format.
  currentPasswordChangeTime=$(echo "$currentPolicy" | grep "policyAttributeNewPasswordRequiredTime" | grep -E -o '\d+' | head -n 1 | xargs)

  # If a current password change time exists, convert it into a human-readable date format.
  if [[ -n $currentPasswordChangeTime ]]; then
    currentPasswordChangeTimeDate=$(date -r "$currentPasswordChangeTime")
  fi

  # Set the new password change time as the current system time (in seconds since the epoch).
  passwordChangeTime=$(date "+%s")
  passwordChangeDate=$(date -r "$passwordChangeTime")
fi

# If the requirePasswordChange flag is on and the current password change time exists,
# update the policy to reflect the new required time for a password change.
if [[ "$_arg_requirePasswordChange" == "on" && -n "$currentPasswordChangeTime" ]]; then
  echo "Attempting to update the password policy from requiring a password change after $currentPasswordChangeTimeDate to after $passwordChangeDate."

  # Insert a placeholder in the policy template for the new password required time.
  if ! sed -i '' '/<key>policyAttributeNewPasswordRequiredTime<\/key>/a\
    <- This real line will be replaced ->' "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change the new password required time." 1
  fi

  # Replace the placeholder with the actual new password change time in the policy template.
  if ! sed -i '' "s/<- This real line will be replaced ->.*<real>.*<\/real>/<real>$passwordChangeTime<\/real>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change the new password required time." 1
  fi

  echo "Successfully modified the password policy template."
elif [[ "$_arg_requirePasswordChange" == "on" ]]; then
  # If no previous password change time exists, add a new policy that requires a password change after the new date.
  echo "Attempting to set the password policy to require a password change after $passwordChangeDate."

  # Define the structure for the new password change policy, specifying when a password must be changed.
  new_passwordChangePolicy="
<dict>
  <key>policyContent<\/key>
  <string>(policyAttributeLastPasswordChangeTime \&lt; policyAttributeNewPasswordRequiredTime) and (policyAttributeCurrentTime \&gt;= policyAttributeNewPasswordRequiredTime)<\/string>
	<key>policyIdentifier<\/key>
	<string>Must change password at next login<\/string>
	<key>policyParameters<\/key>
	<dict>
		<key>policyAttributeNewPasswordRequiredTime<\/key>
		<real>$passwordChangeTime<\/real>
	<\/dict>
<\/dict>"

  # Format the new password change policy for insertion into the policy template.
  new_passwordChangePolicy=$(echo "$new_passwordChangePolicy" | tr '\n' '`')

  # Insert the new password change policy into the Password Change section of the template.
  if ! sed -i '' "s/<- PasswordChange line will be replaced ->.*<array>/<- PasswordChange line will be replaced -><array>$new_passwordChangePolicy/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change the new password required time." 1
  fi

  # Convert the modified template back to its original format and replace the file.
  if ! tr '`' '\n' <"$_policyTemplateFilePath" >"$_policyTemplateFilePath2"; then
    _PRINT_HELP=no die "[Error] Failed to change the new password required time." 1
  fi

  if ! mv -f "$_policyTemplateFilePath2" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change the new password required time." 1
  fi

  echo "The new policy was successfully added to the password template."
fi

# Inform the user that the policy template is being cleaned up after modifications.
echo "Cleaning up policy template."

# Remove the placeholder for Password Authentication policies from the template.
if ! sed -i '' 's/<- PasswordAuthentication line will be replaced ->//g' "$_policyTemplateFilePath"; then
  _PRINT_HELP=no die "[Error] Failed to update the password policy." 1
fi

# Remove the placeholder for Password Change policies from the template.
if ! sed -i '' 's/<- PasswordChange line will be replaced ->//g' "$_policyTemplateFilePath"; then
  _PRINT_HELP=no die "[Error] Failed to update the password policy." 1
fi

# Check if the last two non-empty lines in the template file contain the closing <dict> tag.
finalDict=$(awk 'NF' "$_policyTemplateFilePath" | tail -n 2 | grep 'dict')

# If the <dict> closing tag is missing, add it before the closing </plist> tag
if [[ -z "$finalDict" ]]; then
  if ! sed -i '' 's/<\/plist>/<\/dict><\/plist>/g' "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to add closing dict tag to '$_policyTemplateFilePath'." 1
  fi
fi

# Attempt to apply the modified policy template to the account.
echo "Attempting to apply the policy template."
if ! pwpolicy -u "$_arg_usernameToAdd" -setaccountpolicies "$_policyTemplateFilePath"; then
  _PRINT_HELP=no die "[Error] Failed to update the password policy." 1
else
  echo "The policy template was successfully applied."
fi

echo ""
echo "Verifying that the password policy changes were applied by the template."

# Clean up by removing the temporary policy template file.
if [[ -f "$_policyTemplateFilePath" ]]; then
  rm "$_policyTemplateFilePath"
fi

# Retrieve the updated password policy to ensure the changes were applied.
if ! pwpolicy -u "$_arg_usernameToAdd" -getaccountpolicies | tail -n "+2" >"$_policyTemplateFilePath"; then
  _PRINT_HELP=no die "[Error] Failed to get the current password policy for the new user." 1
fi

# If the policy template is empty, print an error message.
if [[ ! -s "$_policyTemplateFilePath" ]]; then
  _PRINT_HELP=no die "[Error] The password policy is blank; failed to apply any changes." 1
fi

# Verify the new policy by reading it from the template file.
if ! newPolicy=$(defaults read "$_policyTemplateFilePath"); then
  _PRINT_HELP=no die "[Error] The password policy could not be read." 1
fi

# If a password change is required, check that the policy has the correct new password required time.
if [[ "$_arg_requirePasswordChange" == "on" ]]; then
  if ! echo "$newPolicy" | grep "policyAttributeNewPasswordRequiredTime" | grep -o "$passwordChangeTime" >/dev/null; then
    _PRINT_HELP=no die "[Error] Failed to require password to be changed at next login." 1
  else
    echo "Verified that the password change requirement is set."
  fi
fi

# If an enable date is specified, verify that it is correctly set in the policy.
if [[ -n "$_arg_dateAndTimeToEnable" ]]; then
  if ! enableDate=$(echo "$newPolicy" | grep "policyAttributeEnableOnDate" | grep -E -o '".*-.*"' | sed 's/"//g'); then
    _PRINT_HELP=no die "[Error] Failed to set enable date." 1
  else
    echo "Verified the enable date of '$enableDate' is set."
  fi
fi

# Clean up by removing the temporary policy template file.
echo ""
echo "Removing temporary policy template file."
if [[ -f "$_policyTemplateFilePath" ]]; then
  rm "$_policyTemplateFilePath"
fi

# Exit the script with the recorded exit code.
exit $exitCode




