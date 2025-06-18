# Sets the password policy for macOS devices.
#!/usr/bin/env bash
#
# Description: Sets the password policy for macOS devices.
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
# Preset Parameter: --minimumNumbersInPassword "replaceMeWithANumber"
#		Set the minimum number of numeric characters required in the password.
#
# Preset Parameter: --minimumLowercaseLetters "replaceMeWithANumber"
#		Define the minimum number of lowercase letters required.
#
# Preset Parameter: --minimumUppercaseLetters "replaceMeWithANumber"
#		Specify the minimum number of uppercase letters required.
#
# Preset Parameter: --minimumSpecialCharacters "replaceMeWithANumber"
#		Set the minimum number of special characters required.
#
# Preset Parameter: --passwordHistory "replaceMeWithANumber"
#		Define how many previous passwords must be remembered before reuse.
#
# Preset Parameter: --resetToDefaultPolicy
#		Reset the global password policy to the macOS default, which only requires a minimum of 4 characters.
#
# Preset Parameter: --help
#		Displays some help text.
#
# Release Notes: Initial Release

# Initialize variables for various password policy parameters with default values
_arg_maxLoginAttempts=
_arg_loginAttemptLockTime=
_arg_daysUntilPasswordExpiration=
_arg_minimumPasswordLength=
_arg_minimumNumbersInPassword=
_arg_minimumLowercaseLetters=
_arg_minimumUppercaseLetters=
_arg_minimumSpecialCharacters=
_arg_passwordHistory=
_arg_resetToDefaultPolicy="off"

# Function to display the help menu, outlining the usage and available parameters
print_help() {
  printf '\n\n%s\n\n' 'Usage: [--maxLoginAttempts|-a <arg>] [--loginAttemptLockTime|-t <arg>] [--daysUntilPasswordExpiration|-e <arg>] 
  [--minimumPasswordLength|-l <arg>] [--minimumNumbersInPassword|-n <arg>] [--minimumLowercaseLetters|-lc <arg>] 
  [--minimumUppercaseLetters|-uc <arg>] [--minimumSpecialCharacters|-sc <arg>] [--passwordHistory|-ph <arg>] 
  [--resetToDefaultPolicy|-d <arg>] [--help|-h]'
  printf '%s\n' 'Preset Parameter: --maxLoginAttempts "replaceMeWithANumber"'
  printf '\t%s\n' "Define how many incorrect password attempts are allowed before the device locks."
  printf '%s\n' 'Preset Parameter: --loginAttemptLockTime "replaceMeWithANumber"'
  printf '\t%s\n' "Set the lock duration (in minutes) after the maximum login attempts is reached. Max Login Attempts is required (if not previously set)."
  printf '%s\n' 'Preset Parameter: --daysUntilPasswordExpiration "replaceMeWithANumber"'
  printf '\t%s\n' "Specify how many days before a password expires."
  printf '%s\n' 'Preset Parameter: --minimumPasswordLength "replaceMeWithANumber"'
  printf '\t%s\n' "Define the minimum number of characters required for a password."
  printf '%s\n' 'Preset Parameter: --minimumNumbersInPassword "replaceMeWithANumber"'
  printf '\t%s\n' "Set the minimum number of numeric characters required in the password."
  printf '%s\n' 'Preset Parameter: --minimumLowercaseLetters "replaceMeWithANumber"'
  printf '\t%s\n' "Define the minimum number of lowercase letters required."
  printf '%s\n' 'Preset Parameter: --minimumUppercaseLetters "replaceMeWithANumber"'
  printf '\t%s\n' "Specify the minimum number of uppercase letters required."
  printf '%s\n' 'Preset Parameter: --minimumSpecialCharacters "replaceMeWithANumber"'
  printf '\t%s\n' "Set the minimum number of special characters required."
  printf '%s\n' 'Preset Parameter: --passwordHistory "replaceMeWithANumber"'
  printf '\t%s\n' "Define how many previous passwords must be remembered before reuse."
  printf '%s\n' 'Preset Parameter: --resetToDefaultPolicy'
  printf '\t%s\n' "Reset the global password policy to the macOS default, which only requires a minimum of 4 characters."
  printf '%s\n' 'Preset Parameter: --help'
  printf '\t%s\n' "Displays this help menu."
}

# Function to terminate the script with an error message and optional help display
die() {
  local _ret="${2:-1}"
  echo "$1" >&2
  test "${_PRINT_HELP:-no}" = yes && print_help >&2
  exit "${_ret}"
}

# Function to parse the command line arguments and assign values to corresponding variables
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
    --minimumNumbersInPassword | --minimumnumbersinpassword | --numbers | -n)
      test $# -lt 2 && die "[Error] Missing value for the optional argument '$_key'." 1
      _arg_minimumNumbersInPassword=$2
      shift
      ;;
    --minimumNumbersInPassword=*)
      _arg_minimumNumbersInPassword="${_key##--minimumNumbersInPassword=}"
      ;;
    --minimumLowercaseLetters | --minimumlowercaseletters | --lowercase | -lc)
      test $# -lt 2 && die "[Error] Missing value for the optional argument '$_key'." 1
      _arg_minimumLowercaseLetters=$2
      shift
      ;;
    --minimumLowercaseLetters=*)
      _arg_minimumLowercaseLetters="${_key##--minimumLowercaseLetters=}"
      ;;
    --minimumUppercaseLetters | --minimumuppercaseletters | --uppercase | -uc)
      test $# -lt 2 && die "[Error] Missing value for the optional argument '$_key'." 1
      _arg_minimumUppercaseLetters=$2
      shift
      ;;
    --minimumUppercaseLetters=*)
      _arg_minimumUppercaseLetters="${_key##--minimumUppercaseLetters=}"
      ;;
    --minimumSpecialCharacters | --minimumspecialcharacters | --specialcase | -sc)
      test $# -lt 2 && die "[Error] Missing value for the optional argument '$_key'." 1
      _arg_minimumSpecialCharacters=$2
      shift
      ;;
    --minimumSpecialCharacters=*)
      _arg_minimumSpecialCharacters="${_key##--minimumSpecialCharacters=}"
      ;;
    --passwordHistory | --passwordhistory | --history | -ph)
      test $# -lt 2 && die "[Error] Missing value for the optional argument '$_key'." 1
      _arg_passwordHistory=$2
      shift
      ;;
    --passwordHistory=*)
      _arg_passwordHistory="${_key##--passwordHistory=}"
      ;;
    --resetToDefaultPolicy | --defaultPolicy | -d)
      _arg_resetToDefaultPolicy="on"
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

# Execute command line parsing function with the passed arguments
parse_commandline "$@"

# If environment variables for the script parameters are set, override the command line argument values
if [[ -n $maxLoginAttempts ]]; then
  _arg_maxLoginAttempts="$maxLoginAttempts"
fi
if [[ -n $loginAttemptLockTime ]]; then
  _arg_loginAttemptLockTime="$loginAttemptLockTime"
fi
if [[ -n $daysUntilPasswordExpiration ]]; then
  _arg_daysUntilPasswordExpiration="$daysUntilPasswordExpiration"
fi
if [[ -n $minimumPasswordLength ]]; then
  _arg_minimumPasswordLength="$minimumPasswordLength"
fi
if [[ -n $minimumNumbersInPassword ]]; then
  _arg_minimumNumbersInPassword="$minimumNumbersInPassword"
fi
if [[ -n $minimumLowercaseLetters ]]; then
  _arg_minimumLowercaseLetters="$minimumLowercaseLetters"
fi
if [[ -n $minimumUppercaseLetters ]]; then
  _arg_minimumUppercaseLetters="$minimumUppercaseLetters"
fi
if [[ -n $minimumSpecialCharacters ]]; then
  _arg_minimumSpecialCharacters="$minimumSpecialCharacters"
fi
if [[ -n $passwordHistory ]]; then
  _arg_passwordHistory="$passwordHistory"
fi
if [[ -n $resetToDefaultPolicy && $resetToDefaultPolicy == "true" ]]; then
  _arg_resetToDefaultPolicy="on"
fi

# Check if the script is being run as root. If not, exit with an error message.
if [[ $(id -u) -ne 0 ]]; then
  _PRINT_HELP=no die "[Error] This script must be run with root permissions. Try running it with sudo or as the system/root user." 1
fi

# Ensure the user does not attempt to set both a custom policy and reset to default at the same time.
if [[ ( -n "$_arg_maxLoginAttempts" || -n "$_arg_loginAttemptLockTime" || -n "$_arg_daysUntilPasswordExpiration" || -n "$_arg_minimumPasswordLength" ||
  -n "$_arg_minimumNumbersInPassword" || -n "$_arg_minimumLowercaseLetters" || -n "$_arg_minimumUppercaseLetters" || -n "$_arg_minimumSpecialCharacters" ||
  -n "$_arg_passwordHistory" ) && "$_arg_resetToDefaultPolicy" == "on" ]]; then
  _PRINT_HELP=yes die "[Error] You cannot reset the policy back to the default policy and set a different policy at the same time." 1
fi

# Validate max login attempts. Ensure it is a positive integer greater than zero.
if [[ -n "$_arg_maxLoginAttempts" ]]; then
  _arg_maxLoginAttempts=$(echo "$_arg_maxLoginAttempts" | xargs)

  if [[ -z "$_arg_maxLoginAttempts" ]]; then
    _PRINT_HELP=yes die "[Error] An invalid number of max login attempts was given. Please specify a positive whole number that is greater than 0." 1
  fi
fi
if [[ "$_arg_maxLoginAttempts" =~ [^0-9] ]]; then
  _PRINT_HELP=yes die "[Error] An invalid value for max login attempts was given: '$_arg_maxLoginAttempts'. Please specify a positive whole number greater than 0." 1
fi
if [[ "$_arg_maxLoginAttempts" == 0 ]]; then
  _PRINT_HELP=yes die "[Error] An invalid value for max login attempts was given: '$_arg_maxLoginAttempts'. Please specify a positive whole number greater than 0." 1
fi

# Validate login attempt lock time. Ensure it is a positive integer greater than zero.
if [[ -n "$_arg_loginAttemptLockTime" ]]; then
  _arg_loginAttemptLockTime=$(echo "$_arg_loginAttemptLockTime" | xargs)

  if [[ -z "$_arg_loginAttemptLockTime" ]]; then
    _PRINT_HELP=yes die "[Error] An invalid lock time was given. Please specify a positive whole number that is greater than 0." 1
  fi
fi
if [[ "$_arg_loginAttemptLockTime" =~ [^0-9] ]]; then
  _PRINT_HELP=yes die "[Error] An invalid value for lock time was given: '$_arg_loginAttemptLockTime'. Please specify a positive whole number greater than 0." 1
fi
if [[ "$_arg_loginAttemptLockTime" == 0 ]]; then
  _PRINT_HELP=yes die "[Error] An invalid value for lock time was given: '$_arg_loginAttemptLockTime'. Please specify a positive whole number greater than 0." 1
fi

# Validate password expiration time. Ensure it is a positive whole number or zero for no expiration.
if [[ -n "$_arg_daysUntilPasswordExpiration" ]]; then
  _arg_daysUntilPasswordExpiration=$(echo "$_arg_daysUntilPasswordExpiration" | xargs)

  if [[ -z "$_arg_daysUntilPasswordExpiration" ]]; then
    _PRINT_HELP=yes die "[Error] An invalid expiration time was given. Please specify a positive whole number or '0' for no expiration." 1
  fi
fi
if [[ "$_arg_daysUntilPasswordExpiration" =~ [^0-9] ]]; then
  _PRINT_HELP=yes die "[Error] An invalid value for password expiration was given: '$_arg_daysUntilPasswordExpiration'. Please specify a positive whole number or '0' for no expiration." 1
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

# Validate the minimum number of digits. Ensure it is a positive whole number greater than zero.
if [[ -n "$_arg_minimumNumbersInPassword" ]]; then
  _arg_minimumNumbersInPassword=$(echo "$_arg_minimumNumbersInPassword" | xargs)

  if [[ -z "$_arg_minimumNumbersInPassword" ]]; then
    _PRINT_HELP=yes die "[Error] An invalid minimum number of numbers was given. Please specify a positive whole number that is greater than 0." 1
  fi
fi
if [[ "$_arg_minimumNumbersInPassword" =~ [^0-9] ]]; then
  _PRINT_HELP=yes die "[Error] An invalid value for the minimum number of digits was given: '$_arg_minimumNumbersInPassword'. Please specify a positive whole number greater than 0." 1
fi
if [[ "$_arg_minimumNumbersInPassword" == 0 ]]; then
  _PRINT_HELP=yes die "[Error] An invalid value for the minimum number of digits was given: '$_arg_minimumNumbersInPassword'. Please specify a positive whole number greater than 0." 1
fi

# Validate the minimum number of lowercase letters. Ensure it is a positive whole number greater than zero.
if [[ -n "$_arg_minimumLowercaseLetters" ]]; then
  _arg_minimumLowercaseLetters=$(echo "$_arg_minimumLowercaseLetters" | xargs)

  if [[ -z "$_arg_minimumLowercaseLetters" ]]; then
    _PRINT_HELP=yes die "[Error] An invalid minimum number of lowercase letters was given. Please specify a positive whole number that is greater than 0." 1
  fi
fi
if [[ "$_arg_minimumLowercaseLetters" =~ [^0-9] ]]; then
  _PRINT_HELP=yes die "[Error] An invalid value for the minimum number of lowercase letters was given: '$_arg_minimumLowercaseLetters'. Please specify a positive whole number greater than 0." 1
fi
if [[ "$_arg_minimumLowercaseLetters" == 0 ]]; then
  _PRINT_HELP=yes die "[Error] An invalid value for the minimum number of lowercase letters was given: '$_arg_minimumLowercaseLetters'. Please specify a positive whole number greater than 0." 1
fi

# Validate the minimum number of uppercase letters. Ensure it is a positive whole number greater than zero.
if [[ -n "$_arg_minimumUppercaseLetters" ]]; then
  _arg_minimumUppercaseLetters=$(echo "$_arg_minimumUppercaseLetters" | xargs)

  if [[ -z "$_arg_minimumUppercaseLetters" ]]; then
    _PRINT_HELP=yes die "[Error] An invalid minimum number of uppercase letters was given. Please specify a positive whole number that is greater than 0." 1
  fi
fi
if [[ "$_arg_minimumUppercaseLetters" =~ [^0-9] ]]; then
  _PRINT_HELP=yes die "[Error] An invalid minimum number of uppercase letters was given of '$_arg_minimumUppercaseLetters'. Please specify a positive whole number that is greater than 0." 1
fi
if [[ "$_arg_minimumUppercaseLetters" == 0 ]]; then
  _PRINT_HELP=yes die "[Error] An invalid minimum number of uppercase letters was given of '$_arg_minimumUppercaseLetters'. Please specify a positive whole number that is greater than 0." 1
fi

# Validate the minimum number of special characters. Ensure it is a positive whole number greater than zero.
if [[ -n "$_arg_minimumSpecialCharacters" ]]; then
  _arg_minimumSpecialCharacters=$(echo "$_arg_minimumSpecialCharacters" | xargs)

  if [[ -z "$_arg_minimumSpecialCharacters" ]]; then
    _PRINT_HELP=yes die "[Error] An invalid minimum number of special characters was given. Please specify a positive whole number that is greater than 0." 1
  fi
fi
if [[ "$_arg_minimumSpecialCharacters" =~ [^0-9] ]]; then
  _PRINT_HELP=yes die "[Error] An invalid value for the minimum number of special characters was given: '$_arg_minimumSpecialCharacters'. Please specify a positive whole number greater than 0." 1
fi
if [[ "$_arg_minimumSpecialCharacters" == 0 ]]; then
  _PRINT_HELP=yes die "[Error] An invalid value for the minimum number of special characters was given: '$_arg_minimumSpecialCharacters'. Please specify a positive whole number greater than 0." 1
fi

# Validate password history setting. Ensure it is a positive whole number greater than zero.
if [[ -n "$_arg_passwordHistory" ]]; then
  _arg_passwordHistory=$(echo "$_arg_passwordHistory" | xargs)

  if [[ -z "$_arg_passwordHistory" ]]; then
    _PRINT_HELP=yes die "[Error] An invalid number of passwords to remember was given. Please specify a positive whole number that is greater than 0." 1
  fi
fi
if [[ "$_arg_passwordHistory" =~ [^0-9] ]]; then
  _PRINT_HELP=yes die "[Error] An invalid value for the number of passwords to remember was given: '$_arg_passwordHistory'. Please specify a positive whole number greater than 0." 1
fi
if [[ "$_arg_passwordHistory" == 0 ]]; then
  _PRINT_HELP=yes die "[Error] An invalid value for the number of passwords to remember was given: '$_arg_passwordHistory'. Please specify a positive whole number greater than 0." 1
fi

# Ensure that at least one password policy is being set. If none are provided and the reset flag is off, throw an error.
if [[ -z "$_arg_maxLoginAttempts" && -z "$_arg_loginAttemptLockTime" && -z "$_arg_daysUntilPasswordExpiration" && -z "$_arg_minimumPasswordLength" &&
  -z "$_arg_minimumNumbersInPassword" && -z "$_arg_minimumLowercaseLetters" && -z "$_arg_minimumUppercaseLetters" && -z "$_arg_minimumSpecialCharacters" &&
  -z "$_arg_passwordHistory" && "$_arg_resetToDefaultPolicy" == "off" ]]; then
  _PRINT_HELP=yes die "[Error] You must specify the password policy you are trying to set." 1
fi

# Define paths for the primary and secondary policy template files.
_policyTemplateFilePath="/tmp/PwPolicy.plist"
_policyTemplateFilePath2="/tmp/PwPolicy2.plist"

# Reset To Default Policy
if [[ $_arg_resetToDefaultPolicy == "on" ]]; then
  # Notify that a default password policy file is being created.
  echo "Creating default password policy file."

  # Create an XML plist file that contains only the default password policy.
  echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
	<key>policyCategoryPasswordContent</key>
	<array>
		<dict>
			<key>policyContent</key>
			<string>policyAttributePassword matches '^$|.{4,}+'</string>
			<key>policyContentDescription</key>
			<dict>
				<key>ar</key>
				<string>Ø£Ø¯Ø®Ù„ ÙƒÙ„Ù…Ø© Ø³Ø± Ù„Ø§ ØªÙ‚Ù„ Ø¹Ù† Ø£Ø±Ø¨Ø¹Ø© Ø£Ø­Ø±Ù Ø£Ùˆ Ø±Ù…ÙˆØ²ØŒ Ø£Ùˆ Ø§ØªØ±Ùƒ Ø­Ù‚Ù„ ÙƒÙ„Ù…Ø© Ø§Ù„Ø³Ø± ÙØ§Ø±ØºÙ‹Ø§.</string>
				<key>ca</key>
				<string>Introdueix una contrasenya que tingui quatre carÃ cters o mÃ©s, o deixa el camp de la contrasenya en blanc.</string>
				<key>cs</key>
				<string>Zadejte heslo oÂ minimÃ¡lnÃ­ dÃ©lce ÄtyÅ™i znaky nebo nechte pole hesla prÃ¡zdnÃ©.</string>
				<key>da</key>
				<string>Skriv en adgangskode pÃ¥ mindst fire tegn, eller lad adgangskodefeltet vÃ¦re tomt.</string>
				<key>de</key>
				<string>Gib ein Passwort ein, das aus mindestens vier Zeichen besteht, oder lass das Passwortfeld leer.</string>
				<key>el</key>
				<string>Î•Î¹ÏƒÎ±Î³Î¬Î³ÎµÏ„Îµ Î­Î½Î± ÏƒÏ…Î½Î¸Î·Î¼Î±Ï„Î¹ÎºÏŒ Ï€Î¿Ï… Î½Î± Î±Ï€Î¿Ï„ÎµÎ»ÎµÎ¯Ï„Î±Î¹ Î±Ï€ÏŒ Ï„Î­ÏƒÏƒÎµÏÎ¹Ï‚ Î® Ï€ÎµÏÎ¹ÏƒÏƒÏŒÏ„ÎµÏÎ¿Ï…Ï‚ Ï‡Î±ÏÎ±ÎºÏ„Î®ÏÎµÏ‚, Î® Î±Ï†Î®ÏƒÏ„Îµ Ï„Î¿ Ï€ÎµÎ´Î¯Î¿ Ï„Î¿Ï… ÏƒÏ…Î½Î¸Î·Î¼Î±Ï„Î¹ÎºÎ¿Ï ÎºÎµÎ½ÏŒ.</string>
				<key>en</key>
				<string>Enter a password that is four characters or more or leave the password field blank.</string>
				<key>en_AU</key>
				<string>Enter a password that is four characters or more or leave the password field blank.</string>
				<key>en_GB</key>
				<string>Enter a password that is four characters or more or leave the password field blank.</string>
				<key>es</key>
				<string>Introduce una contraseÃ±a que tenga cuatro caracteres como mÃ­nimo o deja el campo de la contraseÃ±a en blanco.</string>
				<key>es_419</key>
				<string>Ingresa una contraseÃ±a de cuatro o mÃ¡s caracteres, o deja el campo de contraseÃ±a en blanco.</string>
				<key>fi</key>
				<string>Kirjoita salasana, jossa on vÃ¤hintÃ¤Ã¤n neljÃ¤ merkkiÃ¤, tai jÃ¤tÃ¤ salasanakenttÃ¤ tyhjÃ¤ksi.</string>
				<key>fr</key>
				<string>Saisissez un mot de passe comportant au moins quatre caractÃ¨res ou laissez le champ vide.</string>
				<key>fr_CA</key>
				<string>Saisissez un mot de passe comportant au moins quatre caractÃ¨res ou laissez le champ vide.</string>
				<key>he</key>
				<string>×™×© ×œ×”×–×™×Ÿ ×¡×™×¡×ž×” ×‘×ª ××¨×‘×¢×” ×ª×•×•×™× ×œ×¤×—×•×ª ××• ×œ×”×©××™×¨ ××ª ×©×“×” ×”×¡×™×¡×ž×” ×¨×™×§.</string>
				<key>hi</key>
				<string>à¤šà¤¾à¤° à¤µà¤°à¥à¤£ à¤¯à¤¾ à¤‰à¤¸à¤¸à¥‡ à¤¬à¤¡à¤¼à¤¾ à¤ªà¤¾à¤¸à¤µà¤°à¥à¤¡ à¤¦à¤°à¥à¤œ à¤•à¤°à¥‡à¤‚ à¤¯à¤¾ à¤ªà¤¾à¤¸à¤µà¤°à¥à¤¡ à¤«à¤¼à¥€à¤²à¥à¤¡ à¤–à¤¼à¤¾à¤²à¥€ à¤›à¥‹à¤¡à¤¼ à¤¦à¥‡à¤‚à¥¤</string>
				<key>hr</key>
				<string>Unesite lozinku koja sadrÅ¾i minimalno Äetiri znaka ili polje lozinke ostavite prazno.</string>
				<key>hu</key>
				<string>Adjon meg egy legalÃ¡bb nÃ©gy karakterbÅ‘l Ã¡llÃ³ jelszÃ³t, vagy hagyja Ã¼resen a jelszÃ³mezÅ‘t.</string>
				<key>id</key>
				<string>Masukkan kata sandi yang terdiri dari empat karakter atau lebih atau kosongkan bidang kata sandi.</string>
				<key>it</key>
				<string>Inserisci una password di quattro o piÃ¹ caratteri o lascia vuoto il campo password.</string>
				<key>ja</key>
				<string>4æ–‡å­—ä»¥ä¸Šã®ãƒ‘ã‚¹ãƒ¯ãƒ¼ãƒ‰ã‚’å…¥åŠ›ã™ã‚‹ã‹ã€ãƒ‘ã‚¹ãƒ¯ãƒ¼ãƒ‰ãƒ•ã‚£ãƒ¼ãƒ«ãƒ‰ã‚’ç©ºã®ã¾ã¾ã«ã—ã¦ãã ã•ã„ã€‚</string>
				<key>ko</key>
				<string>4ìž ì´ìƒì˜ ì•”í˜¸ë¥¼ ìž…ë ¥í•˜ê±°ë‚˜ ì•”í˜¸ í•„ë“œë¥¼ ë¹„ì›Œë‘ì‹­ì‹œì˜¤.</string>
				<key>ms</key>
				<string>Masukkan kata laluan sepanjang empat aksara atau lebih atau biarkan medan kata laluan kosong.</string>
				<key>nl</key>
				<string>Voer een wachtwoord van vier of meer tekens in of laat het wachtwoordveld leeg.</string>
				<key>no</key>
				<string>Angi et passord pÃ¥ minst fire tegn, eller la passordfeltet stÃ¥ tomt.</string>
				<key>pl</key>
				<string>Podaj hasÅ‚o skÅ‚adajÄ…ce siÄ™ zÂ co najmniej czterech znakÃ³w lub zostaw puste pole.</string>
				<key>pt_BR</key>
				<string>Digite uma senha com ao menos quatro caracteres ou deixe o campo de senha em branco.</string>
				<key>pt_PT</key>
				<string>Digite uma palavraâ€‘passe com pelo menos quatro caracteres, ou deixe o campo da palavraâ€‘passe em branco.</string>
				<key>ro</key>
				<string>IntroduceÈ›i o parolÄƒ de minimum patru caractere sau lÄƒsaÈ›i gol cÃ¢mpul pentru parolÄƒ.</string>
				<key>ru</key>
				<string>Ð’Ð²ÐµÐ´Ð¸Ñ‚Ðµ Ð¿Ð°Ñ€Ð¾Ð»ÑŒ, ÑÐ¾ÑÑ‚Ð¾ÑÑ‰Ð¸Ð¹ Ð¸Ð· Ñ‡ÐµÑ‚Ñ‹Ñ€ÐµÑ… Ð¸Ð»Ð¸ Ð±Ð¾Ð»ÐµÐµ ÑÐ¸Ð¼Ð²Ð¾Ð»Ð¾Ð², Ð»Ð¸Ð±Ð¾ Ð¾ÑÑ‚Ð°Ð²ÑŒÑ‚Ðµ Ð¿Ð¾Ð»Ðµ Ð¿Ð°Ñ€Ð¾Ð»Ñ Ð¿ÑƒÑÑ‚Ñ‹Ð¼.</string>
				<key>sk</key>
				<string>Zadajte heslo obsahujÃºce najmenej Å¡tyri znaky alebo nechajte pole pre heslo prÃ¡zdne.</string>
				<key>sv</key>
				<string>Ange ett lÃ¶senord som Ã¤r minst fyra tecken lÃ¥ngt eller lÃ¥t lÃ¶senordsfÃ¤ltet vara tomt.</string>
				<key>th</key>
				<string>à¸›à¹‰à¸­à¸™à¸£à¸«à¸±à¸ªà¸œà¹ˆà¸²à¸™à¸—à¸µà¹ˆà¸¡à¸µà¸­à¸±à¸à¸‚à¸£à¸°à¸­à¸¢à¹ˆà¸²à¸‡à¸™à¹‰à¸­à¸¢à¸ªà¸µà¹ˆà¸•à¸±à¸§à¸«à¸£à¸·à¸­à¹€à¸§à¹‰à¸™à¸Šà¹ˆà¸­à¸‡à¸£à¸«à¸±à¸ªà¸œà¹ˆà¸²à¸™à¹„à¸§à¹‰</string>
				<key>tr</key>
				<string>En az dÃ¶rt karakter uzunluÄŸunda bir parola girin veya parola alanÄ±nÄ± boÅŸ bÄ±rakÄ±n.</string>
				<key>uk</key>
				<string>Ð’Ð²ÐµÐ´Ñ–Ñ‚ÑŒ Ð¿Ð°Ñ€Ð¾Ð»ÑŒ Ð·Ñ– Ñ‰Ð¾Ð½Ð°Ð¹Ð¼ÐµÐ½ÑˆÐµ Ñ‡Ð¾Ñ‚Ð¸Ñ€ÑŒÐ¾Ñ… ÑÐ¸Ð¼Ð²Ð¾Ð»Ñ–Ð² Ð°Ð±Ð¾ Ð·Ð°Ð»Ð¸ÑˆÑ‚Ðµ Ð¿Ð¾Ð»Ðµ Ð¿Ð°Ñ€Ð¾Ð»Ñ Ð¿ÑƒÑÑ‚Ð¸Ð¼.</string>
				<key>vi</key>
				<string>Nháº­p máº­t kháº©u dÃ i 4 kÃ½ tá»± trá»Ÿ lÃªn hoáº·c Ä‘á»ƒ trá»‘ng trÆ°á»ng máº­t kháº©u.</string>
				<key>zh_CN</key>
				<string>è¾“å…¥ä¸å°‘äºŽ4ä¸ªå­—ç¬¦çš„å¯†ç ï¼Œæˆ–å°†å¯†ç æ ç•™ç©ºã€‚</string>
				<key>zh_HK</key>
				<string>è¼¸å…¥ä¸€å€‹å››ä½æˆ–æ›´å¤šå­—å…ƒçš„å¯†ç¢¼ï¼Œæˆ–ç•™ç©ºå¯†ç¢¼æ¬„ä½ã€‚</string>
				<key>zh_TW</key>
				<string>è¼¸å…¥4å€‹å­—å…ƒæˆ–æ›´é•·çš„å¯†ç¢¼ï¼Œæˆ–å°‡å¯†ç¢¼æ¬„ä½ç•™ç©ºã€‚</string>
			</dict>
			<key>policyIdentifier</key>
			<string>com.apple.defaultpasswordpolicy</string>
		</dict>
	</array>
</dict>
</plist>" >"$_policyTemplateFilePath"

  # Attempt to apply the newly created password policy template.
  # If the policy application fails, print an error and exit with a failure code.
  echo "Attempting to apply the policy template."
  if ! pwpolicy -setaccountpolicies "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to update the password policy." 1
  else
    echo "Successfully applied the default policy."
    exit 0
  fi
fi

# Display a message indicating that the password policy template is being created using the current policy.
echo "Creating password policy template using current password policy."

# Extract the current password policy and store it in the specified template file.
# If extraction fails, print an error and exit.
if ! pwpolicy -getaccountpolicies | tail -n "+2" >"$_policyTemplateFilePath"; then
  _PRINT_HELP=no die "[Error] Failed to get current password policy." 1
fi

# Read the current policy into a variable for further manipulation.
currentPolicy=$(defaults read "$_policyTemplateFilePath" 2>/dev/null)

# Extract the maximum failed login attempts from the current policy, if it exists.
currentMaxLoginAttempts=$(echo "$currentPolicy" | grep "policyAttributeMaximumFailedAuthentications" | grep -E -o '\d+')

# If lock time is set but max login attempts are not set in either argument or the current policy, show an error.
if [[ -n "$_arg_loginAttemptLockTime" && -z "$_arg_maxLoginAttempts" && -z $currentMaxLoginAttempts ]]; then
  _PRINT_HELP=no die "[Error] Max login attempts are not currently set. Unable to set the login attempt lock time without the max login attempts being set." 1
fi

# Notify that the template creation process has been completed.
echo "Template created."
echo ""

# Check if the current policy includes an authentication category and add it if missing.
echo "Verifying template contains Authentication category and adding insertion point."
passwordAuthenticationKey=$(echo "$currentPolicy" | grep "policyCategoryAuthentication")
if [[ -z "$passwordAuthenticationKey" ]]; then
  # Add a placeholder to the policy template for inserting the authentication category.
  if ! sed -i '' '/<plist version="1.0">/a\
    <- dictionary line will be replaced ->' "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi

  # Define the structure for the authentication category
  newPasswordAuthenticationCategory="
  <key>policyCategoryAuthentication<\/key>
  <array>
  <\/array>"

  # Format the new category into the template file.
  newPasswordAuthenticationCategory=$(echo "$newPasswordAuthenticationCategory" | tr '\n' '`')
  if ! sed -i '' "s/<- dictionary line will be replaced ->.*<dict.*/<- dictionary line will be replaced -><dict>$newPasswordAuthenticationCategory/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi

  # Convert back to newline-separated format, move the new file into place, and clean up.
  if ! tr '`' '\n' <"$_policyTemplateFilePath" >"$_policyTemplateFilePath2"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi
  if ! mv -f "$_policyTemplateFilePath2" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi
  if ! sed -i '' "s/<- dictionary line will be replaced ->//g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi
fi

# Check if the policy contains a password content category and add it if missing.
echo "Verifying template contains Password Content category and adding insertion point."
passwordContentKey=$(echo "$currentPolicy" | grep "policyCategoryPasswordContent")
if [[ -z "$passwordContentKey" ]]; then
  # Add a placeholder to the policy template for inserting the content category.
  if ! sed -i '' '/<plist version="1.0">/a\
    <- dictionary line will be replaced ->' "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi

  # Define the structure for the content category
  newPasswordContentCategory="
  <key>policyCategoryPasswordContent<\/key>
  <array>
  <\/array>"

  # Format the new category into the template file.
  newPasswordContentCategory=$(echo "$newPasswordContentCategory" | tr '\n' '`')
  if ! sed -i '' "s/<- dictionary line will be replaced ->.*<dict.*/<- dictionary line will be replaced -><dict>$newPasswordContentCategory/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi

  # Convert back to newline-separated format, move the new file into place, and clean up.
  if ! tr '`' '\n' <"$_policyTemplateFilePath" >"$_policyTemplateFilePath2"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi
  if ! mv -f "$_policyTemplateFilePath2" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi
  if ! sed -i '' "s/<- dictionary line will be replaced ->//g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi
fi

# Check if the policy contains a password change category and add it if missing.
echo "Verifying template contains Password Change category and adding insertion point."
passwordChangeKey=$(echo "$currentPolicy" | grep "policyCategoryPasswordChange")
if [[ -z "$passwordChangeKey" ]]; then
  if ! sed -i '' '/<plist version="1.0">/a\
    <- dictionary line will be replaced ->' "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi

  # Define the structure for the change category
  newPasswordChangeCategory="
  <key>policyCategoryPasswordChange<\/key>
  <array>
  <\/array>"

  # Format the new category into the template file.
  newPasswordChangeCategory=$(echo "$newPasswordChangeCategory" | tr '\n' '`')
  if ! sed -i '' "s/<- dictionary line will be replaced ->.*<dict.*/<- dictionary line will be replaced -><dict>$newPasswordChangeCategory/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi

  # Convert back to newline-separated format, move the new file into place, and clean up.
  if ! tr '`' '\n' <"$_policyTemplateFilePath" >"$_policyTemplateFilePath2"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi
  if ! mv -f "$_policyTemplateFilePath2" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi
  if ! sed -i '' "s/<- dictionary line will be replaced ->//g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password policy." 1
  fi
fi

# Add placeholders for inserting new password policies.
if ! sed -i '' '/<key>policyCategoryAuthentication<\/key>/a\
  <- PasswordAuthentication line will be replaced ->' "$_policyTemplateFilePath"; then
  _PRINT_HELP=no die "[Error] Failed to add insertion point for new password authentication policies." 1
fi
if ! sed -i '' '/<key>policyCategoryPasswordContent<\/key>/a\
  <- PasswordContent line will be replaced ->' "$_policyTemplateFilePath"; then
  _PRINT_HELP=no die "[Error] Failed to add insertion point for new password content policies." 1
fi
if ! sed -i '' '/<key>policyCategoryPasswordChange<\/key>/a\
  <- PasswordChange line will be replaced ->' "$_policyTemplateFilePath"; then
  _PRINT_HELP=no die "[Error] Failed to add insertion point for new password change policies." 1
fi

# Verify if the Password Authentication category contains both opening and closing tags for the array.
echo "Verifying Password Authentication category contains both opening and closing tag for the array."
passwordAuthenticationClosingArray=$(grep '<- PasswordAuthentication line will be replaced ->.*<array/>' "$_policyTemplateFilePath")

# If the closing tag for the Password Authentication array is missing, add it.
if [[ -n $passwordAuthenticationClosingArray ]]; then
  if ! sed -i '' '/<- PasswordAuthentication line will be replaced ->/a\
  <\/array>' "$_policyTemplateFilePath"; then
    # Print an error message and exit if adding the closing tag fails.
    _PRINT_HELP=no die "[Error] Failed to add insertion point for new password authentication policies." 1
  fi

  # Correct the opening tag for the array if necessary.
  if ! sed -i '' 's/<- PasswordAuthentication line will be replaced ->.*<array\/>/<- PasswordAuthentication line will be replaced -> <array>/g' "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to add insertion point for new password authentication policies." 1
  fi
fi

# Verify if the Password Content category contains both opening and closing tags for the array.
echo "Verifying Password Content category contains both opening and closing tags for the array."
passwordContentClosingArray=$(grep '<- PasswordContent line will be replaced ->.*<array/>' "$_policyTemplateFilePath")

# If the closing tag for the Password Content array is missing, add it.
if [[ -n $passwordContentClosingArray ]]; then
  if ! sed -i '' '/<- PasswordContent line will be replaced ->/a\
  <\/array>' "$_policyTemplateFilePath"; then
    # Print an error message and exit if adding the closing tag fails.
    _PRINT_HELP=no die "[Error] Failed to add insertion point for new password content policies." 1
  fi

  # Correct the opening tag for the array if necessary.
  if ! sed -i '' 's/<- PasswordContent line will be replaced ->.*<array\/>/<- PasswordContent line will be replaced -> <array>/g' "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to add insertion point for new password content policies." 1
  fi
fi

# Verify if the Password Change category contains both opening and closing tags for the array.
echo "Verifying Password Change category contains opening and closing tags for the array."
echo ""
passwordChangeClosingArray=$(grep '<- PasswordChange line will be replaced ->.*<array/>' "$_policyTemplateFilePath")

# If the closing tag for the Password Change array is missing, add it.
if [[ -n $passwordChangeClosingArray ]]; then
  if ! sed -i '' '/<- PasswordChange line will be replaced ->/a\
  <\/array>' "$_policyTemplateFilePath"; then
    # Print an error message and exit if adding the closing tag fails.
    _PRINT_HELP=no die "[Error] Failed to add insertion point for new password change policies." 1
  fi

  # Correct the opening tag for the array if necessary.
  if ! sed -i '' 's/<- PasswordChange line will be replaced ->.*<array\/>/<- PasswordChange line will be replaced -> <array>/g' "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to add insertion point for new password change policies." 1
  fi
fi

# Max Login Attempts
if [[ -n "$_arg_maxLoginAttempts" && "$currentMaxLoginAttempts" == "$_arg_maxLoginAttempts" ]]; then
  echo "The password policy is already set to only allow $_arg_maxLoginAttempts failed attempts."
  echo ""

# If the maximum login attempts is set but does not match the current value, modify the policy.
elif [[ -n "$_arg_maxLoginAttempts" && -n "$currentMaxLoginAttempts" ]]; then
  echo "Attempting to change the password policy template from allowing $currentMaxLoginAttempts failed attempts to $_arg_maxLoginAttempts."

  # Update the password policy template with the current maximum failed login attempts.
  if ! sed -i '' "s/<string>[0-9]* max login attempts<\/string>/<string>$currentMaxLoginAttempts max login attempts<\/string>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change failed login attempt policy." 1
  fi

  # Add a placeholder for the new maximum failed authentications setting.
  if ! sed -i '' '/<key>policyAttributeMaximumFailedAuthentications<\/key>/a\
    <- This integer line will be replaced ->' "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change failed login attempt policy." 1
  fi

  # Replace the placeholder with the new maximum login attempts value.
  if ! sed -i '' "s/<- This integer line will be replaced ->.*<integer>.*<\/integer>/<integer>$_arg_maxLoginAttempts<\/integer>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change failed login attempt policy." 1
  fi
  echo "Successfully modified the password policy template."
  echo ""
# If there is no current maximum login attempts policy, add a new one.
elif [[ -n "$_arg_maxLoginAttempts" ]]; then
  echo "Attempting to set the password policy template to not allow more than $_arg_maxLoginAttempts failed attempts."

  # Create a new policy block for failed login attempts.
  new_passwordAttemptPolicy="
<dict>
  <key>policyContent<\/key>
  <string>(policyAttributeFailedAuthentications \&lt; policyAttributeMaximumFailedAuthentications)<\/string>
  <key>policyIdentifier<\/key>
	<string>$_arg_maxLoginAttempts max login attempts<\/string>
  <key>policyParameters<\/key>
  <dict>
    <key>policyAttributeMaximumFailedAuthentications<\/key>
    <integer>$_arg_maxLoginAttempts<\/integer>
  <\/dict>
<\/dict>"

  # Replace the placeholder with the new failed login attempts policy.
  new_passwordAttemptPolicy=$(echo "$new_passwordAttemptPolicy" | tr '\n' '`')
  if ! sed -i '' "s/<- PasswordAuthentication line will be replaced ->.*<.*array.*>/<- PasswordAuthentication line will be replaced -><array>$new_passwordAttemptPolicy/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to add new failed password attempt policy." 1
  fi

  # Process the template by replacing backticks with newlines.
  if ! tr '`' '\n' <"$_policyTemplateFilePath" >"$_policyTemplateFilePath2"; then
    _PRINT_HELP=no die "[Error] Failed to add new failed password attempt policy." 1
  fi

  # Move the modified template to the original path.
  if ! mv -f "$_policyTemplateFilePath2" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to add new failed password attempt policy." 1
  fi

  echo "Successfully added the new password policy to the template."
  echo ""
fi

# Login Attempt Lock Time
if [[ -n "$_arg_loginAttemptLockTime" ]]; then
  # Extract the current lock time from the policy in seconds.
  currentLoginAttemptLockTime=$(echo "$currentPolicy" | grep "autoEnableInSeconds" | grep -E -o '\d+')

  # Convert the current lock time from seconds to minutes.
  if [[ -n $currentLoginAttemptLockTime ]]; then
    currentLoginAttemptLockTime=$((currentLoginAttemptLockTime / 60))
  fi
fi

# If the current lock time matches the provided lock time argument, no changes are needed.
if [[ -n "$_arg_loginAttemptLockTime" && $currentLoginAttemptLockTime == "$_arg_loginAttemptLockTime" ]]; then
  echo "The failed attempt lock time is already set to $_arg_loginAttemptLockTime minutes."
  echo ""

# If a lock time argument is provided, but the current lock time is different or not set, modify the policy.
elif [[ -n "$_arg_loginAttemptLockTime" && -n "$currentLoginAttemptLockTime" ]]; then
  echo "Attempting to change the failed login attempt lock time from $currentLoginAttemptLockTime to $_arg_loginAttemptLockTime minutes."

  # Convert the new lock time from minutes to seconds.
  _arg_loginAttemptLockTime=$((_arg_loginAttemptLockTime * 60))

  # Add a placeholder for the new autoEnableInSeconds value in the policy template.
  if ! sed -i '' '/<key>autoEnableInSeconds<\/key>/a\
    <- This integer line will be replaced ->' "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password lock time." 1
  fi

  # Replace the placeholder with the new lock time value in seconds.
  if ! sed -i '' "s/<- This integer line will be replaced ->.*<integer>.*<\/integer>/<integer>$_arg_loginAttemptLockTime<\/integer>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password lock time." 1
  fi

  echo "Successfully modified the password policy template."
  echo ""

# If there is no current lock time, set a new failed attempt lock time in the policy.
elif [[ -n "$_arg_loginAttemptLockTime" ]]; then
  echo "Attempting to set the failed password attempt lock time to $_arg_loginAttemptLockTime minutes."

  # Convert the lock time from minutes to seconds for the policy.
  _arg_loginAttemptLockTime=$((_arg_loginAttemptLockTime * 60))

  # Modify the policy's string to include the new lock time condition.
  if ! sed -i '' "s/<string>(policyAttributeFailedAuthentications \&lt; policyAttributeMaximumFailedAuthentications).*<\/string>/<string>(policyAttributeFailedAuthentications \&lt; policyAttributeMaximumFailedAuthentications) OR (policyAttributeCurrentTime \&gt; (policyAttributeLastFailedAuthenticationTime + autoEnableInSeconds))<\/string>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password lock time." 1
  fi

  # Prepare a new policy block with the updated lockout time in seconds.
  new_passwordLockoutTime="<key>autoEnableInSeconds<\/key>
<integer>$_arg_loginAttemptLockTime<\/integer>"
  new_passwordLockoutTime=$(echo "$new_passwordLockoutTime" | tr '\n' '`')

  # Insert the new lockout time into the policy template.
  if ! sed -i '' "s/<key>policyAttributeMaximumFailedAuthentications<\/key>/$new_passwordLockoutTime$()<key>policyAttributeMaximumFailedAuthentications<\/key>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password lock time." 1
  fi

  # Convert the processed backticks into newlines and create a temporary file.
  if ! tr '`' '\n' <"$_policyTemplateFilePath" >"$_policyTemplateFilePath2"; then
    _PRINT_HELP=no die "[Error] Failed to change password lock time." 1
  fi

  # Replace the original policy template with the modified version.
  if ! mv -f "$_policyTemplateFilePath2" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password lock time." 1
  fi

  echo "Successfully added the new password policy to the template."
  echo ""
fi

# Days Until Password Expiration
if [[ -n "$_arg_daysUntilPasswordExpiration" ]]; then

  # Extract the current password expiration setting from the policy
  currentPasswordExpiration=$(echo "$currentPolicy" | grep "policyAttributeExpiresEveryNDays" | tail -n 1 | grep -E -o '\d+')

  # If the argument is set to 0 (never expire) and no expiration policy exists, notify the user
  if [[ "$_arg_daysUntilPasswordExpiration" == 0 && -z "$currentPasswordExpiration" ]]; then
    echo "The passwords are already set to never expire."
  fi

  # If the argument is set to 0 (never expire) and an expiration policy exists, attempt to remove it
  if [[ "$_arg_daysUntilPasswordExpiration" == 0 && -n "$currentPasswordExpiration" ]]; then
    echo "Attempting to remove password expiration policy so that passwords never expire."

    # Use awk to find and mark the section of the policy that deals with password expiration for deletion
    awk '
    /<string>policyAttributeCurrentTime &gt; policyAttributeLastPasswordChangeTime \+ \(policyAttributeExpiresEveryNDays \* 24 \* 60 \* 60\)<\/string>/ && !appended {
        print two_lines_ago "<- This opening dict will be deleted ->"
        print one_line_ago
        print $0
        appended = 1
        next
    }
    NR > 2 {
        print two_lines_ago
    }
    {
        two_lines_ago = one_line_ago
        one_line_ago = $0
    }
    END {
        if (NR > 1) print one_line_ago
        if (NR > 0) print $0
    }
' "$_policyTemplateFilePath" >"$_policyTemplateFilePath2"

    # Ensure the plist file ends with the correct closing tag
    if ! grep "</plist>" "$_policyTemplateFilePath2"; then
      echo "</plist>" >>"$_policyTemplateFilePath2"
    fi

    # Mark the closing part of the expiration policy for deletion using sed
    if ! sed -i '' '/<key>policyAttributeExpiresEveryNDays<\/key>/{n; n; n; s/$/ <- This closing dict will be deleted ->/;}' "$_policyTemplateFilePath2"; then
      _PRINT_HELP=no die "[Error] Failed to remove password expiration policy." 1
    fi

    # Remove the marked sections from the policy using awk
    if ! awk '/<dict><- This opening dict will be deleted ->/{inblock=1} /<\/dict>.*<- This closing dict will be deleted ->/{inblock=0; next} !inblock {print}' "$_policyTemplateFilePath2" >"$_policyTemplateFilePath"; then
      _PRINT_HELP=no die "[Error] Failed to remove password expiration policy." 1
    fi

    # Clean up by removing the temporary file
    if [[ -f "$_policyTemplateFilePath2" ]]; then
      rm "$_policyTemplateFilePath2"
    fi

    echo "Successfully removed the password expiration policy from the template."
    echo ""
  fi

  # If the argument is set to 0, clear the value of the expiration argument
  if [[ "$_arg_daysUntilPasswordExpiration" == 0 ]]; then
    _arg_daysUntilPasswordExpiration=
  fi
fi

# Check if a value for days until password expiration is provided and if it matches the current policy
if [[ -n "$_arg_daysUntilPasswordExpiration" && "$currentPasswordExpiration" == "$_arg_daysUntilPasswordExpiration" ]]; then
  # Notify the user if the current password expiration policy already matches the desired setting
  echo "The password expiration policy is already set to require a password change every $_arg_daysUntilPasswordExpiration day(s)."
  echo ""

# If the desired expiration policy differs from the current one, attempt to update it
elif [[ -n "$_arg_daysUntilPasswordExpiration" && -n "$currentPasswordExpiration" ]]; then
  echo "Attempting to change the password expiration policy from requiring a password change every $currentPasswordExpiration days to $_arg_daysUntilPasswordExpiration days."

  # Update the password expiration string in the policy template
  if ! sed -i '' "s/<string>Change every .* days<\/string>/<string>Change every $_arg_daysUntilPasswordExpiration days<\/string>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password expiration policy." 1
  fi

  # Insert a placeholder in the policy template for the expiration integer
  if ! sed -i '' '/<key>policyAttributeExpiresEveryNDays<\/key>/a\
    <- This integer line will be replaced ->' "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password expiration policy." 1
  fi

  # Replace the placeholder with the new expiration value
  if ! sed -i '' "s/<- This integer line will be replaced ->.*<integer>.*<\/integer>/<integer>$_arg_daysUntilPasswordExpiration<\/integer>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password expiration policy." 1
  fi

  echo "Successfully modified the password policy template."
  echo ""

# If no expiration policy exists, create a new one
elif [[ -n "$_arg_daysUntilPasswordExpiration" ]]; then
  echo "Attempting to set the password expiration policy to require a password change every $_arg_daysUntilPasswordExpiration days."

  # Define the new password expiration policy as a string
  new_passwordExpirationPolicy="
<dict>
  <key>policyContent<\/key>
  <string>policyAttributeCurrentTime \&gt; policyAttributeLastPasswordChangeTime + (policyAttributeExpiresEveryNDays * 24 * 60 * 60)<\/string>
  <key>policyIdentifier<\/key>
	<string>Change every $_arg_daysUntilPasswordExpiration days<\/string>
  <key>policyParameters<\/key>
  <dict>
    <key>policyAttributeExpiresEveryNDays<\/key>
    <integer>$_arg_daysUntilPasswordExpiration<\/integer>
  <\/dict>
<\/dict>"

  # Add the new policy to the template in the appropriate location
  new_passwordExpirationPolicy=$(echo "$new_passwordExpirationPolicy" | tr '\n' '`')
  if ! sed -i '' "s/<- PasswordChange line will be replaced ->.*<.*array.*>/<- PasswordChange line will be replaced -><array>$new_passwordExpirationPolicy/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to add new password expiration policy." 1
  fi

  # Replace placeholders with the actual new policy in the template
  if ! tr '`' '\n' <"$_policyTemplateFilePath" >"$_policyTemplateFilePath2"; then
    _PRINT_HELP=no die "[Error] Failed to add new password expiration policy." 1
  fi

  # Move the updated policy template to its correct location
  if ! mv -f "$_policyTemplateFilePath2" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to add new password expiration policy." 1
  fi

  echo "Successfully added the new password policy to the template."
  echo ""
fi

# Minimum Password Length
if [[ -n "$_arg_minimumPasswordLength" ]]; then
  # Search for the default Apple password policy in the current policy
  defaultPolicy=$(echo "$currentPolicy" | grep 'com.apple.defaultpasswordpolicy')

  # If the default Apple password policy is found, proceed with its removal
  if [[ -n "$defaultPolicy" ]]; then
    # Use awk to mark lines for removal where the default password length policy is defined
    awk '
    /<string>policyAttributePassword matches '\''\^\$|\.{4,}\+'\''<\/string>/ && !appended {
        print two_lines_ago "<- This opening dict will be deleted ->"
        print one_line_ago
        print $0
        appended = 1
        next
    }
    NR > 2 {
        print two_lines_ago
    }
    {
        two_lines_ago = one_line_ago
        one_line_ago = $0
    }
    END {
        if (NR > 1) print one_line_ago
        if (NR > 0) print $0
    }
' "$_policyTemplateFilePath" >"$_policyTemplateFilePath2"

    # Ensure the plist has the proper closing tag, add one if missing
    if ! grep "</plist>" "$_policyTemplateFilePath2"; then
      echo "</plist>" >>"$_policyTemplateFilePath2"
    fi

    # Insert a placeholder to mark the closing dictionary for deletion
    if ! sed -i '' '/<string>com.apple.defaultpasswordpolicy<\/string>/a\
    <- This closing dict will be deleted ->' "$_policyTemplateFilePath2"; then
      _PRINT_HELP=no die "[Error] Failed to remove default password length policy." 1
    fi

    # Remove both opening and closing dictionaries marked for deletion
    if ! awk '/<dict><- This opening dict will be deleted ->/{inblock=1} /<- This closing dict will be deleted ->.*<\/dict>/{inblock=0; next} !inblock {print}' "$_policyTemplateFilePath2" >"$_policyTemplateFilePath"; then
      _PRINT_HELP=no die "[Error] Failed to remove default password length policy." 1
    fi

    # Clean up by removing the temporary file used during the policy changes
    if [[ -f "$_policyTemplateFilePath2" ]]; then
      rm "$_policyTemplateFilePath2"
    fi

    # Set the current minimum password length to empty as the default policy is now removed
    currentMinimumLength=

  # If no default policy is found, check for a custom minimum length in the current policy
  else
    currentMinimumLength=$(echo "$currentPolicy" | grep "minimumLength" | grep -E -o '\d+')
  fi
fi

# Check if the provided minimum password length matches the current policy
if [[ -n "$_arg_minimumPasswordLength" && "$currentMinimumLength" == "$_arg_minimumPasswordLength" ]]; then
  # Inform the user if the policy is already set to the desired minimum length
  echo "The password policy is already set to require a minimum length of $_arg_minimumPasswordLength character(s)."
  echo ""

# If a new minimum password length is provided but no current length is set, and there's no default policy
elif [[ -n "$_arg_minimumPasswordLength" && -n "$currentMinimumLength" && -z "$defaultPolicy" ]]; then
  # Inform the user that the password policy is being changed
  echo "Attempting to change the password policy from a minimum character length of $currentMinimumLength to $_arg_minimumPasswordLength."

  # Update the policy attribute to the new minimum length
  if ! sed -i '' "s/<string>policyAttributePassword matches '\.{[0-9]*,}.*'<\/string>/<string>policyAttributePassword matches '.{$_arg_minimumPasswordLength,}\+'<\/string>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password length policy." 1
  fi

  # Update the policy description to reflect the new minimum length
  if ! sed -i '' "s/<string>Must be a minimum of [0-9]* characters.*<\/string>/<string>Must be a minimum of $_arg_minimumPasswordLength characters in length<\/string>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password length policy." 1
  fi

  # Insert a placeholder for the new integer value for the minimum length
  if ! sed -i '' '/<key>minimumLength<\/key>/a\
    <- This integer line will be replaced ->' "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password length policy." 1
  fi

  # Replace the placeholder with the actual new minimum length integer value
  if ! sed -i '' "s/<- This integer line will be replaced ->.*<integer>.*<\/integer>/<integer>$_arg_minimumPasswordLength<\/integer>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password length policy." 1
  fi

  # Inform the user that the policy modification was successful
  echo "Successfully modified the password policy template."
  echo ""

# If no current policy is set and a new minimum password length is provided, set a new policy 
elif [[ -n "$_arg_minimumPasswordLength" ]]; then
  # Inform the user that a new policy is being set
  echo "Attempting to set the password policy to require a minimum character length of $_arg_minimumPasswordLength."

  # Create a new password policy template with the specified minimum password length
  new_passwordLengthPolicy="
<dict>
  <key>policyContent<\/key>
  <string>policyAttributePassword matches '.{$_arg_minimumPasswordLength,}+'<\/string>
	<key>policyIdentifier<\/key>
	<string>Must be a minimum of $_arg_minimumPasswordLength characters in length<\/string>
	<key>policyParameters<\/key>
	<dict>
		<key>minimumLength<\/key>
		<integer>$_arg_minimumPasswordLength<\/integer>
	<\/dict>
<\/dict>"

  # Format the new policy by converting it for insertion into the policy template
  new_passwordLengthPolicy=$(echo "$new_passwordLengthPolicy" | tr '\n' '`')

  # Insert the new password policy into the appropriate section of the policy template
  if ! sed -i '' "s/<- PasswordContent line will be replaced ->.*<array>/<- PasswordContent line will be replaced -><array>$new_passwordLengthPolicy/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to add new password history policy." 1
  fi

  # Convert back the policy template and write changes to a new file
  if ! tr '`' '\n' <"$_policyTemplateFilePath" >"$_policyTemplateFilePath2"; then
    _PRINT_HELP=no die "[Error] Failed to add new password history policy." 1
  fi

  # Move the new file to replace the original policy template file
  if ! mv -f "$_policyTemplateFilePath2" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to add new password history policy." 1
  fi

  # Inform the user that the new password policy was successfully added to the template
  echo "Successfully added the new password policy to the template."
  echo ""
fi

# Minimum Numbers
if [[ -n "$_arg_minimumNumbersInPassword" ]]; then
  # Retrieve the current minimum number of numeric characters from the policy if it exists
  currentMinimumNumbers=$(echo "$currentPolicy" | grep "minimumNumericCharacters" | grep -E -o '\d+')
fi

# If the provided number of numeric characters matches the current policy, inform the user
if [[ -n "$_arg_minimumNumbersInPassword" && "$currentMinimumNumbers" == "$_arg_minimumNumbersInPassword" ]]; then
  echo "The password policy is already set to require a minimum of $_arg_minimumNumbersInPassword numeric characters."
  echo ""

# If the provided number of numeric characters is different from the current policy, attempt to change it 
elif [[ -n "$_arg_minimumNumbersInPassword" && -n "$currentMinimumNumbers" ]]; then
  echo "Attempting to change the password policy from requiring a minimum number of numeric characters of $currentMinimumNumbers to $_arg_minimumNumbersInPassword."

  # Update the password policy to reflect the new minimum number of numeric characters
  if ! sed -i '' "s/<string>policyAttributePassword matches '(\.\*\?\\\\\\\p{Nd}\.\*\?){[0-9]*,}\?'<\/string>/<string>policyAttributePassword matches '(.*?\\\\\\\p{Nd}.*?){$_arg_minimumNumbersInPassword,}?'<\/string>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change minimum numbers password policy." 1
  fi

  # Update the policy description to indicate the new minimum number of numeric characters
  if ! sed -i '' "s/<string>Must contain at least [0-9]* number.*<\/string>/<string>Must contain at least $_arg_minimumNumbersInPassword number(s)<\/string>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change minimum numbers password policy." 1
  fi

  # Insert a placeholder for the new integer value for the minimum number of numeric characters
  if ! sed -i '' '/<key>minimumNumericCharacters<\/key>/a\
    <- This integer line will be replaced ->' "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change minimum numbers password policy." 1
  fi

  # Replace the placeholder with the actual integer value of the minimum number of numeric characters
  if ! sed -i '' "s/<- This integer line will be replaced ->.*<integer>.*<\/integer>/<integer>$_arg_minimumNumbersInPassword<\/integer>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change minimum numbers password policy." 1
  fi

  # Inform the user that the password policy template was successfully modified
  echo "Successfully modified the password policy template."
  echo ""

# If no current policy exists, create and set a new minimum number of numeric characters in the password
elif [[ -n "$_arg_minimumNumbersInPassword" ]]; then
  echo "Attempting to set the password policy to requiring a minimum number of $_arg_minimumNumbersInPassword numeric characters."

  # Create a new policy block with the specified minimum number of numeric characters
  new_passwordNumberPolicy="
<dict>
  <key>policyContent<\/key>
  <string>policyAttributePassword matches '(.*?\\\\\\\p{Nd}.*?){$_arg_minimumNumbersInPassword,}?'<\/string>
	<key>policyIdentifier<\/key>
	<string>Must contain at least $_arg_minimumNumbersInPassword number(s)<\/string>
	<key>policyParameters<\/key>
	<dict>
		<key>minimumNumericCharacters<\/key>
		<integer>$_arg_minimumNumbersInPassword<\/integer>
	<\/dict>
<\/dict>"

  # Format the new policy block for insertion into the policy template
  new_passwordNumberPolicy=$(echo "$new_passwordNumberPolicy" | tr '\n' '`')

  # Insert the new policy block at the appropriate point in the template
  if ! sed -i '' "s/<- PasswordContent line will be replaced ->.*<array>/<- PasswordContent line will be replaced -><array>$new_passwordNumberPolicy/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to add new minimum numbers policy." 1
  fi

  # Convert back the policy template for saving
  if ! tr '`' '\n' <"$_policyTemplateFilePath" >"$_policyTemplateFilePath2"; then
    _PRINT_HELP=no die "[Error] Failed to add new minimum numbers policy." 1
  fi

  # Move the new file to replace the original template
  if ! mv -f "$_policyTemplateFilePath2" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to add new minimum numbers policy." 1
  fi

  # Inform the user that the new password policy was successfully added to the template
  echo "Successfully added the new password policy to the template."
  echo ""
fi

# Minimum Lowercase Letters
if [[ -n "$_arg_minimumLowercaseLetters" ]]; then
  # Extract the current minimum number of lowercase letters from the current policy
  currentMinimumLowercaseLetters=$(echo "$currentPolicy" | grep "minimumAlphaCharactersLowerCase" | grep -E -o '\d+')
fi

# If the current policy already matches the user-provided minimum, inform the user
if [[ -n "$_arg_minimumLowercaseLetters" && "$currentMinimumLowercaseLetters" == "$_arg_minimumLowercaseLetters" ]]; then
  echo "The password policy is already set to require a minimum of $_arg_minimumLowercaseLetters lowercase characters."
  echo ""

# If the current policy doesn't match, attempt to modify it
elif [[ -n "$_arg_minimumLowercaseLetters" && -n "$currentMinimumLowercaseLetters" ]]; then
  echo "Attempting to change the password policy from a minimum of $currentMinimumLowercaseLetters lowercase characters to $_arg_minimumLowercaseLetters."

  # Update the regex pattern for password validation to enforce the new number of lowercase letters
  if ! sed -i '' "s/<string>policyAttributePassword matches '(\.\*\[a-z\]\.\*){[0-9]*,}\+'<\/string>/<string>policyAttributePassword matches '(.*[a-z].*){$_arg_minimumLowercaseLetters,}+'<\/string>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change minimum number of lower case letters password policy." 1
  fi

  # Update the description to indicate the new minimum number of lowercase letters
  if ! sed -i '' "s/<string>Must contain at least [0-9]* lower case.*<\/string>/<string>Must contain at least $_arg_minimumLowercaseLetters lower case letter(s)<\/string>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change minimum number of lower case letters password policy." 1
  fi

  # Insert a placeholder for the new integer value for the minimum number of lowercase letters
  if ! sed -i '' '/<key>minimumAlphaCharactersLowerCase<\/key>/a\
    <- This integer line will be replaced ->' "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change minimum number of lower case letters password policy." 1
  fi

  # Replace the placeholder with the actual integer value for the minimum number of lowercase letters
  if ! sed -i '' "s/<- This integer line will be replaced ->.*<integer>.*<\/integer>/<integer>$_arg_minimumLowercaseLetters<\/integer>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change minimum number of lower case letters password policy." 1
  fi

  # Inform the user that the password policy template was successfully modified
  echo "Successfully modified the password policy template."
  echo ""

# If no current policy exists, create and set a new policy for the minimum number of lowercase letters
elif [[ -n "$_arg_minimumLowercaseLetters" ]]; then
  echo "Attempting to set the password policy to require a minimum of $_arg_minimumLowercaseLetters lowercase characters."

  # Create a new policy block with the specified minimum number of lowercase letters
  new_passwordLowerCasePolicy="
<dict>
  <key>policyContent<\/key>
  <string>policyAttributePassword matches '(.*[a-z].*){$_arg_minimumLowercaseLetters,}+'<\/string>
	<key>policyIdentifier<\/key>
	<string>Must contain at least $_arg_minimumLowercaseLetters lower case letter(s)<\/string>
	<key>policyParameters<\/key>
	<dict>
		<key>minimumAlphaCharactersLowerCase<\/key>
		<integer>$_arg_minimumLowercaseLetters<\/integer>
	<\/dict>
<\/dict>"

  # Format the new policy block for insertion into the policy template
  new_passwordLowerCasePolicy=$(echo "$new_passwordLowerCasePolicy" | tr '\n' '`')

  # Insert the new policy block at the appropriate point in the template
  if ! sed -i '' "s/<- PasswordContent line will be replaced ->.*<array>/<- PasswordContent line will be replaced -><array>$new_passwordLowerCasePolicy/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to add new minimum lower case letters policy." 1
  fi

  # Convert back the policy template for saving
  if ! tr '`' '\n' <"$_policyTemplateFilePath" >"$_policyTemplateFilePath2"; then
    _PRINT_HELP=no die "[Error] Failed to add new minimum lower case letters policy." 1
  fi

  # Move the new file to replace the original template
  if ! mv -f "$_policyTemplateFilePath2" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to add new minimum lower case letters policy." 1
  fi

  # Inform the user that the new password policy was successfully added to the template
  echo "Successfully added the new policy to the password template."
  echo ""
fi

# Minimum Uppercase Letters
if [[ -n "$_arg_minimumUppercaseLetters" ]]; then
  # Extract the current minimum number of uppercase letters from the current policy
  currentMinimumUppercaseLetters=$(echo "$currentPolicy" | grep -w "minimumAlphaCharacters" | grep -E -o '\d+')
fi

# If the current policy already matches the user-provided minimum, inform the user
if [[ -n "$_arg_minimumUppercaseLetters" && "$currentMinimumUppercaseLetters" == "$_arg_minimumUppercaseLetters" ]]; then
  echo "The password policy is already set to require a minimum of $_arg_minimumUppercaseLetters uppercase characters."
  echo ""

# If the current policy doesn't match, attempt to modify it
elif [[ -n "$_arg_minimumUppercaseLetters" && -n "$currentMinimumUppercaseLetters" ]]; then
  echo "Attempting to change the password policy from a minimum of $currentMinimumUppercaseLetters uppercase characters to $_arg_minimumUppercaseLetters."

  # Update the regex pattern for password validation to enforce the new number of uppercase letters
  if ! sed -i '' "s/<string>policyAttributePassword matches '(\.\*\[A-Z\]\.\*){[0-9]*,}\+'<\/string>/<string>policyAttributePassword matches '(.*[A-Z].*){$_arg_minimumUppercaseLetters,}+'<\/string>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change minimum number of upper case letters password policy." 1
  fi

  # Update the description to indicate the new minimum number of uppercase letters
  if ! sed -i '' "s/<string>Must contain at least [0-9]* upper case.*<\/string>/<string>Must contain at least $_arg_minimumUppercaseLetters upper case letter(s)<\/string>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change minimum number of upper case letters password policy." 1
  fi

  # Insert a placeholder for the new integer value for the minimum number of uppercase letters
  if ! sed -i '' '/<key>minimumAlphaCharacters<\/key>/a\
    <- This integer line will be replaced ->' "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change minimum number of upper case letters password policy." 1
  fi

  # Replace the placeholder with the actual integer value for the minimum number of uppercase letters
  if ! sed -i '' "s/<- This integer line will be replaced ->.*<integer>.*<\/integer>/<integer>$_arg_minimumUppercaseLetters<\/integer>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change minimum number of upper case letters password policy." 1
  fi

  # Inform the user that the password policy template was successfully modified
  echo "Successfully modified the password policy template."
  echo ""

# If no current policy exists, create and set a new policy for the minimum number of uppercase letters
elif [[ -n "$_arg_minimumUppercaseLetters" ]]; then
  echo "Attempting to set the password policy to require a minimum of $_arg_minimumUppercaseLetters uppercase characters."

  # Create a new policy block with the specified minimum number of uppercase letters
  new_passwordUpperCasePolicy="
<dict>
  <key>policyContent<\/key>
  <string>policyAttributePassword matches '(.*[A-Z].*){$_arg_minimumUppercaseLetters,}+'<\/string>
	<key>policyIdentifier<\/key>
	<string>Must contain at least $_arg_minimumUppercaseLetters upper case letter(s)<\/string>
	<key>policyParameters<\/key>
	<dict>
		<key>minimumAlphaCharacters<\/key>
		<integer>$_arg_minimumUppercaseLetters<\/integer>
	<\/dict>
<\/dict>"

  # Format the new policy block for insertion into the policy template
  new_passwordUpperCasePolicy=$(echo "$new_passwordUpperCasePolicy" | tr '\n' '`')

  # Insert the new policy block at the appropriate point in the template
  if ! sed -i '' "s/<- PasswordContent line will be replaced ->.*<array>/<- PasswordContent line will be replaced -><array>$new_passwordUpperCasePolicy/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to add new minimum upper case letters policy." 1
  fi

  # Convert back the policy template for saving
  if ! tr '`' '\n' <"$_policyTemplateFilePath" >"$_policyTemplateFilePath2"; then
    _PRINT_HELP=no die "[Error] Failed to add new minimum upper case letters policy." 1
  fi

  # Move the new file to replace the original template
  if ! mv -f "$_policyTemplateFilePath2" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to add new minimum upper case letters policy." 1
  fi

  # Inform the user that the new password policy was successfully added to the template
  echo "Successfully added the new policy to the password template."
  echo ""
fi

# Minimum Special Characters
if [[ -n "$_arg_minimumSpecialCharacters" ]]; then
  # Extract the current minimum number of special characters from the policy
  currentMinimumSpecial=$(echo "$currentPolicy" | grep -w "minimumSymbols" | grep -E -o '\d+')
fi

# If the current policy already matches the user-provided value, inform the user
if [[ -n "$_arg_minimumSpecialCharacters" && "$currentMinimumSpecial" == "$_arg_minimumSpecialCharacters" ]]; then
  echo "The password policy is already set to require a minimum of $_arg_minimumSpecialCharacters special characters."
  echo ""

# If the current policy is different, attempt to change it
elif [[ -n "$_arg_minimumSpecialCharacters" && -n "$currentMinimumSpecial" ]]; then
  echo "Attempting to change the password policy from requiring a minimum number of special characters of $currentMinimumSpecial to $_arg_minimumSpecialCharacters."

  # Update the regular expression to enforce the new number of special characters
  if ! sed -i '' "s/<string>policyAttributePassword matches '(\.\*\[^a-zA-Z0-9\]\.\*){[0-9]*,}\+'<\/string>/<string>policyAttributePassword matches '(.*[^a-zA-Z0-9].*){$_arg_minimumSpecialCharacters,}+'<\/string>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change minimum number of special characters password policy." 1
  fi

  # Update the description to reflect the new policy requirement
  if ! sed -i '' "s/<string>Must contain at least [0-9]* special character.*<\/string>/<string>Must contain at least $_arg_minimumSpecialCharacters special character(s)<\/string>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change minimum number of special characters password policy." 1
  fi

  # Insert a placeholder to add the integer value for the new minimum number of special characters
  if ! sed -i '' '/<key>minimumSymbols<\/key>/a\
    <- This integer line will be replaced ->' "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change minimum number of special characters password policy." 1
  fi

  # Replace the placeholder with the actual value for the minimum number of special characters
  if ! sed -i '' "s/<- This integer line will be replaced ->.*<integer>.*<\/integer>/<integer>$_arg_minimumSpecialCharacters<\/integer>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change minimum number of special characters password policy." 1
  fi

  # Inform the user that the policy was successfully modified
  echo "Successfully modified the password policy template."
  echo ""

# If no existing policy is found, create and set a new policy for the minimum number of special characters
elif [[ -n "$_arg_minimumSpecialCharacters" ]]; then
  echo "Attempting to set the password policy to require a minimum of $_arg_minimumSpecialCharacters special characters."

  # Define a new policy block with the specified minimum number of special characters
  new_passwordSpecialCharacterPolicy="
<dict>
  <key>policyContent<\/key>
  <string>policyAttributePassword matches '(.*[^a-zA-Z0-9].*){$_arg_minimumSpecialCharacters,}+'<\/string>
	<key>policyIdentifier<\/key>
	<string>Must contain at least $_arg_minimumSpecialCharacters special character(s)<\/string>
	<key>policyParameters<\/key>
	<dict>
		<key>minimumSymbols<\/key>
		<integer>$_arg_minimumSpecialCharacters<\/integer>
	<\/dict>
<\/dict>"

  # Format the new policy for insertion into the policy template
  new_passwordSpecialCharacterPolicy=$(echo "$new_passwordSpecialCharacterPolicy" | tr '\n' '`')

  # Insert the new policy block at the appropriate point in the template
  if ! sed -i '' "s/<- PasswordContent line will be replaced ->.*<array>/<- PasswordContent line will be replaced -><array>$new_passwordSpecialCharacterPolicy/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to add new minimum special characters policy." 1
  fi

  # Convert back the policy template for saving
  if ! tr '`' '\n' <"$_policyTemplateFilePath" >"$_policyTemplateFilePath2"; then
    _PRINT_HELP=no die "[Error] Failed to add new minimum special characters policy." 1
  fi

  # Move the new file to replace the original template
  if ! mv -f "$_policyTemplateFilePath2" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to add new minimum special characters policy." 1
  fi

  # Inform the user that the new policy was successfully added
  echo "Successfully added the new policy to the password template."
  echo ""
fi

# Password History
if [[ -n "$_arg_passwordHistory" ]]; then
  # Extract the current password history depth from the policy
  currentPasswordHistory=$(echo "$currentPolicy" | grep "policyAttributePasswordHistoryDepth" | grep -E -o '\d+')
fi

# If the current policy already matches the user-provided value, inform the user
if [[ -n "$_arg_passwordHistory" && "$currentPasswordHistory" == "$_arg_passwordHistory" ]]; then
  echo "The password policy is already set to remember the previous $_arg_passwordHistory passwords."
  echo ""

# If the current policy is different, attempt to change it
elif [[ -n "$_arg_passwordHistory" && -n "$currentPasswordHistory" ]]; then
  echo "Attempting to change the password policy from remembering the previous $currentPasswordHistory to $_arg_passwordHistory."

  # Update the string describing the number of remembered passwords
  if ! sed -i '' "s/<string>Does not match any of last .* passwords<\/string>/<string>Does not match any of last $_arg_passwordHistory passwords<\/string>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password history policy." 1
  fi

  # Insert a placeholder to add the integer value for the new password history depth
  if ! sed -i '' '/<key>policyAttributePasswordHistoryDepth<\/key>/a\
    <- This integer line will be replaced ->' "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password history policy." 1
  fi

  # Replace the placeholder with the actual value for the password history depth
  if ! sed -i '' "s/<- This integer line will be replaced ->.*<integer>.*<\/integer>/<integer>$_arg_passwordHistory<\/integer>/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to change password history policy." 1
  fi

  # Inform the user that the policy was successfully modified
  echo "Successfully modified the password policy template."
  echo ""

# If no existing policy is found, create and set a new policy for password history
elif [[ -n "$_arg_passwordHistory" ]]; then
  echo "Attempting to set the password policy to remember the previous $_arg_passwordHistory passwords."

  # Define a new policy block with the specified password history depth
  new_passwordHistoryPolicy="
<dict>
  <key>policyContent<\/key>
  <string>none policyAttributePasswordHashes in policyAttributePasswordHistory<\/string>
  <key>policyIdentifier<\/key>
	<string>Does not match any of the last $_arg_passwordHistory passwords<\/string>
  <key>policyParameters<\/key>
  <dict>
    <key>policyAttributePasswordHistoryDepth<\/key>
    <integer>$_arg_passwordHistory<\/integer>
  <\/dict>
<\/dict>"

  # Format the new policy for insertion into the policy template
  new_passwordHistoryPolicy=$(echo "$new_passwordHistoryPolicy" | tr '\n' '`')

  # Insert the new policy block at the appropriate point in the template
  if ! sed -i '' "s/<- PasswordContent line will be replaced ->.*<array>/<- PasswordContent line will be replaced -><array>$new_passwordHistoryPolicy/g" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to add new password history policy." 1
  fi

  # Convert back the policy template for saving
  if ! tr '`' '\n' <"$_policyTemplateFilePath" >"$_policyTemplateFilePath2"; then
    _PRINT_HELP=no die "[Error] Failed to add new password history policy." 1
  fi

  # Move the new file to replace the original template
  if ! mv -f "$_policyTemplateFilePath2" "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to add new password history policy." 1
  fi

  # Inform the user that the new policy was successfully added
  echo "Successfully added the new policy to the password template."
  echo ""
fi

# Inform the user that the policy template is being cleaned up
echo "Cleaning up policy template."

# Remove the placeholder for Password Authentication policies from the template
if ! sed -i '' 's/<- PasswordAuthentication line will be replaced ->//g' "$_policyTemplateFilePath"; then
  _PRINT_HELP=no die "[Error] Failed to update the password policy." 1
fi

# Remove the placeholder for Password Content policies from the template
if ! sed -i '' 's/<- PasswordContent line will be replaced ->//g' "$_policyTemplateFilePath"; then
  _PRINT_HELP=no die "[Error] Failed to update the password policy." 1
fi

# Remove the placeholder for Password Change policies from the template
if ! sed -i '' 's/<- PasswordChange line will be replaced ->//g' "$_policyTemplateFilePath"; then
  _PRINT_HELP=no die "[Error] Failed to update the password policy." 1
fi

# Check if the last two non-empty lines in the file are missing the closing <dict> tag
finalDict=$(awk 'NF' "$_policyTemplateFilePath" | tail -n 2 | grep 'dict')

# If the <dict> closing tag is missing, add it before the closing </plist> tag
if [[ -z "$finalDict" ]]; then
  if ! sed -i '' 's/<\/plist>/<\/dict><\/plist>/g' "$_policyTemplateFilePath"; then
    _PRINT_HELP=no die "[Error] Failed to add closing dict tag to '$_policyTemplateFilePath'." 1
  fi
fi

# Attempt to apply the modified policy template to the system
echo "Attempting to apply the policy template."
if ! pwpolicy -setaccountpolicies "$_policyTemplateFilePath"; then
  _PRINT_HELP=no die "[Error] Failed to update the password policy." 1
else
  echo "Successfully applied the policy template."
fi

# Clean up by removing the temporary policy template file
echo "Removing temporary policy template file."
if [[ -f "$_policyTemplateFilePath" ]]; then
  rm "$_policyTemplateFilePath"
fi




