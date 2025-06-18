# Gets the details of all iSCSI devices on the system.
#!/usr/bin/env bash

# Description: Gets the details of all iSCSI devices on the system.
#
# Release Notes: Initial Release
#
# Usage: [-WYSIWYGCustomFieldName <Arg>]
#
# Preset Parameter: --help
#   Displays the help menu.
#
# Preset Parameter: --WYSIWYGCustomFieldName "ReplaceMeWithAnyMultilineCustomField"
#   Optionally specify the name of a WYSIWYG custom field to save the results to.

# Functions
# Print an error message and exit with a specific status code
die() {
    local _ret="${2:-1}"
    test "${_PRINT_HELP:-no}" = yes && print_help >&2
    echo "$1" >&2
    exit "${_ret}"
}

print_help() {
    printf '\n\n%s\n\n' 'Usage: [-WYSIWYGCustomFieldName <Arg>]'
    printf '%s\n' 'Preset Parameter: --help'
    printf '\t%s\n' "Displays the help menu."
    printf '%s\n' 'Preset Parameter: --WYSIWYGCustomFieldName "ReplaceMeWithAnyMultilineCustomField"'
    printf '\t%s\n' "Optionally specify the name of a WYSIWYG custom field to save the results to."
}

convertToHTMLTable() {
    local _arg_delimiter=" "
    local _arg_inputObject

    # Process command-line arguments for the function.
    while test $# -gt 0; do
        _key="$1"
        case "$_key" in
        --delimiter | -d)
            test $# -lt 2 && echo "[Error] Missing value for the required argument" >&2 && return 1
            _arg_delimiter=$2
            shift
            ;;
        --*)
            echo "[Error] Got an unexpected argument" >&2
            return 1
            ;;
        *)
            _arg_inputObject=$1
            ;;
        esac
        shift
    done

    # Handles missing input by checking stdin or returning an error.
    if [[ -z $_arg_inputObject ]]; then
        if [ -p /dev/stdin ]; then
            _arg_inputObject=$(cat)
        else
            echo "[Error] Missing input object to convert to table" >&2
            return 1
        fi
    fi

    local htmlTable="<table>\n"
    htmlTable+=$(printf '%b' "$_arg_inputObject" | head -n1 | awk -F "$_arg_delimiter" '{
        printf "<tr>"
        for (i=1; i<=NF; i+=1)
        { printf "<th>"$i"</th>" }
        printf "</tr>"
    }')
    htmlTable+="\n"
    htmlTable+=$(printf '%b' "$_arg_inputObject" | tail -n +2 | awk -F "$_arg_delimiter" '{
        printf "<tr>"
        for (i=1; i<=NF; i+=1)
        { printf "<td>"$i"</td>" }
        print "</tr>"
    }')
    htmlTable+="\n</table>"

    printf '%b' "$htmlTable" '\n'
}

# Function to set a custom field
function SetCustomField() {
    if [[ -z "$1" ]] || [[ -z "$2" ]]; then
        echo "[Error] Missing required arguments."
        return 1
    fi
    local customfieldName=$1
    local customfieldValue=$2
    if [ -f "${NINJA_DATA_PATH}/ninjarmm-cli" ]; then
        if [ -x "${NINJA_DATA_PATH}/ninjarmm-cli" ]; then
            if "$NINJA_DATA_PATH"/ninjarmm-cli get "$customfieldName" >/dev/null; then
                # check if the value is greater than 10000 characters
                if [ ${#customfieldValue} -gt 10000 ]; then
                    echo "[Warn] Custom field value is greater than 10000 characters"
                fi
                if ! echo "${customfieldValue::10000}" | "$NINJA_DATA_PATH"/ninjarmm-cli set --stdin "$customfieldName"; then
                    echo "[Warn] Failed to set custom field"
                else
                    echo "[Info] Custom field value set successfully"
                fi
            else
                echo "[Warn] Custom Field ($customfieldName) does not exist or agent does not have permission to access it"
            fi
        else
            echo "[Warn] ninjarmm-cli is not executable"
        fi
    else
        echo "[Warn] ninjarmm-cli does not exist"
    fi
}

# Parse the command-line arguments
parse_commandline() {
    while test $# -gt 0; do
        _key="$1"
        case "$_key" in
        -w | --WYSIWYGCustomFieldName)
            test $# -lt 2 && die "Missing value for the optional argument '$_key'." 1
            _arg_WYSIWYGCustomFieldName="$2"
            shift
            ;;
        --WYSIWYGCustomFieldName=*)
            _arg_WYSIWYGCustomFieldName="${_key##--wysiwygCustomFieldName=}"
            ;;
        -w*)
            _arg_WYSIWYGCustomFieldName="${_key##-w}"
            ;;
        --help)
            _PRINT_HELP=yes die "" 0
            ;;
        -h)
            _PRINT_HELP=yes die "" 0
            ;;
        *)
            _PRINT_HELP=yes die "[Error] Got an unexpected argument '$1'" 1
            ;;
        esac
        shift
    done
}

parse_commandline "$@"

# If script form variables are used, replace the command line parameters with their value.
if [[ -n "${wysiwygCustomFieldName}" ]]; then
    _arg_WYSIWYGCustomFieldName="$wysiwygCustomFieldName"
fi

# If no valid custom field was provided, display an error message and exit the script.
# if [[ -z "${_arg_WYSIWYGCustomFieldName}" ]]; then
#     _PRINT_HELP=yes die "[Error] You must provide a valid WYSIWYG custom field name." 1
# fi

# Check if the root user is running the script
if [[ $EUID -ne 0 ]]; then
    die "[Error] This script must be run as root." 1
fi

if ! [ "$(command -v iscsiadm)" ]; then
    die "[Error] The command iscsiadm not installed." 1
fi

if ! [ -f "/etc/iscsi/iscsid.conf" ]; then
    die "[Error] /etc/iscsi/iscsid.conf is not present." 1
fi

# Print Initiator Name
_connection_identifier=$(grep -v "#" /etc/iscsi/initiatorname.iscsi 2>/dev/null | awk -F= '{print $2}')

# Get the iSCSI session details
session=$(iscsiadm -m session -P 3 2>&1)

# HTML title variables
_title_connections="iSCSI Connections"
_title_sessions="iSCSI Sessions"

# Delimiter for result parsing
_delimiter=";"

# iSCSI Connections
declare -g _iscsi_connections=""
declare -g _initiator_address=""
declare -g _initiator_port=""
declare -g _target_address=""
declare -g _target_port=""

# iSCSI Sessions
declare -g _iscsi_sessions=""
declare -g _authentication_type=""
declare -g _initiator_name=""
declare -g _initiator_node_address=""
declare -g _initiator_node_portal_address=""
declare -g _initiator_side_identifier=""
declare -g _is_connected=""
declare -g _is_data_digest=""
declare -g _is_persistent=""
declare -g _number_of_luns=0
declare -g _session_identifier=""
declare -g _target_node_address=""
declare -g _target_side_identifier=""

while read -r line; do
    if [[ "$line" == "Target:"* ]]; then
        if [[ -n "${_initiator_address}" ]]; then
            # Add results
            _iscsi_connections="${_iscsi_connections}\n"
            _iscsi_connections="${_iscsi_connections}${_connection_identifier}${_delimiter}"
            _iscsi_connections="${_iscsi_connections}${_initiator_address}${_delimiter}"
            _iscsi_connections="${_iscsi_connections}${_initiator_port}${_delimiter}"
            _iscsi_connections="${_iscsi_connections}${_target_address}${_delimiter}"
            _iscsi_connections="${_iscsi_connections}${_target_port}"
            _iscsi_sessions="${_iscsi_sessions}\n"
            _iscsi_sessions="${_iscsi_sessions}${_authentication_type}${_delimiter}"
            _iscsi_sessions="${_iscsi_sessions}${_initiator_name}${_delimiter}"
            _iscsi_sessions="${_iscsi_sessions}${_initiator_node_address}${_delimiter}"
            _iscsi_sessions="${_iscsi_sessions}${_initiator_node_portal_address}${_delimiter}"
            _iscsi_sessions="${_iscsi_sessions}${_initiator_side_identifier}${_delimiter}"
            _iscsi_sessions="${_iscsi_sessions}${_is_connected}${_delimiter}"
            _iscsi_sessions="${_iscsi_sessions}${_is_data_digest}${_delimiter}"
            _iscsi_sessions="${_iscsi_sessions}${_is_persistent}${_delimiter}"
            _iscsi_sessions="${_iscsi_sessions}${_number_of_luns}${_delimiter}"
            _iscsi_sessions="${_iscsi_sessions}${_session_identifier}${_delimiter}"
            _iscsi_sessions="${_iscsi_sessions}${_target_node_address}${_delimiter}"
            _iscsi_sessions="${_iscsi_sessions}${_target_side_identifier}"
        fi

        # Reset the variables
        # iSCSI Connections
        _initiator_address=""
        _initiator_port=""
        _target_address=""
        _target_port=""

        # iSCSI Sessions
        _authentication_type=""
        _initiator_name=""
        _initiator_node_address=""
        _initiator_node_portal_address=""
        _initiator_side_identifier=""
        _is_connected=""
        _is_data_digest=""
        _is_persistent=""
        _number_of_luns=0
        _session_identifier=""
        _target_node_address=""
        _target_side_identifier=""

        # Get the target
        connection_identifier=$(echo "$line" | cut -d ':' -f 2-3 | awk '{print $1}')
        _target_node_address=$(echo "$connection_identifier" | cut -d ':' -f 1-2 | awk '{$1=$1;print}')
        _target_address=$(echo "$connection_identifier" | cut -d ':' -f 1 | awk '{$1=$1;print}')
        _target_side_identifier=$(echo "$connection_identifier" | cut -d ':' -f 2 | awk '{print $1}')
    fi
    if [[ "$line" == *"Current Portal:"* ]]; then
        portal=$(echo "$line" | cut -d ':' -f 2-3)
        _initiator_node_portal_address=$(echo "$portal" | cut -d ':' -f 1-2 | cut -d ',' -f 1 | awk '{$1=$1;print}')
        _initiator_port=$(echo "$portal" | cut -d ':' -f 2 | cut -d ',' -f 1 | awk '{$1=$1;print}')
        _target_port=$(echo "$portal" | cut -d ':' -f 2 | cut -d ',' -f 1 | awk '{$1=$1;print}')
    fi
    if [[ "$line" == *"Persistent Portal:"* ]]; then
        _is_persistent="Yes"
    fi
    if [[ "$line" == *"Iface Name:"* ]]; then
        _initiator_name=$(echo "$line" | cut -d ':' -f 2 | awk '{$1=$1;print}')
    fi
    if [[ "$line" == *"Iface Initiatorname:"* ]]; then
        initiator=$(echo "$line" | cut -d ':' -f 2-4)
        _initiator_node_address=$(echo "$initiator" | cut -d ':' -f 1-2 | awk '{$1=$1;print}')
        _initiator_side_identifier=$(echo "$initiator" | cut -d ':' -f 3 | awk '{$1=$1;print}')
        _initiator_address=$(echo "$initiator" | cut -d ':' -f 1 | awk '{$1=$1;print}')
    fi
    if [[ "$line" == *"iSCSI Connection State:"* ]]; then
        _is_connected=$(echo "$line" | cut -d ':' -f 2 | awk '{$1=$1;print}')
    fi
    if [[ "$line" == *"SID:"* ]]; then
        _session_identifier=$(echo "$line" | cut -d ':' -f 2 | awk '{$1=$1;print}')
    fi
    if [[ "$line" == *"DataDigest:"* ]]; then
        _is_data_digest=$(echo "$line" | cut -d ':' -f 2 | awk '{$1=$1;print}')
    fi
    if [[ "$line" == *"CHAP:"* ]]; then
        _authentication_type="CHAP"
    fi
    if [[ "$line" == *"username: <empty>"* ]]; then
        # If the username is empty, set auth_method to None
        _authentication_type="None"
    fi
    if [[ "$line" == *"Lun:"* ]]; then
        _number_of_luns=$((_number_of_luns + 1))
    fi

done <<<"$session"

_iscsi_connections="${_iscsi_connections}\n${_connection_identifier}${_delimiter}${_initiator_address}${_delimiter}${_initiator_port}${_delimiter}${_target_address}${_delimiter}${_target_port}"
_iscsi_sessions="${_iscsi_sessions}\n${_authentication_type}${_delimiter}${_initiator_name}${_delimiter}${_initiator_node_address}${_delimiter}${_initiator_node_portal_address}${_delimiter}${_initiator_side_identifier}${_delimiter}${_is_connected}${_delimiter}${_is_data_digest}${_delimiter}${_is_persistent}${_delimiter}${_number_of_luns}${_delimiter}${_session_identifier}${_delimiter}${_target_node_address}${_delimiter}${_target_side_identifier}"

# Output results to Activity Feed
_console_iscsi_connections="Connection Identifier${_delimiter}Initiator Address${_delimiter}Initiator Port${_delimiter}Target Address${_delimiter}Target Port\n${_iscsi_connections}"
_console_iscsi_sessions="Auth Type${_delimiter}Name${_delimiter}Init Address${_delimiter}Init Portal Address${_delimiter}Init Side ID${_delimiter}Connected${_delimiter}Data Digest${_delimiter}Persistent${_delimiter}LUNs${_delimiter}SID${_delimiter}Tgt Node Address${_delimiter}Tgt Side Identifier\n${_iscsi_sessions}"
# Print the result to activity feed
echo -e "\n---${_title_connections}---"
echo -e "${_console_iscsi_connections}" | column -t -s ';'
echo -e "\n---${_title_sessions}---"

# Check if there are no active iSCSI sessions
if [[ "${session}" == *"No active sessions"* || $(echo "$session" | wc -l) -le 1 ]]; then
    echo "No active iSCSI sessions"
    # If no sessions are active, notify that no data to be saved to custom field
    if [[ -n "${_arg_WYSIWYGCustomFieldName}" ]]; then
        echo "[Info] No data to save to custom field."
    fi
    exit 0
else
    echo -e "${_console_iscsi_sessions}" | column -t -s ';'
fi

# Add Headers
_iscsi_connections="Connection Identifier${_delimiter}Initiator Address${_delimiter}Initiator Port${_delimiter}Target Address${_delimiter}Target Port\n${_iscsi_connections}"
_iscsi_sessions="Authentication Type${_delimiter}Initiator Name${_delimiter}Initiator Node Address${_delimiter}Initiator Node Portal Address${_delimiter}Initiator Side Identifier${_delimiter}Is Connected${_delimiter}Is Data Digest${_delimiter}Is Persistent${_delimiter}Number of LUNs${_delimiter}Session Identifier${_delimiter}Target Node Address${_delimiter}Target Side Identifier\n${_iscsi_sessions}"

# Convert the CSV result to an HTML table
html_connections_result=$(convertToHTMLTable "$_iscsi_connections" --delimiter "${_delimiter}")
html_sessions_result=$(convertToHTMLTable "$_iscsi_sessions" --delimiter "${_delimiter}")

# Combine the results
html_result+="<h3>${_title_connections}</h3>"
html_result+="$html_connections_result"
html_result+="<h3>${_title_sessions}</h3>"
html_result+="$html_sessions_result"

if [[ -n "${_arg_WYSIWYGCustomFieldName}" ]]; then
    SetCustomField "$_arg_WYSIWYGCustomFieldName" "$html_result"
fi





