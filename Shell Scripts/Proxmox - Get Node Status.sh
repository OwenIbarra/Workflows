# Get the Proxmox Node Status and save it to a multiline and/or WYSIWYG custom field
#!/usr/bin/env bash

# Description: Get the Proxmox Node Status and save it to a multiline and/or WYSIWYG custom field
#
# Release Notes: Fixed online status not showing up correctly due to inactive subscription status.

# Command line arguments, swap the numbers if you want the multiline custom field to be the second argument
multiline_custom_field=$1 # First argument is the multiline custom field name
wysiwyg_custom_field=$2   # Second argument is the WYSIWYG custom field name

function IsSubscriptionActive() {
    # Check if the subscription is active
    if ! subscription_status=$(pvesh get /nodes/localhost/subscription --noborder | grep status); then
        echo "[Error] Failed to get the subscription status."
        echo "$subscription_status"
        exit 1
    fi
    # Check if the subscription is active
    if [[ $(echo "$subscription_status" | awk '{print $2}') == "active" ]]; then
        return 0
    else
        return 1
    fi
}

subscription_status=""
if IsSubscriptionActive; then
    echo "[Info] The Proxmox VE Subscription is active."
    subscription_status="active"
else
    echo "[Warn] The Proxmox VE Subscription is not active."
    subscription_status="inactive"
fi

# Check if the custom fields are set to null
if [[ -n "${multilineCustomField}" && "${multilineCustomField}" != "null" ]]; then
    multiline_custom_field=$multilineCustomField
fi
if [[ -n "${wysiwygCustomField}" && "${wysiwygCustomField}" != "null" ]]; then
    wysiwyg_custom_field=$wysiwygCustomField
fi

# Check if the custom fields are the same
if [[ -n "${multiline_custom_field}" && "${multiline_custom_field}" == "${wysiwyg_custom_field}" ]]; then
    echo "[Error] multilineCustomField and wysiwygCustomField cannot be the same custom field."
    exit 1
fi

# Check if the custom fields are not set
if [[ -z "${multiline_custom_field}" ]]; then
    echo "[Info] multilineCustomField is not set."
fi
if [[ -z "${wysiwyg_custom_field}" ]]; then
    echo "[Info] wysiwygCustomField is not set."
fi

# Check that we have the required tools
if ! command -v pvesh &>/dev/null; then
    echo "[Error] The Proxmox VE API tool 'pvesh' is required."
    exit 1
fi

# Check that we are running as root
if [[ $EUID -ne 0 ]]; then
    echo "[Error] This script must be run as root."
    exit 1
fi

# Check if ninjarmm-cli command exists
ninjarmm_cli="/opt/NinjaRMMAgent/programdata/ninjarmm-cli"
if [[ -z $ninjarmm_cli ]]; then
    echo "[Error] The ninjarmm-cli command does not exist in the default path. Please ensure the NinjaRMM agent is installed before running this script."
    exit 1
else
    # ninjarmm-cli command exists in the default path
    echo -n
fi

# Run the pvesh command to get the status information
if ! pvesh_status_output=$(pvesh get /cluster/status --noborder); then
    echo "[Error] Failed to get the Proxmox Node Status."
    echo "$pvesh_status_output"
    exit 1
fi
# Example Output from: pvesh get /cluster/status --noborder
# id        name     type    ip            level local nodeid nodes online quorate version
# cluster   cluster1 cluster                                      4        1       4
# node/pve1 pve1     node    192.168.1.10  c     0          1       1
# node/pve2 pve2     node    192.168.1.20  c     0          2       1
# node/pve3 pve3     node    192.168.1.30  c     0          3       1
# node/pve4 pve4     node    192.168.1.40  c     1          4       1

# Exclude the cluster information then skip the first line
node_status=$(echo "$pvesh_status_output" | grep -v "cluster" | tail -n +2)

# Create a table with the node status information with only the columns named id, name, ip, and online
if [[ "${subscription_status}" == "active" ]]; then
    data_table=$(echo "$node_status" | awk '{print $7, $2, $4, $8}' | column -t)
else
    data_table=$(echo "$node_status" | awk '{print $7, $2, $4, $7}' | column -t)
fi

# Convert the table to an HTML table with headers
result_table=$(echo "$data_table" | awk 'BEGIN {print "<table style=\"white-space:nowrap;\"><tr><th>Node ID</th><th>Node Name</th><th>IP Address</th><th>Online Status</th><th>Votes</th></tr>"} {print "<tr>"; for(i=1;i<=NF;i++) print "<td>" $i "</td>"; print "<td>1</td></tr>"} END {print "</table>"}')

# Save the result to the WYSIWYG custom field
if [[ -n "$wysiwyg_custom_field" ]]; then
    # Check if the NinjaRMM CLI exists and is executable
    if [[ -x "$ninjarmm_cli" ]]; then
        # Save the result to the custom field
        if hideOutput=$("$ninjarmm_cli" set "$wysiwyg_custom_field" "$result_table" 2>&1); then
            echo "[Info] Successfully set custom field: $wysiwyg_custom_field"
        else
            echo "[Error] Failed to set custom field: $wysiwyg_custom_field. Custom Field does not exist or does not have write permissions."
            _exit_code=1
        fi
    else
        echo "[Error] NinjaRMM CLI not found or not executable"
        _exit_code=1
    fi
fi

# Format the output for the multiline custom field
pvesh_status_output=$(
    # Exclude the cluster information then skip the first line
    echo "$data_table" | awk '{if (NR == 1) print "--------"; print "Node ID: " $1 "\nNode Name: " $2 "\nIP Address: " $3 "\nOnline Status: " $4 "\nVotes: 1\n"; if (NR != NF) print "--------"}'
)

# Save the result to the multiline custom field
_exit_code=0
if [[ -n "$multiline_custom_field" ]]; then
    if [[ -x "$ninjarmm_cli" ]]; then
        if hideOutput=$("$ninjarmm_cli" set "$multiline_custom_field" "$pvesh_status_output" 2>&1); then
            echo "[Info] Successfully set custom field: $multiline_custom_field"
        else
            echo "[Error] Failed to set custom field: $multiline_custom_field. Custom Field does not exist or does not have write permissions."
            _exit_code=1
        fi
    else
        echo "[Error] NinjaRMM CLI not found or not executable"
        _exit_code=1
    fi
fi

# Output the result
echo "${pvesh_status_output}"

exit $_exit_code





