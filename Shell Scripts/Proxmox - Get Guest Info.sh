# This script gets the status and basic info of all Proxmox guests on a host and saves it to a WYSIWYG custom field.
#!/usr/bin/env bash

# Description: This script gets the status and basic info of all Proxmox guests on a host and saves it to a WYSIWYG custom field.
#
# Release Notes: Fixed spelling errors. Removes the need for python.
#
# Below are all the (case sensitive) valid parameters for this script.
# Only the custom field name is required!
# Preset Parameter: "Custom_Field_Name"
#   Custom_Field_Name: The name of the WYSIWYG custom field to save the VM info to.

Custom_Field_Name=$1

if [[ -n "${customFieldName}" ]]; then
    Custom_Field_Name="${customFieldName}"
fi

if [[ -z "${Custom_Field_Name}" || "${Custom_Field_Name}" == "null" ]]; then
    echo "The custom field name is required."
    echo " Example: guests"
    exit 1
fi

# Check that we have the required tools
if ! command -v pvesh &>/dev/null; then
    echo "The Proxmox VE API tool 'pvesh' is required."
    exit 1
fi

# Check that we are running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root."
    exit 1
fi

function SetCustomField() {
    local result
    if ! result=$(/opt/NinjaRMMAgent/programdata/ninjarmm-cli "$@" 2>&1); then
        echo "$result"
        return 1
    else
        return 0
    fi
}

function ConvertPveTableToHtml() {
    # Convert the Proxmox ASCII table to HTML
    #
    # This accepts the ASCII table from Proxmox on stdin and outputs the HTML table on stdout
    # This function is designed to work with the output of the pvesh get command
    # This doesn't add the table tags, so you need to wrap the output in <table> tags
    #
    # Example usage: pvesh get /nodes | ConvertPveTableToHtml
    cat - |
        sed '1s/┌/<tr>/g' |            # Replace on the first line corner with <tr>
        sed '3s/╞/<\/tr>/g' |          # Replace on the third line with </tr>
        sed '1s/┐/<th>/g' |            # Replace on the first line last corner with <th>
        sed '2s/[│]/<\/th><th>/g' |    # Replace pipes on the second line with </th><th>
        sed 's/[│]/<\/td><td>/g' |     # Replace all pipes with </td><td>
        sed 's/^<\/th>//g' |           # Remove the leading </th> we added earlier
        sed 's/<th>$//g' |             # Remove the trailing <th> we added earlier
        sed 's/[╡┤]/<tr>/g' |          # Replace the row end with <tr>
        sed 's/[├└]/<\/tr><tr>/g' |    # Replace the row start with <tr>
        sed 's/[┌┬─┼┐├┴┤└┘│╞╪═╡]//g' | # Remove all uneeded characters
        tr -d '\n' |                   # Remove new lines
        sed 's/<tr>$//g' |             # Remove the trailing <tr>
        sed 's/<tr><\/td>/<tr>/g' |    # Fix the empty <tr>
        sed 's/<tr><tr>/<tr>/g' |      # Fix duplicate <tr>
        sed 's/<td><\/tr>/<\/tr>/g' |  # Fix leading <td>
        sed 's/<th>\s*/<th>/g' |       # Remove the leading whitespace in <th>
        sed 's/\s*<\/th>/<\/th>/g' |   # Remove the trailing whitespace in </th>
        sed 's/<tr>\s*/<tr>/g' |       # Remove the leading whitespace in <tr>
        sed 's/\s*<\/tr>/<\/tr>/g' |   # Remove the trailing whitespace in </tr>
        sed 's/<td>\s*/<td>/g' |       # Remove the leading whitespace in <td>
        sed 's/\s*<\/td>/<\/td>/g'     # Remove the trailing whitespace in </td>
}

# Get the status and basic info of all Proxmox VMs on a host
qemu_guests=$(pvesh get /nodes/localhost/qemu)

# Create a table to store the VM info with the headers: Name, Status, Memory, CPUs, Disk Sizes
vm_table=""

# Convert the ASCII table to HTML for the qemu guests
qemu_table=$(echo "$qemu_guests" | ConvertPveTableToHtml)

# Only add the qemu guests if there are any
if [[ -n "${qemu_guests}" ]]; then
    vm_table="$vm_table<h2>QEMU Guests</h2><table>$qemu_table</table>"
fi

# Loop through each lxc and add the info to the table
lxc_guests=$(pvesh get /nodes/localhost/lxc)

# Convert the ASCII table to HTML for the lxc guests
lxc_table=$(echo "$lxc_guests" | ConvertPveTableToHtml)

# Only add the lxc guests if there are any
if [[ -n "${lxc_guests}" ]]; then
    vm_table="$vm_table<h2>LXC Guests</h2><table>$lxc_table</table>"
fi

# When no guests are found, display a message stating so
if [[ -n "${qemu_guests}" ]] && [[ -n "${lxc_guests}" ]]; then
    vm_table="<h2>No guests found.</h2>"
fi

# Highlight the running and stopped VMs
vm_table=$(echo "$vm_table" | sed 's/<tr><td>running<\/td>/<tr class="success"><td>Running<\/td>/g')
vm_table=$(echo "$vm_table" | sed 's/<tr><td>stopped<\/td>/<tr class="danger"><td>Stopped<\/td>/g')

# Save the table to the custom field
if ! result=$(SetCustomField set "$Custom_Field_Name" "$vm_table"); then
    if [[ -n "${result}" ]]; then
        echo "[Error] Failed to save the Proxmox VM info to the custom field: $Custom_Field_Name"
        echo "[Error] $result"
    fi
else
    echo "[Info] The Proxmox VM info has been saved to the custom field: $Custom_Field_Name"
fi

echo "QEMU Guests:"
pvesh get /nodes/localhost/qemu --noborder
echo ""
echo "LXC Guests:"
pvesh get /nodes/localhost/lxc --noborder





