# Collects system performance data (CPU, memory, disk, and network). The results can optionally be saved to a WYSIWYG custom field.
#!/usr/bin/env bash
#
# Description: Collects system performance data (CPU, memory, disk, and network). The results can optionally be saved to a WYSIWYG custom field.
#
# Example: --daysSinceLastReboot "1" --durationToPerformTests "5" --numberOfEvents "5" --wysiwygCustomFieldName "WYSIWYG"
#
# [Alert] This computer was last started on 01/22/2025 02:11:52 PM, which was 2.00 days ago.
# Collecting the last 5 warning and error events.
#
# Collecting performance metrics for 5 minutes.
# Finished collecting performance metrics.
#
# Formatting total CPU results.
# Formatting CPU process data.
# Formatting the total RAM results.
# Formatting RAM process data.
# Formatting the network usage data
# Formatting disk results.
# Formatting event log entries.
#
# Collecting system information.
#
# ### 12th Gen Intel(R) Core(TM) i9-12900H 5.0 GHz ###
# Average CPU % Used  Minimum CPU % Used  Maximum CPU % Used
# 0.50%               0.50%               0.70%
#
# ### Memory Usage ###
# Total Memory Installed: 1.04 GiB
# Average RAM % Used  Minimum RAM % Used  Maximum RAM % Used
# 73.64%              72.40%              74.44%
#
# ### Top 5 CPU Processes ###
# PID      Name             Average CPU % Used  Minimum CPU % Used  Maximum CPU % Used
# 1        systemd          0.62%               0.70%               0.90%
# 1431197  ninjarmm-linage  0.12%               0.10%               0.20%
# 1745     java             0.08%               0.10%               0.10%
# 1905     java             0.08%               0.10%               0.10%
# 10       mm_percpu_wq     0.00%               0.00%               0.00%
#
# ### Top 5 RAM Processes ###
# PID      Name             Average RAM % Used  Minimum RAM % Used  Maximum RAM % Used
# 1745     java             10.00%              10.00%              10.00%
# 1905     java             9.40%               9.40%               9.40%
# 1431197  ninjarmm-linage  6.60%               6.60%               6.60%
# 4591     powerline-daemo  1.60%               1.60%               1.60%
# 248      systemd-journal  1.50%               1.50%               1.50%
#
# ### Network Usage ###
# Network Adapter  MAC Address        Type   Average Sent & Received  Minimum Sent & Received  Maximum Sent & Received
# eth0             00:15:5d:45:d5:10  Wired  0.32 Mbps                0.11 Mbps                0.82 Mbps
#
# ### Disk Usage ###
# Mount Point  Device Path  Free Space        Total Space  Physical Disk      Media Type
# /            /dev/sda2    113.50 GiB (97%)  123.01 GiB   Msft Virtual Disk  HDD
# /boot/efi    /dev/sda1    0.49 GiB (98%)    0.50 GiB     Msft Virtual Disk  HDD
#
# The custom field 'WYSIWYG' has been provided.
# Converting CPU process data into HTML.
# Converting RAM process data into HTML.
# Converting network usage data into HTML.
# Converting disk usage data into HTML.
# Assembling the html data into the html card
# Highlighting last startup date.
# Highlighting overall CPU usage metrics.
# Highlighting overall RAM usage metrics.
# Converting journalctl data into HTML format.
#
# Attempting to set the custom field 'WYSIWYG'.
# Successfully set the custom field 'WYSIWYG'.
#
# ### Last 5 warnings and errors in the journalctl log. ###
# Service  PID  Time Created          Message
# kernel   N/A  01/21/25 10:33:01 AM  TCP: eth0: Driver has suspect GRO implementation, TCP performance may be compromised.
# kernel   N/A  01/21/25 10:33:00 AM  FAT-fs (sda1): Volume was not properly unmounted. Some data may be corrupt. Please run fsck.
# kernel   N/A  01/21/25 10:32:57 AM  device-mapper: core: CONFIG_IMA_DISABLE_HTABLE is disabled. Duplicate IMA measurements will not be recorded in the IMA log.
# kernel   N/A  01/21/25 10:32:57 AM  ima: Can not allocate sha384 (reason: -2)
# kernel   N/A  01/21/25 10:32:57 AM  tpm_crb VTPM0101:00: [Firmware Bug]: Bad ACPI memory layout
#
# Preset Parameter: --daysSinceLastReboot "7"
#		Specify the number of days by which the system should have been rebooted.
#
# Preset Parameter: --durationToPerformTests "5"
#		The duration (in minutes) for which the performance tests should be executed.
#
# Preset Parameter: --numberOfEvents "5"
#		The number of error and warning events to retrieve from the journalctl log.
#
# Preset Parameter: --wysiwygCustomField "ReplaceMeWithAnyWYSIWYGCustomField"
#		Optionally specify the name of a WYSIWYG custom field to store the formatted performance data.
#
# Preset Parameter: --help
#		Displays some help text.
#
# Release Notes: Initial Release

# Script arguments
_arg_daysSinceLastReboot=
_arg_durationToPerformTests=5
_arg_numberOfEvents=5
_arg_wysiwygCustomField=
exitCode=0

# Converts a string input into an HTML table format.
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

  _arg_inputObject=${_arg_inputObject//"%"/"%%"}

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

# Help menu
print_help() {
  printf '\n\n%s\n\n' 'Usage: [--daysSinceLastReboot|-r <arg>] [--durationToPerformTests|-d <arg>] [--numberOfEvents|-n <arg>]
  [--wysiwygCustomField|-w <arg>] [--help|-h]'
  printf '%s\n' 'Preset Parameter: --daysSinceLastReboot "7"'
  printf '\t%s\n' "Specify the number of days by which the system should have been rebooted."
  printf '%s\n' 'Preset Parameter: --durationToPerformTests "5"'
  printf '\t%s\n' "The duration (in minutes) for which the performance tests should be executed."
  printf '%s\n' 'Preset Parameter: --numberOfEvents "5"'
  printf '\t%s\n' "The number of error and warning events to retrieve from the journalctl log."
  printf '%s\n' 'Preset Parameter: --wysiwygCustomField "ReplaceMeWithAnyWYSIWYGCustomField"'
  printf '\t%s\n' "Optionally specify the name of a WYSIWYG custom field to store the formatted performance data."
  printf '%s\n' 'Preset Parameter: --help'
  printf '\t%s\n' "Displays this help menu."
}

die() {
  local _ret="${2:-1}"
  echo "$1" >&2
  test "${_PRINT_HELP:-no}" = yes && print_help >&2
  exit "${_ret}"
}

# Parses the given command line parameters
parse_commandline() {
  while test $# -gt 0; do
    _key="$1"
    case "$_key" in
    --daysSinceLastReboot | --dayssincelastreboot | --days | -r)
      test $# -lt 2 && die "[Error] Missing value for the optional argument '$_key'." 1
      _arg_daysSinceLastReboot=$2
      shift
      ;;
    --daysSinceLastReboot=*)
      _arg_daysSinceLastReboot="${_key##--daysSinceLastReboot=}"
      ;;
    --durationToPerformTests | --durationtoperformtests | --duration | -d)
      test $# -lt 2 && die "[Error] Missing value for the optional argument '$_key'." 1
      _arg_durationToPerformTests=$2
      shift
      ;;
    --durationToPerformTests=*)
      _arg_durationToPerformTests="${_key##--durationToPerformTests=}"
      ;;
    --numberOfEvents | --numberofevents | --events | -n)
      test $# -lt 2 && die "[Error] Missing value for the optional argument '$_key'." 1
      _arg_numberOfEvents=$2
      shift
      ;;
    --numberOfEvents=*)
      _arg_numberOfEvents="${_key##--numberOfEvents=}"
      ;;
    --wysiwygCustomField | --wysiwygcustomfield | --wysiwyg | -w)
      test $# -lt 2 && die "[Error] Missing value for the optional argument '$_key'." 1
      _arg_wysiwygCustomField=$2
      shift
      ;;
    --wysiwygCustomField=*)
      _arg_wysiwygCustomField="${_key##--wysiwygCustomField=}"
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

echo " "

# If script form variables are used, replace the command line parameters with their value.
if [[ -n $daysSinceLastReboot ]]; then
  _arg_daysSinceLastReboot="$daysSinceLastReboot"
fi
if [[ -n $durationToPerformTests ]]; then
  _arg_durationToPerformTests="$durationToPerformTests"
fi
if [[ -n $numberOfEvents ]]; then
  _arg_numberOfEvents="$numberOfEvents"
fi
if [[ -n $wysiwygCustomFieldName ]]; then
  _arg_wysiwygCustomField="$wysiwygCustomFieldName"
fi

# Ensure the script is being run with root permissions
if [[ $(id -u) -ne 0 ]]; then
  _PRINT_HELP=no die "[Error] This script must be run with root permissions. Try running it with sudo or as the system/root user." 1
fi

# Validate and sanitize the 'Days Since Last Reboot' argument
if [[ -n "$_arg_daysSinceLastReboot" ]]; then
  _arg_daysSinceLastReboot=$(echo "$_arg_daysSinceLastReboot" | xargs)

  # Check if the argument is empty after trimming
  if [[ -z "$_arg_daysSinceLastReboot" ]]; then
    _PRINT_HELP=yes die "[Error] The 'Days Since Last Reboot' value of '$_arg_daysSinceLastReboot' is invalid. Please provide a positive whole number or 0."
  fi
fi

# Ensure 'Days Since Last Reboot' is a valid numeric value
if [[ -n "$_arg_daysSinceLastReboot" && "$_arg_daysSinceLastReboot" =~ [^0-9] ]]; then
  _PRINT_HELP=yes die "[Error] The 'Days Since Last Reboot' value of '$_arg_daysSinceLastReboot' is invalid. Please provide a positive whole number or 0." 1
fi

# Validate and sanitize the 'Duration To Perform Tests' argument
if [[ -n "$_arg_durationToPerformTests" ]]; then
  _arg_durationToPerformTests=$(echo "$_arg_durationToPerformTests" | xargs)
fi

# Ensure the duration is provided
if [[ -z "$_arg_durationToPerformTests" ]]; then
  _PRINT_HELP=yes die "[Error] Please provide a valid duration for performing the tests." 1
fi

# Check if the duration is a valid positive number between 1 and 60
if [[ "$_arg_durationToPerformTests" =~ [^0-9] || "$_arg_durationToPerformTests" -eq 0 || "$_arg_durationToPerformTests" -gt 60 ]]; then
  _PRINT_HELP=yes die "[Error] The 'Duration To Perform Tests' value of '$_arg_durationToPerformTests' is invalid.
[Error] Please provide a positive whole number that's greater than 0 and less than or equal to 60." 1
fi

# Validate and sanitize the 'Number of Events' argument
if [[ -n "$_arg_numberOfEvents" ]]; then
  _arg_numberOfEvents=$(echo "$_arg_numberOfEvents" | xargs)
fi

# Ensure the number of events is provided
if [[ -z "$_arg_numberOfEvents" ]]; then
  _PRINT_HELP=yes die "[Error] Please provide a valid number of recent warning and error events to include in the results." 1
fi

# Check if the number of events is a valid numeric value and within the allowed range
if [[ "$_arg_numberOfEvents" =~ [^0-9] || "$_arg_numberOfEvents" -gt 2147483647 ]]; then
  _PRINT_HELP=yes die "[Error] The 'Number of Events' value of '$_arg_numberOfEvents' is invalid. Please provide a positive whole number that is less than 2147483648 or 0." 1
fi

# Validate and sanitize the 'WYSIWYG Custom Field' argument
if [[ -n "$_arg_wysiwygCustomField" ]]; then
  _arg_wysiwygCustomField=$(echo "$_arg_wysiwygCustomField" | xargs)

  # Check if the argument is empty
  if [[ -z "$_arg_wysiwygCustomField" ]]; then
    _PRINT_HELP=yes die "[Error] The 'WYSIWYG Custom Field' value of '$_arg_wysiwygCustomField' is invalid. Please provide a valid custom field name.
  https://ninjarmm.zendesk.com/hc/en-us/articles/360060920631-Custom-Field-Setup" 1
  fi
fi

# Check if the custom field contains invalid characters
if [[ -n "$_arg_wysiwygCustomField" && "$_arg_wysiwygCustomField" =~ [^0-9a-zA-Z0-9] ]]; then
  _PRINT_HELP=yes die "[Error] The 'WYSIWYG Custom Field' value of '$_arg_wysiwygCustomField' is invalid. Please provide a valid custom field name.
  https://ninjarmm.zendesk.com/hc/en-us/articles/360060920631-Custom-Field-Setup" 1
fi

# Locate the ninjarmm-cli tool, which is required for setting custom fields
if [[ -n "$_arg_wysiwygCustomField" ]]; then
  if [[ -n $NINJA_DATA_PATH && -f "$NINJA_DATA_PATH/ninjarmm-cli" ]]; then
    ninjarmmcliPath="$NINJA_DATA_PATH/ninjarmm-cli"
  elif [[ -f "/opt/NinjaRMMAgent/programdata/ninjarmm-cli" ]]; then
    ninjarmmcliPath=/opt/NinjaRMMAgent/programdata/ninjarmm-cli
  else
    _PRINT_HELP=no die "[Error] Unable to locate ninjarmm-cli. ninjarmm-cli is required to set custom fields.
    https://ninjarmm.zendesk.com/hc/en-us/articles/4405408656013-Custom-Fields-and-Documentation-CLI-and-Scripting#h_01FB4NZ6GCG2V53NS4T1RQX8PY" 1
  fi
fi

# Ensure the script does not run if another instance is already running
lockFile=/opt/NinjaRMMAgent/SystemPerformance.lock
if [[ -f "$lockFile" ]]; then
  echo "Process lock file found at '$lockFile'. Checking if the process is still running."

  if ! otherScript=$(cat "$lockFile"); then
    _PRINT_HELP=no die "[Error] Unable to access the lock file at '$lockFile'." 1
  fi

  if [[ -d "/proc/$otherScript" ]]; then
    _PRINT_HELP=no die "[Error] This script is already running in another process with the process id (PID) '$otherScript'. Please wait for that process to complete." 1
  fi
fi

# Create a lock file to prevent multiple script instances
if ! echo $$ >$lockFile; then
  _PRINT_HELP=no die "[Error] Failed to create the process lock file at '$lockFile'. This is to prevent multiple instances of the performance script from running simultaneously." 1
fi

# Record the start date and time of the script
reportStartDate=$(date "+%x %r")

# Calculate the system's last boot time and check if it exceeds the allowed days since reboot
lastBoot=$(date -d "$(uptime -s)" "+%s")
lastStartupDate=$(date -d "@$lastBoot" "+%x %r")
if [[ -n "$_arg_daysSinceLastReboot" && $(date -d "-$_arg_daysSinceLastReboot days" "+%s") -gt "$lastBoot" ]]; then
  secondsSinceLastBoot=$(($(date "+%s") - lastBoot))
  daysSinceLastBoot=$(echo "$secondsSinceLastBoot" | awk '{printf "%.2f\n", $1 / 86400}')
  echo "[Alert] This computer was last started on $lastStartupDate, which was $daysSinceLastBoot days ago."

  exceededLastStartupLimit="true"
fi

# Collect warning and error events from the system logs
if [[ "$_arg_numberOfEvents" -gt 0 ]]; then
  echo "Collecting the last $_arg_numberOfEvents warning and error events."

  if ! journalctl -r -p warning -n "$_arg_numberOfEvents" -o short-iso >/tmp/journal.log; then
    echo "[Error] Failed to retrieve the last $_arg_numberOfEvents events." >&2
    exitCode=1
  fi

  if [[ -f "/tmp/journal.log" ]]; then
    journalLines=$(wc -l /tmp/journal.log | grep -o "[0-9]*" | xargs)
  fi

  if [[ -z "$journalLines" || "$journalLines" =~ [^0-9] || "$journalLines" -le 1 ]]; then
    echo "[Warning] No errors or warnings were found in the journalctl log. Is the journalctl service enabled and configured with an adequate file size limit?"
  fi
fi

# Collect CPU, RAM, network, and disk performance metrics
echo ""
echo "Collecting performance metrics for $_arg_durationToPerformTests minutes."
COLUMNS=10000 top -b -d 60 -n "$((_arg_durationToPerformTests + 1))" -o %CPU >/tmp/cpuData.log 2>/tmp/cpuDataErr.log &
COLUMNS=10000 top -b -d 60 -n "$((_arg_durationToPerformTests + 1))" -o %MEM >/tmp/memData.log 2>/tmp/memDataErr.log &
cat "/proc/net/dev" >/tmp/netData.log 2>/tmp/netDataErr.log
df --output=target,source,avail,size,pcent | {
  read -r header
  echo "$header"
  sort -k1,1
} >/tmp/diskData.log 2>/tmp/diskData.log

# Continuously gather network metrics over the specified duration
i=1
while [[ $i -lt "$_arg_durationToPerformTests" ]]; do
  cat "/proc/net/dev" >>/tmp/netData.log 2>>/tmp/netDataErr.log
  sleep 60
  i=$((i + 1))
done

# Wait for background tasks to complete
wait

# Validate collected performance data and handle errors
if [[ -s "/tmp/cpuDataErr.log" ]]; then
  cat "/tmp/cpuDataErr.log" >&2
  _PRINT_HELP=no die "[Error] Errors were detected while attempting to gather CPU performance metrics." 1
fi
if [[ ! -s "/tmp/cpuData.log" ]]; then
  _PRINT_HELP=no die "[Error] No cpu performance metrics were collected." 1
fi
if [[ -s "/tmp/memDataErr.log" ]]; then
  cat "/tmp/memDataErr.log" >&2
  _PRINT_HELP=no die "[Error] Errors were detected while attempting to gather RAM performance metrics." 1
fi
if [[ ! -s "/tmp/memData.log" ]]; then
  _PRINT_HELP=no die "[Error] No RAM performance metrics were collected." 1
fi
if [[ -s "/tmp/diskDataErr.log" ]]; then
  cat "/tmp/diskDataErr.log" >&2
  _PRINT_HELP=no die "[Error] Errors were detected while attempting to gather disk performance metrics." 1
fi
if [[ ! -s "/tmp/diskData.log" ]]; then
  _PRINT_HELP=no die "[Error] No disk performance metrics were collected." 1
fi
if [[ -s "/tmp/netDataErr.log" ]]; then
  cat "/tmp/netDataErr.log" >&2
  _PRINT_HELP=no die "[Error] Errors were detected while attempting to gather network performance metrics." 1
fi
if [[ ! -s "/tmp/netData.log" ]]; then
  _PRINT_HELP=no die "[Error] No network performance metrics were collected." 1
fi

# Indicate the completion of performance metric collection
echo "Finished collecting performance metrics."
echo ""

# Process and format the total CPU usage metrics
echo "Formatting total CPU results."
cpuTotalData=$(
  awk '
    BEGIN {
      # Define the table header for CPU results
      header = "Average CPU % Used;Minimum CPU % Used;Maximum CPU % Used"
    }
    /^[[:space:]]*%Cpu\(s\):/ && NF > 8{

      # Extract CPU idle percentage and calculate the used percentage
      if ($7 ~ /[0-9]/) {
        split($7, cpuIdlePerc,",")
        cpuPerc = 100 - cpuIdlePerc[2]
      } else {
        cpuPerc = 100 - $8
      }

      # Aggregate metrics
      countCpu += 1
      cpuSum += cpuPerc

      # Determine minimum and maximum CPU usage
      if(! cpuMin ){ cpuMin = cpuPerc }
      if(cpuPerc < cpuMin){ cpuMin = cpuPerc }
      if(! cpuMax){ cpuMax = cpuPerc }
      if(cpuPerc > cpuMax){ cpuMax = cpuPerc }
    }
    END {
      # Print the formatted CPU usage data
      print header
      avgCpu = cpuSum / countCpu
      printf "%.2f%%;%.2f%%;%.2f%%\n", avgCpu, cpuMin, cpuMax
    }
  ' '/tmp/cpuData.log'
)

# Extract specific CPU metrics (average, minimum, and maximum) from the formatted data
CPUAverage=$(echo "$cpuTotalData" | column -t -s ";" | grep "[0-9]" | awk '{ print $1 }')
CPUMinimum=$(echo "$cpuTotalData" | column -t -s ";" | grep "[0-9]" | awk '{ print $2 }')
CPUMaximum=$(echo "$cpuTotalData" | column -t -s ";" | grep "[0-9]" | awk '{ print $3 }')

# Process and format CPU usage by process
echo "Formatting CPU process data."
cpuProcessData=$(
  awk '
    BEGIN {
      # Define the table header for process-level CPU metrics
      header = "PID;Name;Average CPU % Used;Minimum CPU % Used;Maximum CPU % Used"
    }
    /^[[:space:]]*[0-9]/ && NF > 8{
      # Extract process information (PID, name, and CPU usage)
      procId = $1
      procName = $NF
      cpuPerc = $9

      # Aggregate CPU metrics for each process
      sumCpu[procId] += cpuPerc
      countCpu[procId] += 1
      pidName[procId] = procName

      # Determine minimum and maximum CPU usage for each process
      if(! cpuMin[procId] ){ cpuMin[procId] = cpuPerc }
      if(cpuPerc < cpuMin[procId]){ cpuMin[procId] = cpuPerc }
      if(! cpuMax[procId]){ cpuMax[procId] = cpuPerc }
      if(cpuPerc > cpuMax[procId]){ cpuMax[procId] = cpuPerc }
    }
    END {
      # Print the formatted process-level CPU data
      print header
      for (pid in sumCpu) {
        avgCpu = sumCpu[pid] / countCpu[pid]
        printf "%s;%s;%.2f%%;%.2f%%;%.2f%%\n", pid, pidName[pid], avgCpu, cpuMin[pid], cpuMax[pid]
      }
    }
  ' '/tmp/cpuData.log' | {
    # Sort and display the top 6 processes by average CPU usage
    read -r header
    echo "$header"
    sort -t ';' -k3,3nr
  } | head -n 6
)

# Process and format the total RAM usage metrics
echo "Formatting the total RAM results."
memTotalData=$(
  awk '
    BEGIN {
      # Define the table header for RAM results
      header = "Average RAM % Used;Minimum RAM % Used;Maximum RAM % Used"
    }
    /.* Mem :/ && NF > 8{
      # Extract total and free memory and calculate used percentage
      memTotal = $4
      memFree = $6
      memUsed = $4 - $6
      memPerc = ( memUsed / memTotal ) * 100

      # Aggregate metrics
      memSum += memPerc
      memCount += 1

      # Determine minimum and maximum RAM usage
      if(! memMin ){ memMin = memPerc }
      if(memPerc < memMin){ memMin = memPerc }
      if(! memMax){ memMax = memPerc }
      if(memPerc > memMax){ memMax = memPerc }
    }
    END {
      # Print the formatted RAM usage data
      print header
      avgMem = memSum / memCount
      printf "%.2f%%;%.2f%%;%.2f%%\n", avgMem, memMin, memMax
    }
  ' '/tmp/memData.log'
)

# Extract specific RAM metrics (average, minimum, and maximum) from the formatted data
MEMAverage=$(echo "$memTotalData" | column -t -s ";" | grep "[0-9]" | awk '{ print $1 }')
MEMMinimum=$(echo "$memTotalData" | column -t -s ";" | grep "[0-9]" | awk '{ print $2 }')
MEMMaximum=$(echo "$memTotalData" | column -t -s ";" | grep "[0-9]" | awk '{ print $3 }')

# Process and format RAM usage by process
echo "Formatting RAM process data."
memProcessData=$(
  awk '
    BEGIN {
      # Define the table header for process-level RAM metrics
      header = "PID;Name;Average RAM % Used;Minimum RAM % Used;Maximum RAM % Used"
    }
    /^[[:space:]]*[0-9]/ && NF > 8 {
      # Extract process information (PID, name, and RAM usage)
      procId = $1
      procName = $NF
      ramPerc = $10

      # Aggregate RAM metrics for each process
      sumRam[procId] += ramPerc
      countRam[procId] += 1
      pidName[procId] = procName

      # Determine minimum and maximum RAM usage for each process
      if(! ramMin[procId] ){ ramMin[procId] = ramPerc }
      if(ramPerc < ramMin[procId]){ ramMin[procId] = ramPerc }
      if(! ramMax[procId]){ ramMax[procId] = ramPerc }
      if(ramPerc > ramMax[procId]){ ramMax[procId] = ramPerc }
    }
    END {
      # Print the formatted process-level RAM data
      print header
      for (pid in sumRam) {
        avgRam = sumRam[pid] / countRam[pid]
        printf "%s;%s;%.2f%%;%.2f%%;%.2f%%\n", pid, pidName[pid], avgRam, ramMin[pid], ramMax[pid]
      }
    }
  ' '/tmp/memData.log' | {
    # Sort and display the top 6 processes by average RAM usage
    read -r header
    echo "$header"
    sort -t ';' -k3,3nr
  } | head -n 6
)

# Process and format network usage metrics
echo "Formatting the network usage data."
netData=$(
  awk '
    BEGIN {
      # Define the table header for network usage metrics
      header = "Network Adapter;MAC Address;Type;Average Sent & Received;Minimum Sent & Received;Maximum Sent & Received"
    }
    /^.*:/ && NF > 8 && ! /^[[:space:]]*lo:/ {
      # Collect network usage statistics for each adapter
      split($1, netAdapter, ":")
      receivedBytes = $2
      transmittedBytes = $10

      # Calculate total transmitted and received data
      if (! startingTotal[netAdapter[1]]) {
        startingTotal[netAdapter[1]] = (receivedBytes + transmittedBytes)
        next
      }
      totalBits = ((receivedBytes + transmittedBytes) - startingTotal[netAdapter[1]]) * 8
      totalMegabits = totalBits / 1000000

      # Aggregate metrics
      netSum[netAdapter[1]] += totalMegabits
      countAdapter[netAdapter[1]] += 1
      adapterName[netAdapter[1]] = netAdapter[1]

      # Get MAC address
      ipLink = "ip link show " netAdapter[1]
      while ((ipLink | getline line) > 0) {
        if (line ~ /link\/ether/) {
          n = split(line, a, " ")

          for (i = 1; i <= n; i++) {
            if (a[i] == "link/ether") {
              adapterMac[netAdapter[1]] = a[i+1]
            }
          }
        }
      }
      close(ipLink)
      
      # Get the adapter type
      netType = "/sys/class/net/" netAdapter[1] "/type"
      while ((getline line < netType) > 0) {
        if (line == 1) {
          adapterType[netAdapter[1]] = "Wired"
        } 
        
        if (line == 801) {
          adapterType[netAdapter[1]] = "Wi-Fi"
        }
        
        if ( line != 801 && line != 1) {
          adapterType[netAdapter[1]] = "Other"
        }
      }
      close(netType)

      # Get the minimum and maximum
      if(! netMin[netAdapter[1]]){ netMin[netAdapter[1]] = totalMegabits }
      if(totalMegabits < netMin[netAdapter[1]]){ netMin[netAdapter[1]] = totalMegabits }
      if(! netMax[netAdapter[1]]){ netMax[netAdapter[1]] = totalMegabits }
      if(totalMegabits > netMax[netAdapter[1]]){ netMax[netAdapter[1]] = totalMegabits }
    }
    END {
      # Print the formatted network usage data
      print header
      for (adapter in netSum) {
        avgNet = netSum[adapter] / countAdapter[adapter]
        printf "%s;%s;%s;%.2f Mbps;%.2f Mbps;%.2f Mbps\n", adapterName[adapter], adapterMac[adapter], adapterType[adapter], avgNet, netMin[adapter], netMax[adapter]
      }
    }
  ' '/tmp/netData.log'
)

echo "Formatting disk results."
diskData=$(
  awk '
    BEGIN {
      # Define the table header for disk usage metrics
      header = "Mount Point;Device Path;Free Space;Total Space;Physical Disk;Media Type"
      print header
    }
    /^\// {
      # Extract disk usage information for each mounted device
      mountedOn = $1
      filesystem = $2
      availPerc = 100 - $5
      freeSpaceGiB = $3 / (1024^2)
      totalSpaceGiB_num = $4 / (1024^2)

      # Format free and total space
      freeSpace = sprintf("%.2f GiB (%.0f%%)", freeSpaceGiB, availPerc)
      totalSpaceGiB = sprintf("%.2f GiB", totalSpaceGiB_num)

      # Skip if the filesystem indicates its not actually stored on a disk
      if(filesystem == "none"){
        next
      }

      if(filesystem == "tmpfs"){
        next
      }

      if(filesystem == "rootfs"){
        next
      }

      if(filesystem == "devtmpfs"){
        next
      }

      if(filesystem == "udev"){
        next
      }

      # Extract the device name
      findDeviceName = "lsblk -no PKNAME $(findmnt -n -o SOURCE " mountedOn ") 2>/dev/null"
      while ((findDeviceName | getline line) > 0) {
        if (line ~ /[A-Za-z0-9]/) {
          deviceName = line
        }
      }
      close(findDeviceName)

      vendorPath = "/sys/block/" deviceName "/device/vendor"
      modelPath = "/sys/block/" deviceName "/device/model"

      # Retrieve the vendor of the drive
      physicalDiskCount = 0
      while ((getline line < vendorPath) > 0) {
        deviceVendor = line
        gsub(/^[ \t]+|[ \t]+$/, "", deviceVendor)
        physicalDiskCount+=1
      }
      close(vendorPath)

      # Retrieve the model of the drive
      while ((getline line < modelPath) > 0) {
        deviceModel = line
        gsub(/^[ \t]+|[ \t]+$/, "", deviceModel)
        physicalDiskCount+=1
      }
      close(modelPath)

      # If the information is found add it to the table
      if (physicalDiskCount != 0){
        if (deviceVendor){
          physicalDisk = deviceVendor " " deviceModel
        }else{
          physicalDisk = deviceModel
        }
      }else{
        physicalDisk = "Unspecified"
      }

      # Determine if the device is an HDD or SSD
      rotationPath = "/sys/block/" deviceName "/queue/rotational"
      rotationCount = 0
      while ((getline line < rotationPath) > 0) {
        rotationCount+=1
        if (line == 0) { deviceType = "SSD" }
        if (line == 1) { deviceType = "HDD" }
        if (line != 0 && line != 1){ deviceType = "Unspecified" }
      }
      close(rotationPath)

      # If no information is found set the device type to "Unspecified"
      if (rotationCount == 0){ deviceType = "Unspecified" }

      # Print the formatted disk usage data
      printf "%s;%s;%s;%s;%s;%s\n", mountedOn, filesystem, freeSpace, totalSpaceGiB, physicalDisk, deviceType
    }
  ' '/tmp/diskData.log'
)

# Check if the journal log file exists and is not empty
if [[ -f "/tmp/journal.log" && -s "/tmp/journal.log" ]]; then
  # Count the number of lines in the journal log file
  journalLines=$(wc -l /tmp/journal.log | grep -o "[0-9]*" | xargs)

  # If there are more than one line in the journal log, process the log entries
  if [[ "$journalLines" -ge 1 ]]; then
    echo "Formatting event log entries."

    # Use `awk` to process the journal log and extract relevant fields
    errorEvents=$(
      awk '
      BEGIN {
        # Define the header for the formatted output
        header = "Service;PID;Time Created;Message"
        print header
      }
      /^[0-9]/ {
        # Convert the timestamp to epoch format
        getEpoch = "date -d \"" $1 "\" +%s"
        getEpoch | getline epoch
        close(getEpoch)

        # Format the timestamp to a human-readable format
        date = strftime("%x %r", epoch)

        # Extract the service, PID, and message from the log entry
        if ($3 ~ /^.*\[[0-9]*\]:/) {
          split($3, servicePart, "[")
          service = servicePart[1]

          pid = substr(servicePart[2], 1, length(servicePart[2])-2)
          split($0, messagePart, "]: ")

          message = messagePart[2]
        }else{
          split($3, servicePart, ":")
          service = servicePart[1]
          pid = "N/A"

          split($0, messagePart, service": ")

          message = messagePart[2]
        }

        # Output the formatted data as a semicolon-separated string
        print service ";" pid ";" date ";" message
      }
    ' '/tmp/journal.log'
    )
  fi
fi

echo ""
echo "Collecting system information."

# Retrieve the CPU model name
CPU_NAME=$(lscpu | grep "Model name:" | head -n 1 | awk -F: '{gsub(/^[ \t]+/, "", $2); print $2}' | xargs)

# Retrieve the maximum CPU speed in MHz
CPU_SPEED_MHZ=$(dmidecode -t processor | grep "Max Speed" | sed 's/[^0-9]//g' | xargs)

# Convert the CPU speed to GHz if a valid value is retrieved
if [[ -n "$CPU_SPEED_MHZ" ]]; then
  CPU_SPEED_GHZ=$(awk "BEGIN { printf \"%.1f\", $CPU_SPEED_MHZ / 1000 }")
  CPU_SPEED_GHZ="${CPU_SPEED_GHZ} GHz"
fi

# Combine the CPU name and speed into a single variable
CPU="${CPU_NAME} ${CPU_SPEED_GHZ}"

# Retrieve the total memory installed on the system in GiB
TotalMemory=$(grep "MemTotal" /proc/meminfo | awk '{printf "%.2f GiB\n", $2 / 1024 / 1024 " GiB"}')

# Define the list of log files to clean up
logPaths=("/tmp/cpuData.log" "/tmp/cpuDataErr.log" "/tmp/diskData.log" "/tmp/diskDataErr.log" "/tmp/journal.log" "/tmp/memData.log" "/tmp/memDataErr.log" "/tmp/netData.log" "/tmp/netDataErr.log")

# Iterate over the log files and remove each if it exists
for logFile in "${logPaths[@]}"; do
  if [[ -f "$logFile" ]]; then
    # Attempt to remove the log file and handle errors if it fails
    if ! rm "$logFile"; then
      echo "[Error] Failed to remove the log file at '$logFile'." >&2
      exitCode=1
    fi
  fi
done

# Display the CPU information and formatted total CPU usage data
echo ""
echo "### $CPU ###"
echo "$cpuTotalData" | column -t -s ";"

# Display the total memory installed and the formatted total memory usage data
echo ""
echo "### Memory Usage ###"
echo "Total Memory Installed: $TotalMemory"
echo "$memTotalData" | column -t -s ";"

# Display the top 5 CPU-consuming processes
echo ""
echo "### Top 5 CPU Processes ###"
echo "$cpuProcessData" | column -t -s ";"

# Display the top 5 RAM-consuming processes
echo ""
echo "### Top 5 RAM Processes ###"
echo "$memProcessData" | column -t -s ";"

# Display the formatted network usage data
echo ""
echo "### Network Usage ###"
echo "$netData" | column -t -s ";"

# Display the formatted disk usage data
echo ""
echo "### Disk Usage ###"
echo "$diskData" | column -t -s ";"

# Check if a custom field has been provided
if [[ -n "$_arg_wysiwygCustomField" ]]; then
  echo ""
  echo "The custom field '$_arg_wysiwygCustomField' has been provided."

  # Convert CPU process data to HTML format
  echo "Converting CPU process data into HTML."
  cpuProcessMetricTable=$(echo "$cpuProcessData" | convertToHTMLTable -d ";")
  cpuProcessMetricTable=${cpuProcessMetricTable//"<th>"/"<th><b>"}
  cpuProcessMetricTable=${cpuProcessMetricTable//"</th>"/"</b></th>"}
  cpuProcessMetricTable=${cpuProcessMetricTable//"<table>"/"<table><caption style='border-top: 1px; border-left: 1px; border-right: 1px; border-style: solid; border-color: #CAD0D6'><b>Top 5 CPU Processes</b></caption>"}
  cpuProcessMetricTable=${cpuProcessMetricTable//"Average CPU % Used"/"<i class='fa-solid fa-arrow-down-up-across-line'></i>&nbsp;&nbsp;Average CPU % Used"}
  cpuProcessMetricTable=${cpuProcessMetricTable//"Minimum CPU % Used"/"<i class='fa-solid fa-arrows-down-to-line'></i>&nbsp;&nbsp;Minimum CPU % Used"}
  cpuProcessMetricTable=${cpuProcessMetricTable//"Maximum CPU % Used"/"<i class='fa-solid fa-arrows-up-to-line'></i>&nbsp;&nbsp;Maximum CPU % Used"}

  # Apply thresholds for CPU metrics to highlight warnings and danger levels
  cpuProcessMetricTable=$(
    echo "$cpuProcessMetricTable" | awk '
      BEGIN {
        dangerThreshold = 50.00
        warningThreshold = 20.00
      }
      {
        if ($0 ~ /<tr><td>/) {
          split($0, tableData, "<td>")
          
          avg = tableData[4]
          min = tableData[5]
          max = tableData[6]

          gsub(/[^0-9.]/, "", avg)
          gsub(/[^0-9.]/, "", min)
          gsub(/[^0-9.]/, "", max)

          avg += 0
          min += 0
          max += 0

          # Highlight rows based on thresholds
          if (avg > dangerThreshold || min > dangerThreshold || max > dangerThreshold) {
            sub(/<tr>/, "<tr class='\''danger'\''>");
          } else if (avg > warningThreshold || min > warningThreshold || max > warningThreshold) {
            sub(/<tr>/, "<tr class='\''warning'\''>");
          }
        }

        print $0
      }
    '
  )

  # Convert RAM process data to HTML format
  echo "Converting RAM process data into HTML."
  ramProcessMetricTable=$(echo "$memProcessData" | convertToHTMLTable -d ";")
  ramProcessMetricTable=${ramProcessMetricTable//"<th>"/"<th><b>"}
  ramProcessMetricTable=${ramProcessMetricTable//"</th>"/"</b></th>"}
  ramProcessMetricTable=${ramProcessMetricTable//"<table>"/"<table><caption style='border-top: 1px; border-left: 1px; border-right: 1px; border-style: solid; border-color: #CAD0D6'><b>Top 5 RAM Processes</b></caption>"}
  ramProcessMetricTable=${ramProcessMetricTable//"Average RAM % Used"/"<i class='fa-solid fa-arrow-down-up-across-line'></i>&nbsp;&nbsp;Average RAM % Used"}
  ramProcessMetricTable=${ramProcessMetricTable//"Minimum RAM % Used"/"<i class='fa-solid fa-arrows-down-to-line'></i>&nbsp;&nbsp;Minimum RAM % Used"}
  ramProcessMetricTable=${ramProcessMetricTable//"Maximum RAM % Used"/"<i class='fa-solid fa-arrows-up-to-line'></i>&nbsp;&nbsp;Maximum RAM % Used"}

  # Apply thresholds for RAM metrics to highlight warnings and danger levels
  ramProcessMetricTable=$(
    echo "$ramProcessMetricTable" | awk '
      BEGIN {
        dangerThreshold = 30.00
        warningThreshold = 10.00
      }
      {
        if ($0 ~ /<tr><td>/) {
          split($0, tableData, "<td>")

          avg = tableData[4]
          min = tableData[5]
          max = tableData[6]

          gsub(/[^0-9.]/, "", avg)
          gsub(/[^0-9.]/, "", min)
          gsub(/[^0-9.]/, "", max)

          avg += 0
          min += 0
          max += 0

          # Highlight rows based on thresholds
          if (avg > dangerThreshold || min > dangerThreshold || max > dangerThreshold) {
            sub(/<tr>/, "<tr class='\''danger'\''>");
          } else if (avg > warningThreshold || min > warningThreshold || max > warningThreshold) {
            sub(/<tr>/, "<tr class='\''warning'\''>");
          }
        }

        print $0
      }
    '
  )

  echo "Converting network usage data into HTML."

  # Apply formatting to the network usage table
  networkInterfaceUsage=$(echo "$netData" | convertToHTMLTable -d ";")
  networkInterfaceUsage=${networkInterfaceUsage//"<th>"/"<th><b>"}
  networkInterfaceUsage=${networkInterfaceUsage//"</th>"/"</b></th>"}
  networkInterfaceUsage=${networkInterfaceUsage//"<table>"/"<table><caption style='border-top: 1px; border-left: 1px; border-right: 1px; border-style: solid; border-color: #CAD0D6'><b>Network Usage</b></caption>"}
  networkInterfaceUsage=${networkInterfaceUsage//"Average Sent & Received"/"<i class='fa-solid fa-arrow-down-up-across-line'></i>&nbsp;&nbsp;Average Sent & Received"}
  networkInterfaceUsage=${networkInterfaceUsage//"Minimum Sent & Received"/"<i class='fa-solid fa-arrows-down-to-line'></i>&nbsp;&nbsp;Minimum Sent & Received"}
  networkInterfaceUsage=${networkInterfaceUsage//"Maximum Sent & Received"/"<i class='fa-solid fa-arrows-up-to-line'></i>&nbsp;&nbsp;Maximum Sent & Received"}
  networkInterfaceUsage=${networkInterfaceUsage//"<th><b>Type</b></th>"/"<th><b><i class='fa-solid fa-network-wired'></i>&nbsp;&nbsp;Type</b></th>"}
  networkInterfaceUsage=${networkInterfaceUsage//"<td>Wired</td>"/"<td><i class='fa-solid fa-ethernet'></i>&nbsp;&nbsp;Wired</td>"}
  networkInterfaceUsage=${networkInterfaceUsage//"<td>Wi-Fi</td>"/"<td><i class='fa-solid fa-wifi'></i>&nbsp;&nbsp;Wi-Fi</td>"}
  networkInterfaceUsage=${networkInterfaceUsage//"<td>Other</td>"/"<td><i class='fa-solid fa-circle-question'></i>&nbsp;&nbsp;Other</td>"}

  # Apply threshold-based row highlighting for network usage data
  networkInterfaceUsage=$(
    echo "$networkInterfaceUsage" | awk '
      BEGIN {
        dangerThreshold = 100.00
        warningThreshold = 10.00
      }
      {
        if ($0 ~ /<tr><td>/) {
          split($0, tableData, "<td>")

          avg = tableData[5]
          min = tableData[6]
          max = tableData[7]
          networkType = tableData[4]

          gsub(/&nbsp;/, "", networkType)
          gsub(/<i.*><\/i>/, "", networkType)
          gsub(/<\/td>/, "", networkType)

          gsub(/[^0-9.]/, "", avg)
          gsub(/[^0-9.]/, "", min)
          gsub(/[^0-9.]/, "", max)

          avg += 0
          min += 0
          max += 0

          # Highlight rows based on thresholds
          if (avg > dangerThreshold || min > dangerThreshold || max > dangerThreshold) {
            sub(/<tr>/, "<tr class='\''danger'\''>");
          } else if (avg > warningThreshold || min > warningThreshold || max > warningThreshold || networkType != "Wired" ) {
            sub(/<tr>/, "<tr class='\''warning'\''>");
          }
        }

        print $0
      }
    '
  )

  echo "Converting disk usage data into HTML."
  diskTable=$(echo "$diskData" | convertToHTMLTable -d ";")

  # Apply formatting to the disk usage table
  diskTable=${diskTable//"<th>"/"<th><b>"}
  diskTable=${diskTable//"</th>"/"</b></th>"}
  diskTable=${diskTable//"<table>"/"<table><caption style='border-top: 1px; border-left: 1px; border-right: 1px; border-style: solid; border-color: #CAD0D6'><b>Disk Usage</b></caption>"}

  # Apply threshold-based row highlighting for disk usage data
  diskTable=$(
    echo "$diskTable" | awk '
      BEGIN {
        dangerThreshold = 10.00
        warningThreshold = 100.00
      }
      {
        if ($0 ~ /<tr><td>/) {
          split($0, tableData, "<td>")

          freeSpace = tableData[4]
          mediaType = tableData[7]

          gsub(/ GiB.*/, "", freeSpace)
          gsub(/<\/td>.*/, "", mediaType)

          freeSpace += 0

          # Highlight rows based on thresholds and media type
          if (freeSpace < dangerThreshold || (mediaType != "SSD" && mediaType != "Unspecified" )) {
            sub(/<tr>/, "<tr class='\''danger'\''>");
          } else if (freeSpace < warningThreshold) {
            sub(/<tr>/, "<tr class='\''warning'\''>");
          }
        }

        print $0
      }
    '
  )

  # Record the completion date and time
  reportCompleteDate=$(date "+%x %r")

  # Assemble the HTML card for the report
  echo "Assembling the html data into the html card"
  htmlCard="<div class='card flex-grow-1'>
  <div class='card-title-box'>
    <div class='card-title'><i class='fa-solid fa-gauge-high'></i>&nbsp;&nbsp;System Performance Metrics</div>
  </div>
  <div class='card-body' style='white-space: nowrap'>
    <table style='border: 0px; justify-content: space-evenly; white-space: nowrap;'>
      <tbody>
        <tr>
          <td style='border: 0px; white-space: nowrap; padding-left: 0px;'>
            <p class='card-text'><b>Start Date and Time</b><br>$reportStartDate</p>
          </td>
          <td style='border: 0px; white-space: nowrap;'>
            <p class='card-text'><b>Completed Date and Time</b><br>$reportCompleteDate</p>
          </td>
        </tr>
      </tbody>
    </table>
    <p id='lastStartup' class='card-text'><b>Last Startup Time</b><br>$lastStartupDate</p>
    <p><b>$CPU</b></p>
    <table style='border: 0px;'>
      <tbody>
        <tr>
          <td style='border: 0px; white-space: nowrap'>
            <div class='stat-card' style='display: flex;'>
              <div class='stat-value' id='cpuOverallAvg' style='color: #008001;'>$CPUAverage</div>
              <div class='stat-desc'><i class='fa-solid fa-arrow-down-up-across-line'></i>&nbsp;&nbsp;Average CPU % Used</div>
            </div>
          </td>
          <td style='border: 0px; white-space: nowrap'>
            <div class='stat-card' style='display: flex;'>
              <div class='stat-value' id='cpuOverallMin' style='color: #008001;'>$CPUMinimum</div>
              <div class='stat-desc'><i class='fa-solid fa-arrows-down-to-line'></i>&nbsp;&nbsp;Minimum CPU % Used</div>
            </div>
          </td>
          <td style='border: 0px; white-space: nowrap'>
            <div class='stat-card' style='display: flex;'>
                <div class='stat-value' id='cpuOverallMax' style='color: #008001;'>$CPUMaximum</div>
                <div class='stat-desc'><i class='fa-solid fa-arrows-up-to-line'></i>&nbsp;&nbsp;Maximum CPU % Used</div>
            </div>
          </td>
        </tr>
      </tbody>
    </table>
    <p><b>Total Memory: $TotalMemory</b></p>
    <table style='border: 0px;'>
      <tbody>
        <tr>
          <td style='border: 0px; white-space: nowrap'>
            <div class='stat-card' style='display: flex;'>
              <div class='stat-value' id='ramOverallAvg' style='color: #008001;'>$MEMAverage</div>
              <div class='stat-desc'><i class='fa-solid fa-arrow-down-up-across-line'></i>&nbsp;&nbsp;Average RAM % Used</div>
            </div>
          </td>
          <td style='border: 0px; white-space: nowrap'>
            <div class='stat-card' style='display: flex;'>
              <div class='stat-value' id='ramOverallMin' style='color: #008001;'>$MEMMinimum</div>
              <div class='stat-desc'><i class='fa-solid fa-arrows-down-to-line'></i>&nbsp;&nbsp;Minimum RAM % Used</div>
            </div>
          </td>
          <td style='border: 0px; white-space: nowrap'>
            <div class='stat-card' style='display: flex;'>
              <div class='stat-value' id='ramOverallMax' style='color: #008001;'>$MEMMaximum</div>
              <div class='stat-desc'><i class='fa-solid fa-arrows-up-to-line'></i>&nbsp;&nbsp;Maximum RAM % Used</div>
            </div>
          </td>
        </tr>
      </tbody>
    </table>
    $cpuProcessMetricTable
    <br>
    $ramProcessMetricTable
    <br>
    $networkInterfaceUsage
    <br>
    $diskTable
    <br>
  </div>
</div>"
  if [[ "$_arg_daysSinceLastReboot" -ge 0 ]]; then
    echo "Highlighting last startup date."
  fi

  # Check if the last startup exceeded the specified limit and update the HTML card accordingly
  if [[ "$exceededLastStartupLimit" == "true" ]]; then
    # Add a red exclamation icon to highlight exceeded startup limit
    htmlCard=${htmlCard//"id='lastStartup' class='card-text'><b>Last Startup Time</b><br>$lastStartupDate"/"id='lastStartup' class='card-text'><b>Last Startup Time</b><br>$lastStartupDate&nbsp;&nbsp;<i class='fa-solid fa-circle-exclamation' style='color: #D53948;'></i>"}
  elif [[ "$_arg_daysSinceLastReboot" -ge 0 ]]; then
    # Add a green check icon to indicate a valid startup limit
    htmlCard=${htmlCard//"id='lastStartup' class='card-text'><b>Last Startup Time</b><br>$lastStartupDate"/"id='lastStartup' class='card-text'><b>Last Startup Time</b><br>$lastStartupDate&nbsp;&nbsp;<i class='fa-solid fa-circle-check' style='color: #008001;'></i>"}
  fi

  # Highlight overall CPU usage metrics based on thresholds
  echo "Highlighting overall CPU usage metrics."
  CPUNumericAverage=$(echo "$CPUAverage" | awk '{ gsub(/[^0-9.]/, ""); printf "%.0f", $1 }')
  CPUNumericMaximum=$(echo "$CPUMaximum" | awk '{ gsub(/[^0-9.]/, ""); printf "%.0f", $1 }')
  CPUNumericMinimum=$(echo "$CPUMinimum" | awk '{ gsub(/[^0-9.]/, ""); printf "%.0f", $1 }')

  # Update HTML card with warning or danger thresholds for CPU usage
  if [[ "$CPUNumericAverage" -ge 60 && "$CPUNumericAverage" -lt 90 ]]; then
    htmlCard=${htmlCard//"id='cpuOverallAvg' style='color: #008001;'"/"id='cpuOverallAvg' style='color: #FAC905;'"}
  fi
  if [[ "$CPUNumericMaximum" -ge 60 && "$CPUNumericMaximum" -lt 90 ]]; then
    htmlCard=${htmlCard//"id='cpuOverallMax' style='color: #008001;'"/"id='cpuOverallMax' style='color: #FAC905;'"}
  fi
  if [[ "$CPUNumericMinimum" -ge 60 && "$CPUNumericMinimum" -lt 90 ]]; then
    htmlCard=${htmlCard//"id='cpuOverallMin' style='color: #008001;'"/"id='cpuOverallMin' style='color: #FAC905;'"}
  fi
  if [[ "$CPUNumericAverage" -ge 90 ]]; then
    htmlCard=${htmlCard//"id='cpuOverallAvg' style='color: #008001;'"/"id='cpuOverallAvg' style='color: #D53948;'"}
  fi
  if [[ "$CPUNumericMaximum" -ge 90 ]]; then
    htmlCard=${htmlCard//"id='cpuOverallMax' style='color: #008001;'"/"id='cpuOverallMax' style='color: #D53948;'"}
  fi
  if [[ "$CPUNumericMinimum" -ge 90 ]]; then
    htmlCard=${htmlCard//"id='cpuOverallMin' style='color: #008001;'"/"id='cpuOverallMin' style='color: #D53948;'"}
  fi

  # Highlight overall RAM usage metrics based on thresholds
  echo "Highlighting overall RAM usage metrics."
  MEMNumericAverage=$(echo "$MEMAverage" | awk '{ gsub(/[^0-9.]/, ""); printf "%.0f", $1 }')
  MEMNumericMaximum=$(echo "$MEMMaximum" | awk '{ gsub(/[^0-9.]/, ""); printf "%.0f", $1 }')
  MEMNumericMinimum=$(echo "$MEMMinimum" | awk '{ gsub(/[^0-9.]/, ""); printf "%.0f", $1 }')

  # Update HTML card with warning or danger thresholds for RAM usage
  if [[ "$MEMNumericAverage" -ge 60 && "$MEMNumericAverage" -lt 90 ]]; then
    htmlCard=${htmlCard//"id='ramOverallAvg' style='color: #008001;'"/"id='ramOverallAvg' style='color: #FAC905;'"}
  fi
  if [[ "$MEMNumericMaximum" -ge 60 && "$MEMNumericMaximum" -lt 90 ]]; then
    htmlCard=${htmlCard//"id='ramOverallMax' style='color: #008001;'"/"id='ramOverallMax' style='color: #FAC905;'"}
  fi
  if [[ "$MEMNumericMinimum" -ge 60 && "$MEMNumericMinimum" -lt 90 ]]; then
    htmlCard=${htmlCard//"id='ramOverallMin' style='color: #008001;'"/"id='ramOverallMin' style='color: #FAC905;'"}
  fi
  if [[ "$MEMNumericAverage" -ge 90 ]]; then
    htmlCard=${htmlCard//"id='ramOverallAvg' style='color: #008001;'"/"id='ramOverallAvg' style='color: #D53948;'"}
  fi
  if [[ "$MEMNumericMaximum" -ge 90 ]]; then
    htmlCard=${htmlCard//"id='ramOverallMax' style='color: #008001;'"/"id='ramOverallMax' style='color: #D53948;'"}
  fi
  if [[ "$MEMNumericMinimum" -ge 90 ]]; then
    htmlCard=${htmlCard//"id='ramOverallMin' style='color: #008001;'"/"id='ramOverallMin' style='color: #D53948;'"}
  fi

  # Store the assembled HTML card as the WYSIWYG value
  wysiwygValue="$htmlCard"

  # Check if event data needs to be included in the WYSIWYG field
  if [[ "$_arg_numberOfEvents" -gt 0 ]]; then
    echo "Converting journalctl data into HTML format."
  fi

  # Convert journalctl error events to HTML format or handle missing events
  if [[ "$_arg_numberOfEvents" -gt 0 && -n "$errorEvents" ]]; then
    eventLogTableMetrics=$(echo "$errorEvents" | convertToHTMLTable -d ";")
    eventLogTableMetrics=${eventLogTableMetrics//"<th>"/"<th><b>"}
    eventLogTableMetrics=${eventLogTableMetrics//"</th>"/"</b></th>"}
    eventLogTableMetrics=${eventLogTableMetrics//"<th><b>Service"/"<th style='width: 250px'><b>Service"}
    eventLogTableMetrics=${eventLogTableMetrics//"<th><b>PID"/"<th style='width: 75px'><b>PID"}
    eventLogTableMetrics=${eventLogTableMetrics//"<th><b>Time Created"/"<th style='width: 200px'><b>Time Created"}
  elif [[ "$_arg_numberOfEvents" -gt 0 ]]; then
    eventLogTableMetrics="<p style='margin-top: 0px'>No warning or error events were found in the journalctl log.</p>"
  fi

  # Append event log data to the WYSIWYG value
  if [[ "$_arg_numberOfEvents" -gt 0 ]]; then
    eventLogCard="<div class='card flex-grow-1'>
    <div class='card-title-box'>
        <div class='card-title'><i class='fa-solid fa-book'></i>&nbsp;&nbsp;Recent Error Events</div>
    </div>
    <div class='card-body' style='white-space: nowrap'>
        $eventLogTableMetrics
    </div>
</div>"
    wysiwygValue+="$eventLogCard"

    # Check and handle the 40,000-character limit for the WYSIWYG field
    characterCount=${#wysiwygValue}
    if [[ "$characterCount" -gt 40000 ]]; then
      echo "The current character count is '$characterCount'."
      echo "[Warning] The 40,000-character limit has been reached! Trimming output to fit within the allowed limit..."
    fi

    while [[ "$characterCount" -gt 40000 ]]; do
      eventLogTableMetrics=$(echo "$eventLogTableMetrics" | sed '0,/<tr>/{/<tr>/{N;N;N;N;N;/<\/tr>/d;}}')

      wysiwygValue="$htmlCard"

      eventLogCard="<div class='card flex-grow-1'>
    <div class='card-title-box'>
        <div class='card-title'><i class='fa-solid fa-book'></i>&nbsp;&nbsp;Recent Error Events</div>
    </div>
    <div class='card-body' style='white-space: nowrap'>
        $eventLogTableMetrics
    </div>
</div>"
      wysiwygValue+="<h1>This info has been truncated to accommodate the 40,000 character limit.</h1>"
      wysiwygValue+="$eventLogCard"

      characterCount=${#wysiwygValue}
    done
  fi

  # Attempt to set the custom field using ninjarmm-cli
  echo ""
  echo "Attempting to set the custom field '$_arg_wysiwygCustomField'."
  # Try to set the multiline custom field using ninjarmm-cli and capture the output
  if ! output=$("$ninjarmmcliPath" set "$_arg_wysiwygCustomField" "$wysiwygValue" 2>&1); then
    echo "[Error] $output" >&2
    exitCode=1
  else
    echo "Successfully set the custom field '$_arg_wysiwygCustomField'."
  fi
fi

# Display the last number of events in the journalctl log
if [[ -n "$_arg_numberOfEvents" ]]; then
  echo ""
  echo "### Last $_arg_numberOfEvents warnings and errors in the journalctl log. ###"

  if [[ -n "$errorEvents" ]]; then
    echo "$errorEvents" | column -t -s ";"
  else
    echo "No errors or warnings were found in the journalctl log. Ensure the journalctl service is enabled and configured with an adequate file size limit."
  fi
fi

# Attempt to remove the lock file
if [[ -f "$lockFile" ]]; then
  if ! rm "$lockFile"; then
    echo "[Error] Failed to remove the lock file at '$lockFile'. This file prevents multiple instances of the performance script from running simultaneously." >&2
    exitCode=1
  fi
fi

exit "$exitCode"



