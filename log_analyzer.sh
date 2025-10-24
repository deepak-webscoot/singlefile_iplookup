#!/bin/bash
set -euo pipefail

# Script: single_file_threat_checker.sh
# Description: Single file IP threat intelligence with time range filtering

SCRIPT_NAME="single_file_threat_checker.sh"
OTX_API_KEY="ad3be64c61425dcbca6a5dbd43f3c8e056ced8f3c2662dc5248c20815c083564"

# Cleanup function
cleanup() {
    rm -f "/tmp/ips.$$" "/tmp/filtered_logs.$$" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

# Display usage
usage() {
    echo "=== Single File IP Threat Intelligence ==="
    echo "Usage: $0 <access_log_file>"
    echo ""
    echo "Features:"
    echo "• Time-range filtering options"
    echo "• AlienVault OTX threat checking"
    echo "• Shows recent hits for high-risk IPs"
    echo "• Generates CSF blocking commands"
    exit 0
}

if [[ "$#" -lt 1 ]] || [[ "$1" =~ ^(-h|--help)$ ]]; then
    usage
fi

LOG_FILE="$1"

# Check if log file exists and is readable
if [[ ! -f "$LOG_FILE" ]] || [[ ! -r "$LOG_FILE" ]]; then
    echo "Error: Log file '$LOG_FILE' not found or not readable" >&2
    exit 1
fi

# Check dependencies
check_dependencies() {
    for dep in grep awk curl jq date; do
        if ! command -v "$dep" &>/dev/null; then
            echo "Error: Required tool '$dep' not found" >&2
            exit 1
        fi
    done
}

# Show menu and get time range choice
show_menu() {
    echo ""
    echo "=== TIME RANGE SELECTION ==="
    echo "1) Today's logs"
    echo "2) Last Hour (60 minutes)" 
    echo "3) Last 10 Minutes"
    echo "4) Custom time range (flexible format)"
    echo ""
    echo -n "Enter your choice (1-4): "
}

# Time range filtering functions using efficient awk commands
filter_todays_logs() {
    local log_file="$1"
    local output_file="$2"
    
    echo "Filtering today's logs..."
    
    # Efficient today's filter - always get top 30 IPs
    awk -v d="$(date "+%d/%b/%Y")" '$4 ~ d {print $1}' "$log_file" | \
    sort | uniq -c | sort -nr | head -30 > "$output_file"
    
    local ip_count
    ip_count=$(wc -l < "$output_file" 2>/dev/null | awk '{print $1}')
    
    if [[ "$ip_count" -eq 0 ]]; then
        echo "Error: No IP addresses found for today" >&2
        return 1
    fi
    
    echo "Found $ip_count IPs for today"
    return 0
}

filter_last_hour() {
    local log_file="$1"
    local output_file="$2"
    
    echo "Filtering logs from last hour..."
    
    # Efficient last hour filter - always get top 30 IPs
    awk -v d="$(date --date='1 hour ago' "+%d/%b/%Y:%H")" '$4 ~ d {print $1}' "$log_file" | \
    sort | uniq -c | sort -nr | head -30 > "$output_file"
    
    local ip_count
    ip_count=$(wc -l < "$output_file" 2>/dev/null | awk '{print $1}')
    
    if [[ "$ip_count" -eq 0 ]]; then
        echo "Error: No IP addresses found for last hour" >&2
        return 1
    fi
    
    echo "Found $ip_count IPs from last hour"
    return 0
}

filter_last_10min() {
    local log_file="$1"
    local output_file="$2"
    
    echo "Filtering logs from last 10 minutes..."
    
    # Efficient last 10 minutes filter - always get top 30 IPs
    awk -v d="$(date -d '10 min ago' '+%d/%b/%Y:%H:%M')" '$4 > "["d {print $1}' "$log_file" | \
    sort | uniq -c | sort -nr | head -30 > "$output_file"
    
    local ip_count
    ip_count=$(wc -l < "$output_file" 2>/dev/null | awk '{print $1}')
    
    if [[ "$ip_count" -eq 0 ]]; then
        echo "Error: No IP addresses found for last 10 minutes" >&2
        return 1
    fi
    
    echo "Found $ip_count IPs from last 10 minutes"
    return 0
}

filter_custom_range() {
    local log_file="$1"
    local output_file="$2"
    
    echo ""
    echo "Custom Time Range Options:"
    echo "Examples:"
    echo "  - 07:00-20:00    (7AM to 8PM)"
    echo "  - 09:00-09:23    (9AM to 9:23AM)" 
    echo "  - 14:30-15:45    (2:30PM to 3:45PM)"
    echo ""
    echo -n "Enter time range (HH:MM-HH:MM): "
    read -r time_range
    
    # Validate time range format
    if ! [[ "$time_range" =~ ^[0-9]{1,2}:[0-9]{2}-[0-9]{1,2}:[0-9]{2}$ ]]; then
        echo "Error: Invalid time format. Use HH:MM-HH:MM format." >&2
        return 1
    fi
    
    local start_time end_time
    start_time=$(echo "$time_range" | cut -d'-' -f1)
    end_time=$(echo "$time_range" | cut -d'-' -f2)
    
    # Normalize times to HH:MM format
    start_time=$(date -d "$start_time" +"%H:%M" 2>/dev/null || echo "$start_time")
    end_time=$(date -d "$end_time" +"%H:%M" 2>/dev/null || echo "$end_time")
    
    echo "Filtering logs from $start_time to $end_time..."
    
    # Get today's date for filtering
    local today
    today=$(date +"%d/%b/%Y")
    
    # Efficient custom range filtering - always get top 30 IPs
    awk -v today="$today" -v start="$start_time" -v end="$end_time" '
    {
        # Extract date and time from log line (field 4)
        if (match($4, /\[([0-9]{2}\/[A-Za-z]{3}\/[0-9]{4}):([0-9]{2}:[0-9]{2}:[0-9]{2})/, m)) {
            log_date = m[1]
            log_time = m[2]
            # Extract just HH:MM from HH:MM:SS
            time_part = substr(log_time, 1, 5)
            if (log_date == today && time_part >= start && time_part <= end) {
                print $1
            }
        }
    }' "$log_file" | sort | uniq -c | sort -nr | head -30 > "$output_file"
    
    local ip_count
    ip_count=$(wc -l < "$output_file" 2>/dev/null | awk '{print $1}')
    
    if [[ "$ip_count" -eq 0 ]]; then
        echo "Error: No IP addresses found for custom range" >&2
        return 1
    fi
    
    echo "Found $ip_count IPs in custom range"
    return 0
}

# Get raw log entries for recent hits display
get_raw_logs_for_time_range() {
    local log_file="$1"
    local time_range="$2"
    
    case "$time_range" in
        "today")
            # Get today's raw log entries
            grep "$(date "+%d/%b/%Y")" "$log_file" 2>/dev/null || echo ""
            ;;
        "last_hour")
            # Get last hour raw log entries  
            local hour_pattern
            hour_pattern=$(date --date='1 hour ago' "+%d/%b/%Y:%H")
            grep "\[$hour_pattern" "$log_file" 2>/dev/null || echo ""
            ;;
        "last_10min")
            # Get last 10 minutes raw log entries using efficient method
            awk -v d="$(date -d '10 min ago' '+%d/%b/%Y:%H:%M')" '$4 > "["d' "$log_file" 2>/dev/null || echo ""
            ;;
        "custom")
            # For custom range, return all of today's logs and we'll filter later
            grep "$(date "+%d/%b/%Y")" "$log_file" 2>/dev/null || echo ""
            ;;
    esac
}

# Check IP against AlienVault OTX
check_ip_threat() {
    local ip="$1"
    
    local response
    response=$(curl -s --max-time 10 --connect-timeout 5 \
              "https://otx.alienvault.com/api/v1/indicators/IPv4/$ip/general" \
              -H "X-OTX-API-KEY: $OTX_API_KEY" 2>/dev/null || echo '{}')
    
    local pulses
    pulses=$(echo "$response" | jq -r '.pulse_info.count // 0' 2>/dev/null || echo 0)
    
    local country
    country=$(echo "$response" | jq -r '.country_name // "Unknown"' 2>/dev/null || echo "Unknown")
    
    echo "$pulses|$country"
}

# Calculate risk level
get_risk_level() {
    local pulses="$1"
    
    if [[ "$pulses" -gt 10 ]]; then
        echo "HIGH"
    elif [[ "$pulses" -gt 5 ]]; then
        echo "MEDIUM" 
    elif [[ "$pulses" -gt 0 ]]; then
        echo "LOW"
    else
        echo "CLEAN"
    fi
}

# Show recent hits for high-risk IPs
show_recent_hits() {
    local ip="$1"
    local log_file="$2"
    local time_range="$3"
    
    echo ""
    echo "Recent 5 hits from $ip:"
    echo "----------------------"
    
    local recent_entries
    
    if [[ "$time_range" == "custom" ]]; then
        # For custom range, we need to filter by time
        recent_entries=$(grep "^$ip" "$log_file" | awk -v start="$start_time" -v end="$end_time" '
        {
            if (match($4, /:[0-9]{2}:[0-9]{2}:[0-9]{2}/)) {
                time_part = substr($4, 14, 5)
                if (time_part >= start && time_part <= end) {
                    print $0
                }
            }
        }' | tail -5)
    else
        # For predefined ranges, use simple grep
        recent_entries=$(grep "^$ip" "$log_file" | tail -5)
    fi
    
    if [[ -z "$recent_entries" ]]; then
        echo "  No recent entries found"
        return
    fi
    
    # Show the actual log entries
    echo "$recent_entries" | while read -r line; do
        echo "  $line"
    done
}

# Main function
main() {
    echo "=== Single File IP Threat Intelligence ==="
    echo "Processing file: $LOG_FILE"
    
    # Step 1: Check dependencies
    check_dependencies
    echo "✓ Basic tools available"
    
    # Step 2: Show menu and get choice
    while true; do
        show_menu
        read -r choice
        
        case "$choice" in
            1) time_range="today"; break ;;
            2) time_range="last_hour"; break ;;
            3) time_range="last_10min"; break ;;
            4) time_range="custom"; break ;;
            *) echo "Invalid choice. Please enter 1, 2, 3, or 4." ;;
        esac
    done
    
    # Store custom times if needed
    if [[ "$time_range" == "custom" ]]; then
        if ! filter_custom_range "$LOG_FILE" "/tmp/ips.$$"; then
            exit 1
        fi
        # start_time and end_time are already set in filter_custom_range function
    else
        # Step 3: Extract IPs based on time range
        local ip_file="/tmp/ips.$$"
        
        case "$time_range" in
            "today")
                filter_todays_logs "$LOG_FILE" "$ip_file" || exit 1
                ;;
            "last_hour")
                filter_last_hour "$LOG_FILE" "$ip_file" || exit 1
                ;;
            "last_10min")
                filter_last_10min "$LOG_FILE" "$ip_file" || exit 1
                ;;
        esac
    fi
    
    # Step 4: Get raw logs for recent hits display
    echo "Preparing log data for analysis..."
    local raw_logs_file="/tmp/filtered_logs.$$"
    get_raw_logs_for_time_range "$LOG_FILE" "$time_range" > "$raw_logs_file"
    
    # Step 5: Analyze IPs - Clean output without progress messages
    echo ""
    echo "THREAT ANALYSIS RESULTS:"
    echo "========================"
    printf "%-6s %-18s %-12s %-8s %-8s %s\n" "Hits" "IP Address" "Country" "Pulses" "Risk" "Recommendation"
    echo "-----------------------------------------------------------------------"
    
    local high_risk_ips=()
    local total_ips=0
    
    # Read from the appropriate IP file
    local ip_file_to_use="/tmp/ips.$$"
    if [[ "$time_range" == "custom" ]]; then
        ip_file_to_use="/tmp/ips.$$"
    else
        ip_file_to_use="/tmp/ips.$$"
    fi
    
    while read -r line; do
        local hits ip
        hits=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $2}')
        
        [[ -z "$ip" ]] && continue
        
        total_ips=$((total_ips + 1))
        
        # Check IP threat
        local result
        result=$(check_ip_threat "$ip")
        
        local pulses
        pulses=$(echo "$result" | cut -d'|' -f1)
        local country
        country=$(echo "$result" | cut -d'|' -f2)
        
        # Shorten long country names
        if [[ ${#country} -gt 10 ]]; then
            country="${country:0:9}."
        fi
        
        # Get risk level
        local risk_level
        risk_level=$(get_risk_level "$pulses")
        
        # Track high risk IPs
        if [[ "$risk_level" == "HIGH" ]]; then
            high_risk_ips+=("$ip")
        fi
        
        # Display result - clean output without progress messages
        printf "%-6s %-18s %-12s %-8s %-8s " "$hits" "$ip" "$country" "$pulses" "$risk_level"
        
        # Recommendation
        if [[ "$risk_level" == "HIGH" ]]; then
            echo "🚨 BLOCK"
        elif [[ "$risk_level" == "MEDIUM" ]]; then
            echo "⚠️  MONITOR"
        else
            echo "✓ OK"
        fi
        
        # Rate limiting
        sleep 1
        
    done < "$ip_file_to_use"
    
    # Step 6: Show recent hits for high-risk IPs
    if [[ ${#high_risk_ips[@]} -gt 0 ]]; then
        echo ""
        echo "=== RECENT ACTIVITY FROM HIGH-RISK IPs ==="
        for ip in "${high_risk_ips[@]}"; do
            show_recent_hits "$ip" "$raw_logs_file" "$time_range"
        done
    fi
    
    # Step 7: Show results and CSF blocking commands
    echo ""
    echo "=== ANALYSIS COMPLETE ==="
    echo "Total IPs checked: $total_ips"
    echo "High-risk IPs: ${#high_risk_ips[@]}"
    
    if [[ ${#high_risk_ips[@]} -gt 0 ]]; then
        echo ""
        echo "🚨 RECOMMENDED CSF BLOCKING COMMANDS:"
        echo "====================================="
        for ip in "${high_risk_ips[@]}"; do
            echo "csf -d $ip"
        done
        echo ""
        echo "To block all high-risk IPs, copy and run the above commands."
    else
        echo ""
        echo "No high-risk IPs found. No blocking actions required."
    fi
}

# Run main function
main "$@"
