#!/bin/bash
set -euo pipefail

# Script: log_analyzer.sh
# Description: Analyze log files for threat intelligence

SCRIPT_NAME="log_analyzer.sh"
OTX_API_KEY="ad3be64c61425dcbca6a5dbd43f3c8e056ced8f3c2662dc5248c20815c083564"

# Cleanup function
cleanup() {
    rm -f "/tmp/ips.$$" "/tmp/logs.$$" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

# Display usage
usage() {
    echo "=== Log File Threat Analyzer ==="
    echo "Usage: $0 [OPTION|FILE]"
    echo ""
    echo "Options:"
    echo "  --today         Analyze today's traffic from default logs"
    echo "  --last-hour     Analyze last hour's traffic from default logs" 
    echo "  --last-10mins   Analyze last 10 minutes traffic from default logs"
    echo "  FILE            Analyze specific log file"
    echo "  -h, --help      Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 /var/log/virtualmin/domain.com_access_log"
    echo "  $0 --today"
    echo "  $0 --last-hour"
    echo "  $0 --last-10mins"
    exit 0
}

if [[ "$#" -eq 0 ]] || [[ "$1" =~ ^(-h|--help)$ ]]; then
    usage
fi

# Check dependencies
check_dependencies() {
    for dep in grep awk curl jq date; do
        if ! command -v "$dep" &>/dev/null; then
            echo "Error: Required tool '$dep' not found"
            exit 1
        fi
    done
}

# Find default log directory
find_log_directory() {
    if [[ -d "/var/log/virtualmin" ]]; then
        echo "/var/log/virtualmin"
    elif [[ -d "/var/log/apache2/domlogs" ]]; then
        echo "/var/log/apache2/domlogs"
    elif [[ -d "/var/log/nginx" ]]; then
        echo "/var/log/nginx"
    elif [[ -d "/var/log/httpd" ]]; then
        echo "/var/log/httpd"
    else
        echo "Error: No log directory found" >&2
        exit 1
    fi
}

# Get time range pattern
get_time_pattern() {
    local mode="$1"
    
    case "$mode" in
        "today")
            date +"%d/%b/%Y"
            ;;
        "last-hour")
            # Current time and 1 hour ago in log format
            local current_hour=$(date +"%H")
            local previous_hour=$((10#${current_hour} - 1))
            # Handle hour wrap-around
            if [[ $previous_hour -lt 0 ]]; then
                previous_hour=23
            fi
            # Format to 2 digits
            printf "%02d" $previous_hour
            ;;
        "last-10mins")
            # Current time in log format (will filter precisely later)
            date +"%d/%b/%Y:%H:%M"
            ;;
        *)
            echo "Error: Unknown time mode '$mode'" >&2
            exit 1
            ;;
    esac
}

# Extract IPs from log file or directory
extract_ips() {
    local source="$1"
    local mode="$2"
    local output_file="$3"
    
    echo "Analyzing: $source"
    echo "Time range: $mode"
    
    local time_pattern
    time_pattern=$(get_time_pattern "$mode")
    
    # Create temp file for filtered logs
    local temp_logs="/tmp/logs.$$"
    
    if [[ -f "$source" ]]; then
        # Single file mode
        if [[ ! -r "$source" ]]; then
            echo "Error: Cannot read file: $source" >&2
            return 1
        fi
        
        echo "Processing file: $(basename "$source")"
        
        case "$mode" in
            "today")
                grep -h "$time_pattern" "$source" > "$temp_logs" 2>/dev/null || true
                ;;
            "last-hour")
                # Filter for last hour
                grep -h "$time_pattern" "$source" > "$temp_logs" 2>/dev/null || true
                ;;
            "last-10mins")
                # More precise filtering for last 10 minutes
                local ten_mins_ago=$(date -d '10 minutes ago' +"%d/%b/%Y:%H:%M")
                local current_time=$(date +"%d/%b/%Y:%H:%M")
                # This is approximate - we'll use grep for the minute part
                awk -v pattern="$time_pattern" '$0 ~ pattern' "$source" > "$temp_logs" 2>/dev/null || true
                ;;
        esac
        
    elif [[ -d "$source" ]]; then
        # Directory mode - find all access logs
        echo "Searching for log files in: $source"
        
        local log_files
        log_files=$(find "$source" -maxdepth 1 -type f \( -name "*access*log" -o -name "*.log" \) \
                   ! -name "*.gz" ! -name "*.*[0-9]" 2>/dev/null | head -10)
        
        if [[ -z "$log_files" ]]; then
            echo "Error: No log files found in $source" >&2
            return 1
        fi
        
        # Process each file
        while IFS= read -r logfile; do
            if [[ -r "$logfile" ]]; then
                case "$mode" in
                    "today")
                        grep -h "$time_pattern" "$logfile" >> "$temp_logs" 2>/dev/null || true
                        ;;
                    "last-hour")
                        grep -h "$time_pattern" "$logfile" >> "$temp_logs" 2>/dev/null || true
                        ;;
                    "last-10mins")
                        awk -v pattern="$time_pattern" '$0 ~ pattern' "$logfile" >> "$temp_logs" 2>/dev/null || true
                        ;;
                esac
            fi
        done <<< "$log_files"
    else
        echo "Error: Source '$source' is not a file or directory" >&2
        return 1
    fi
    
    # Check if we got any log entries
    local total_lines
    total_lines=$(wc -l < "$temp_logs" 2>/dev/null || echo 0)
    
    if [[ "$total_lines" == "0" ]]; then
        echo "No log entries found for the specified time range"
        return 1
    fi
    
    echo "Processing $total_lines log entries..."
    
    # Extract IPs
    awk '{print $1}' "$temp_logs" 2>/dev/null | \
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
    sort | uniq -c | sort -nr | head -30 > "$output_file"
    
    local ip_count
    ip_count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    
    if [[ "$ip_count" == "0" ]]; then
        echo "Error: No IP addresses could be extracted"
        return 1
    fi
    
    echo "✓ Extracted $ip_count unique IP addresses"
    return 0
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

# Main function
main() {
    local source
    local mode="today"
    
    # Parse arguments
    case "$1" in
        "--today")
            source=$(find_log_directory)
            mode="today"
            ;;
        "--last-hour")
            source=$(find_log_directory)
            mode="last-hour"
            ;;
        "--last-10mins")
            source=$(find_log_directory) 
            mode="last-10mins"
            ;;
        *)
            if [[ -f "$1" ]] || [[ -d "$1" ]]; then
                source="$1"
                mode="today"
            else
                echo "Error: '$1' is not a valid file, directory, or option" >&2
                usage
            fi
            ;;
    esac
    
    echo "=== Log File Threat Analyzer ==="
    echo "Starting analysis..."
    
    # Check dependencies
    check_dependencies
    echo "✓ Basic tools available"
    
    # Extract IPs
    local ip_file="/tmp/ips.$$"
    if ! extract_ips "$source" "$mode" "$ip_file"; then
        exit 1
    fi
    
    # Analyze IPs
    echo ""
    echo "THREAT ANALYSIS RESULTS:"
    echo "======================="
    printf "%-6s %-18s %-12s %-8s %-8s %s\n" "Hits" "IP Address" "Country" "Pulses" "Risk" "Recommendation"
    echo "-----------------------------------------------------------------------"
    
    local high_risk_ips=()
    
    while read -r line; do
        local hits ip
        hits=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $2}')
        
        [[ -z "$ip" ]] && continue
        
        local result
        result=$(check_ip_threat "$ip")
        
        local pulses
        pulses=$(echo "$result" | cut -d'|' -f1)
        local country
        country=$(echo "$result" | cut -d'|' -f2)
        
        if [[ ${#country} -gt 10 ]]; then
            country="${country:0:9}."
        fi
        
        local risk_level
        risk_level=$(get_risk_level "$pulses")
        
        if [[ "$risk_level" == "HIGH" ]]; then
            high_risk_ips+=("$ip")
        fi
        
        printf "%-6s %-18s %-12s %-8s %-8s " "$hits" "$ip" "$country" "$pulses" "$risk_level"
        
        if [[ "$risk_level" == "HIGH" ]]; then
            echo "🚨 BLOCK"
        elif [[ "$risk_level" == "MEDIUM" ]]; then
            echo "⚠️  MONITOR"
        else
            echo "✓ OK"
        fi
        
        sleep 1
        
    done < "$ip_file"
    
    # Show results
    echo ""
    echo "=== ANALYSIS COMPLETE ==="
    echo "Mode: $mode"
    echo "Source: $source"
    echo "IPs checked: $(wc -l < "$ip_file")"
    echo "High-risk IPs: ${#high_risk_ips[@]}"
    
    if [[ ${#high_risk_ips[@]} -gt 0 ]]; then
        echo ""
        echo "🚨 RECOMMENDED ACTIONS:"
        echo "======================="
        for ip in "${high_risk_ips[@]}"; do
            echo "csf -d $ip  # Block high-risk IP"
        done
    fi
}

# Run main function
main "$@"
