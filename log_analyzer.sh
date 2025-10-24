#!/bin/bash
set -euo pipefail

# Script: single_file_iplookup.sh
# Description: Interactive log file threat analyzer

SCRIPT_NAME="single_file_iplookup.sh"
OTX_API_KEY="ad3be64c61425dcbca6a5dbd43f3c8e056ced8f3c2662dc5248c20815c083564"

# Cleanup function
cleanup() {
    rm -f "/tmp/ips.$$" "/tmp/logs.$$" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

# Display usage
usage() {
    echo "=== Single File IP Threat Analyzer ==="
    echo "Usage: $0 [LOG_FILE]"
    echo ""
    echo "If LOG_FILE is provided, uses that file directly"
    echo "If no argument, asks for file interactively"
    echo ""
    exit 0
}

if [[ "$#" -gt 0 ]] && [[ "$1" =~ ^(-h|--help)$ ]]; then
    usage
fi

# Check dependencies
check_dependencies() {
    for dep in grep awk curl jq; do
        if ! command -v "$dep" &>/dev/null; then
            echo "Error: Required tool '$dep' not found"
            exit 1
        fi
    done
}

# Interactive file selection
select_log_file() {
    local default_locations=(
        "/var/log/virtualmin"
        "/var/log/apache2/domlogs" 
        "/var/log/nginx"
        "/var/log/httpd"
    )
    
    echo ""
    echo "📁 LOG FILE SELECTION"
    echo "===================="
    
    # Check for common log directories
    local found_dirs=()
    for dir in "${default_locations[@]}"; do
        if [[ -d "$dir" ]]; then
            found_dirs+=("$dir")
            echo "📍 Found: $dir"
        fi
    done
    
    echo ""
    echo "Please enter the path to your access log file:"
    echo "Examples:"
    for dir in "${found_dirs[@]}"; do
        echo "  $dir/your-domain.com_access_log"
    done
    echo "  /full/path/to/your/access_log"
    echo ""
    read -p "➡️  Log file path: " log_file
    
    # Validate file
    if [[ ! -f "$log_file" ]]; then
        echo "❌ Error: File '$log_file' does not exist or is not a file"
        exit 1
    fi
    
    if [[ ! -r "$log_file" ]]; then
        echo "❌ Error: Cannot read file '$log_file' (permission denied)"
        exit 1
    fi
    
    echo "✅ Using file: $log_file"
    echo "$log_file"
}

# Interactive time range selection
select_time_range() {
    echo ""
    echo "⏰ TIME RANGE SELECTION"
    echo "======================"
    echo "1. Today's entries"
    echo "2. Last hour" 
    echo "3. Last 10 minutes"
    echo "4. All entries (entire file)"
    echo ""
    
    while true; do
        read -p "➡️  Select option (1-4): " choice
        
        case "$choice" in
            1)
                echo "today"
                return
                ;;
            2)
                echo "last-hour" 
                return
                ;;
            3)
                echo "last-10mins"
                return
                ;;
            4)
                echo "all"
                return
                ;;
            *)
                echo "❌ Please enter a number between 1 and 4"
                ;;
        esac
    done
}

# Get time pattern for filtering
get_time_pattern() {
    local mode="$1"
    
    case "$mode" in
        "today")
            date +"%d/%b/%Y"
            ;;
        "last-hour")
            # Last hour in log format
            date -d '1 hour ago' +"%d/%b/%Y:%H"
            ;;
        "last-10mins")
            # Last 10 minutes (we'll filter more precisely)
            date -d '10 minutes ago' +"%d/%b/%Y:%H:%M"
            ;;
        "all")
            echo "all"
            ;;
        *)
            echo "Error: Unknown time mode '$mode'" >&2
            exit 1
            ;;
    esac
}

# Extract IPs based on time range
extract_ips() {
    local log_file="$1"
    local mode="$2"
    local output_file="$3"
    
    echo ""
    echo "🔍 EXTRACTING IP ADDRESSES"
    echo "=========================="
    echo "File: $(basename "$log_file")"
    echo "Time range: $mode"
    
    local time_pattern
    time_pattern=$(get_time_pattern "$mode")
    
    # Create temp file for filtered logs
    local temp_logs="/tmp/logs.$$"
    
    case "$mode" in
        "today")
            echo "Filtering today's entries..."
            grep -h "$time_pattern" "$log_file" > "$temp_logs" 2>/dev/null || true
            ;;
        "last-hour")
            echo "Filtering last hour's entries..."
            grep -h "$time_pattern" "$log_file" > "$temp_logs" 2>/dev/null || true
            ;;
        "last-10mins")
            echo "Filtering last 10 minutes entries..."
            # More precise filtering for minutes
            awk -v pattern="$time_pattern" '$4 ~ pattern' "$log_file" > "$temp_logs" 2>/dev/null || true
            ;;
        "all")
            echo "Processing all entries..."
            cat "$log_file" > "$temp_logs" 2>/dev/null || true
            ;;
    esac
    
    # Check if we got any log entries
    local total_lines
    total_lines=$(wc -l < "$temp_logs" 2>/dev/null || echo 0)
    
    if [[ "$total_lines" == "0" ]]; then
        echo "❌ No log entries found for the selected time range"
        return 1
    fi
    
    echo "📊 Processing $total_lines log entries..."
    
    # Extract IPs - simple and reliable
    awk '{print $1}' "$temp_logs" 2>/dev/null | \
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
    sort | uniq -c | sort -nr | head -30 > "$output_file"
    
    local ip_count
    ip_count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    
    if [[ "$ip_count" == "0" ]]; then
        echo "❌ No IP addresses could be extracted"
        return 1
    fi
    
    echo "✅ Extracted $ip_count unique IP addresses"
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

# Show recent log entries for high-risk IPs
show_recent_entries() {
    local log_file="$1"
    shift
    local high_risk_ips=("$@")
    
    if [[ ${#high_risk_ips[@]} -eq 0 ]]; then
        return
    fi
    
    echo ""
    echo "🔍 RECENT LOG ENTRIES FOR HIGH-RISK IPs"
    echo "========================================"
    
    for ip in "${high_risk_ips[@]}"; do
        echo ""
        echo "🚨 HIGH-RISK IP: $ip"
        echo "----------------------------------------"
        
        # Get last 5 entries for this IP from the log file
        local recent_entries
        recent_entries=$(grep "$ip" "$log_file" | tail -5)
        
        if [[ -n "$recent_entries" ]]; then
            echo "Last 5 log entries:"
            echo "-------------------"
            echo "$recent_entries"
        else
            echo "No recent entries found for this IP"
        fi
    done
}

# Main function
main() {
    echo "=== Single File IP Threat Analyzer ==="
    echo ""
    
    # Check dependencies
    check_dependencies
    echo "✅ Basic tools available"
    
    # Handle file argument or ask interactively
    local log_file
    if [[ "$#" -eq 1 ]] && [[ -f "$1" ]]; then
        log_file="$1"
        echo "✅ Using provided file: $log_file"
    else
        log_file=$(select_log_file)
    fi
    
    # Always ask for time range
    local time_range
    time_range=$(select_time_range)
    
    # Extract IPs
    local ip_file="/tmp/ips.$$"
    if ! extract_ips "$log_file" "$time_range" "$ip_file"; then
        exit 1
    fi
    
    # Analyze IPs
    echo ""
    echo "🛡️  THREAT ANALYSIS RESULTS"
    echo "=========================="
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
    
    # Show recent entries for high-risk IPs
    show_recent_entries "$log_file" "${high_risk_ips[@]}"
    
    # Final summary
    echo ""
    echo "✅ ANALYSIS COMPLETE"
    echo "==================="
    echo "File analyzed: $(basename "$log_file")"
    echo "Time range: $time_range"
    echo "IPs checked: $(wc -l < "$ip_file")"
    echo "High-risk IPs: ${#high_risk_ips[@]}"
    
    if [[ ${#high_risk_ips[@]} -gt 0 ]]; then
        echo ""
        echo "🚨 RECOMMENDED BLOCKING COMMANDS:"
        echo "================================"
        for ip in "${high_risk_ips[@]}"; do
            echo "csf -d $ip"
        done
    fi
    
    echo ""
    echo "💡 Note: High-risk IPs have >10 threat intelligence reports"
}

# Run main function with all arguments
main "$@"
