# IP Threat Intelligence Analyzer

A powerful bash script that analyzes web server access logs to identify potentially malicious IP addresses using AlienVault OTX threat intelligence.

## 🚀 Quick Start

### One-Line Execution (No Installation)
```bash
curl -sL https://raw.githubusercontent.com/deepak-webscoot/singlefile_iplookup/main/log_analyzer.sh | bash -s -- /path/to/your/access_log
```

### Permanent Installation (Recommended)
Add this function to your `~/.bashrc` or `~/.zshrc`:

```bash
ws-singleiplookup() {
    if [ $# -eq 0 ]; then
        echo "Usage: ws-singleiplookup <logfile>"
        return 1
    fi
    local temp_script=$(mktemp)
    curl -sL https://raw.githubusercontent.com/deepak-webscoot/singlefile_iplookup/main/log_analyzer.sh -o "$temp_script"
    chmod +x "$temp_script"
    "$temp_script" "$1"
    rm -f "$temp_script"
}
```

Then reload and use:
```bash
source ~/.bashrc
ws-singleiplookup /var/log/nginx/access.log
```

## 📋 What This Script Does

This script helps you identify potentially malicious IP addresses accessing your web server by:

- 🔍 **Analyzing access logs** from Apache, Nginx, or Virtualmin
- ⏰ **Filtering by time ranges** (today, last hour, last 10 minutes, or custom)
- 🛡️ **Checking threat intelligence** via AlienVault OTX
- 🚨 **Identifying high-risk IPs** with malicious history
- 📊 **Showing recent activity** from suspicious IPs
- 🔧 **Generating CSF firewall** blocking commands

## 🎯 Usage Examples

### Basic Analysis
```bash
# Analyze today's traffic
ws-singleiplookup /var/log/virtualmin/yourdomain.com_access_log

# Analyze specific time range
ws-singleiplookup /var/log/nginx/access.log
```

### Common Log File Locations
```bash
# Virtualmin logs
ws-singleiplookup /var/log/virtualmin/yourdomain.com_access_log

# Nginx logs
ws-singleiplookup /var/log/nginx/access.log

# Apache logs
ws-singleiplookup /var/log/apache2/access.log
```

## 🖥️ How It Works

### Step-by-Step Process

1. **Select Time Range** - Choose which logs to analyze:
   - ✅ Today's logs
   - ✅ Last hour
   - ✅ Last 10 minutes  
   - ✅ Custom time range

2. **Extract IPs** - Script extracts top 30 IPs from selected time period

3. **Threat Check** - Each IP is checked against AlienVault OTX database

4. **Risk Assessment** - IPs are categorized by risk level:
   - 🟢 **CLEAN** (0 pulses) - No known threats
   - 🟡 **LOW** (1-5 pulses) - Minor threat history
   - 🟠 **MEDIUM** (6-10 pulses) - Moderate threat history
   - 🔴 **HIGH** (10+ pulses) - Significant threat history

5. **Results Display** - See detailed analysis with recommendations

### Sample Output
```
THREAT ANALYSIS RESULTS:
========================
Hits   IP Address         Country   Pulses  Risk    Recommendation
-------------------------------------------------------------------
165    192.168.1.100     USA       25      HIGH    🚨 BLOCK
42     10.0.0.50         China     8       MEDIUM  ⚠️ MONITOR
15     172.16.1.200      Germany   0       CLEAN   ✓ OK

🚨 RECOMMENDED CSF BLOCKING COMMANDS:
=====================================
csf -d 192.168.1.100
```

## 🛡️ Blocking Malicious IPs

The script generates ready-to-use CSF firewall commands:

```bash
# Copy and run the commands shown in the output:
csf -d 192.168.1.100
csf -d 10.0.0.50

# Verify IP is blocked
csf -g 192.168.1.100
```

## ⚙️ Requirements

### Essential Tools
- `curl` - For API calls and downloading
- `jq` - For JSON parsing
- `grep`, `awk`, `sort` - For log processing
- `date` - For time calculations

### Install Dependencies (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install curl jq
```

### Install Dependencies (CentOS/RHEL)
```bash
sudo yum install curl jq
```

## 🔧 Features

### ✅ Time Range Filtering
- **Today's Logs** - Analyze all of today's activity
- **Last Hour** - Focus on recent attacks
- **Last 10 Minutes** - Real-time threat detection
- **Custom Range** - Specify exact time windows (e.g., 09:00-17:00)

### ✅ Threat Intelligence
- **AlienVault OTX Integration** - World's largest threat data repository
- **Pulse Count** - Number of threat intelligence reports
- **Country Detection** - Geographic origin of IPs
- **Risk Scoring** - Automated risk assessment

### ✅ Actionable Output
- **CSF Commands** - Ready-to-use blocking commands
- **Recent Activity** - Last 5 requests from malicious IPs
- **Clear Recommendations** - Block, Monitor, or OK

## ❓ Frequently Asked Questions

### Q: What log formats are supported?
**A:** Common Log Format and Combined Log Format used by Apache, Nginx, and Virtualmin.

### Q: Is an API key required?
**A:** No, the script includes a built-in AlienVault OTX API key.

### Q: How often should I run this?
**A:** 
- **Daily** for routine monitoring
- **Immediately** after noticing suspicious activity
- **Weekly** for comprehensive security review

### Q: Can it block IPs automatically?
**A:** No, for safety reasons you must manually run the generated CSF commands.

### Q: What are "pulses" in the output?
**A:** Pulses represent the number of threat intelligence reports about an IP in AlienVault OTX database.

## 🐛 Troubleshooting

### Common Issues

**"Log file not found or not readable"**
```bash
# Check file exists and permissions
ls -la /var/log/nginx/access.log
sudo chmod 644 /var/log/nginx/access.log
```

**"Required tool not found"**
```bash
# Install missing dependencies
sudo apt install jq curl
```

**"No IP addresses found"**
- Check if the log file has recent entries
- Verify time zone settings
- Ensure log format is compatible

## 📝 Log Format Compatibility

The script works with standard web server log formats:

```
# Common Log Format
127.0.0.1 - - [25/Oct/2025:10:30:45 +0000] "GET / HTTP/1.1" 200 1234

# Combined Log Format  
127.0.0.1 - - [25/Oct/2025:10:30:45 +0000] "GET / HTTP/1.1" 200 1234 "http://example.com" "Mozilla/5.0..."
```

## 🔒 Security Notes

- The script only reads log files - no modifications are made
- IP blocking requires manual confirmation
- AlienVault OTX queries are rate-limited
- Temporary files are automatically cleaned up

## 📞 Support

If you encounter issues:
1. Check the log file exists and is readable
2. Verify all dependencies are installed
3. Ensure you have internet connectivity for OTX queries
4. Check the time range selection matches your log data

---

**Happy Threat Hunting!** 🎯
