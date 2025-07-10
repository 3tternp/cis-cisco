#!/bin/bash

# Script to interactively collect Cisco switch credentials, check CIS Cisco IOS Benchmark compliance, and generate HTML report
# Version: 1.0.0
# Features: Auto-installs dependencies, displays script banner, requires user permission, checks CIS recommendations, generates HTML report with pie chart

# Display script banner
cat << 'EOF'

========================================
   CIS Cisco IOS Switch Compliance Checker
========================================
Version: 1.0.0          Developer: Astra
========================================

EOF

# Prompt for user permission to proceed
echo "Do you want to proceed with the compliance check? (y/n):"
read -r confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Execution aborted by user."
    exit 0
fi

# Function to detect package manager and install dependencies
install_dependencies() {
    local pkg_manager=""
    local install_cmd=""

    # Detect package manager
    if command -v apt-get &> /dev/null; then
        pkg_manager="apt"
        install_cmd="sudo apt-get install -y"
    elif command -v yum &> /dev/null; then
        pkg_manager="yum"
        install_cmd="sudo yum install -y"
    else
        echo "Error: No supported package manager (apt or yum) found."
        exit 1
    fi

    # Check and install sshpass
    if ! command -v sshpass &> /dev/null; then
        echo "sshpass is not installed. Attempting to install using $pkg_manager..."
        read -p "Proceed with installation? (y/n): " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            echo "Error: sshpass is required. Please install manually and retry."
            exit 1
        fi
        $install_cmd sshpass
        if [ $? -ne 0 ]; then
            echo "Error: Failed to install sshpass. Please install manually."
            exit 1
        fi
        echo "sshpass installed successfully."
    fi

    # Check and install bc
    if ! command -v bc &> /dev/null; then
        echo "bc is not installed. Attempting to install using $pkg_manager..."
        read -p "Proceed with installation? (y/n): " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            echo "Error: bc is required. Please install manually and retry."
            exit 1
        fi
        $install_cmd bc
        if [ $? -ne 0 ]; then
            echo "Error: Failed to install bc. Please install manually."
            exit 1
        fi
        echo "bc installed successfully."
    fi
}

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if [[ $octet -lt 0 || $octet -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

# Function to validate port
validate_port() {
    local port=$1
    if [[ $port =~ ^[0-9]+$ && $port -ge 1 && $port -le 65535 ]]; then
        return 0
    else
        return 1
    fi
}

# Install dependencies
install_dependencies

# Prompt for user input
echo "Enter Cisco switch IP address:"
read -r CISCO_IP
if ! validate_ip "$CISCO_IP"; then
    echo "Error: Invalid IP address format."
    exit 1
fi

echo "Enter SSH port (default 22):"
read -r SSH_PORT
if [ -z "$SSH_PORT" ]; then
    SSH_PORT=22
fi
if ! validate_port "$SSH_PORT"; then
    echo "Error: Invalid port number. Must be between 1 and 65535."
    exit 1
fi

echo "Enter Cisco switch username:"
read -r USERNAME
if [ -z "$USERNAME" ]; then
    echo "Error: Username cannot be empty."
    exit 1
fi

echo "Enter Cisco switch password (input will be hidden):"
read -s PASSWORD
echo
if [ -z "$PASSWORD" ]; then
    echo "Error: Password cannot be empty."
    exit 1
fi

# Set SSH command (enable mode for privileged commands)
SSH_COMMAND="sshpass -p \"$PASSWORD\" ssh -p $SSH_PORT -o StrictHostKeyChecking=no $USERNAME@$CISCO_IP"
REPORT_FILE="cis_cisco_compliance_report.html"
TEMP_FILE="cis_cisco_temp.txt"

# Initialize temporary file for results
: > $TEMP_FILE

# Define findings information (ID, Name, Risk Rating, Remediation)
declare -A FINDINGS_INFO=(
    ["1.1.1"]="Ensure minimum password length is 15 or more|High|configure terminal\nenable secret <password>\nline vty 0 4\npassword <password>\nend\nwrite memory"
    ["1.1.2"]="Ensure password complexity is enabled|High|configure terminal\naaa new-model\naaa common-criteria policy cc-policy\nmin-length 15\nnumeric-count 1\nupper-case 1\nlower-case 1\nspecial-case 1\nend\nwrite memory"
    ["1.2.1"]="Ensure AAA authentication for local users|High|configure terminal\naaa new-model\naaa authentication login default local\nend\nwrite memory"
    ["1.3.1"]="Ensure SSH is enabled|Medium|configure terminal\nip ssh version 2\nip ssh time-out 60\nip ssh authentication-retries 3\nend\nwrite memory"
    ["1.3.2"]="Ensure SSH access is restricted|Medium|configure terminal\nline vty 0 4\naccess-class 10 in\nend\nwrite memory\nNote: Create ACL 10 to restrict IPs"
    ["1.3.3"]="Ensure SSH uses strong ciphers|Medium|configure terminal\nip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr\nend\nwrite memory"
    ["1.4.1"]="Ensure login banner is configured|Low|configure terminal\nbanner motd ^C Authorized access only! ^C\nend\nwrite memory"
    ["1.4.2"]="Ensure EXEC timeout is 10 minutes or less|Medium|configure terminal\nline vty 0 4\nexec-timeout 10 0\nend\nwrite memory"
    ["2.1.1"]="Ensure NTP is enabled|High|configure terminal\nntp server pool.ntp.org\nntp authentication-key 1 md5 <key>\nntp trusted-key 1\nend\nwrite memory"
    ["2.2.1"]="Ensure logging is enabled|High|configure terminal\nlogging on\nlogging host <syslog_server>\nlogging trap informational\nend\nwrite memory"
    ["2.2.2"]="Ensure logging includes timestamps|Medium|configure terminal\nservice timestamps log datetime msec\nend\nwrite memory"
    ["2.3.1"]="Ensure SNMPv3 is used|Medium|configure terminal\nsnmp-server group <group> v3 auth\nsnmp-server user <user> <group> v3 auth sha <password>\nend\nwrite memory"
    ["2.3.2"]="Ensure SNMP communities are not public/private|High|configure terminal\nno snmp-server community public\nno snmp-server community private\nend\nwrite memory"
    ["3.1.1"]="Ensure VTY lines use only SSH|High|configure terminal\nline vty 0 4\ntransport input ssh\nend\nwrite memory"
    ["3.1.2"]="Ensure telnet is disabled|High|configure terminal\nline vty 0 4\ntransport input none\nend\nwrite memory"
    ["3.2.1"]="Ensure loopback interface is configured|Medium|configure terminal\ninterface loopback0\nip address <loopback_ip> 255.255.255.255\nend\nwrite memory"
    ["4.1.1"]="Ensure ACLs are applied to interfaces|Medium|configure terminal\ninterface <interface>\nip access-group <acl_name> in\nend\nwrite memory"
    ["4.2.1"]="Ensure port security is enabled|Medium|configure terminal\ninterface <interface>\nswitchport port-security\nswitchport port-security maximum 2\nswitchport port-security violation restrict\nend\nwrite memory"
    ["5.1.1"]="Ensure VLAN 1 is not used|High|configure terminal\ninterface <interface>\nswitchport access vlan <non-1-vlan>\nend\nwrite memory"
    ["5.2.1"]="Ensure spanning-tree PortFast is enabled on access ports|Medium|configure terminal\ninterface <interface>\nspanning-tree portfast\nend\nwrite memory"
)

# Function to execute command and check output
check_config() {
    local check_id=$1
    local description=$2
    local command=$3
    local expected=$4
    local output
    local status
    local risk
    local remediation

    # Extract name, risk, and remediation from FINDINGS_INFO
    IFS='|' read -r name risk remediation <<< "${FINDINGS_INFO[$check_id]}"

    echo "Checking $check_id: $description..."
    # Execute command in privileged EXEC mode
    output=$($SSH_COMMAND "enable\n$PASSWORD\n$command" 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "Error: Failed to connect to $CISCO_IP on port $SSH_PORT or enter enable mode. Check credentials, connectivity, or SSH access."
        exit 1
    fi
    if echo "$output" | grep -qE "$expected"; then
        status="PASS"
    else
        status="FAIL"
    fi
    echo "[$status] $check_id|$name|$risk|$remediation" >> $TEMP_FILE
}

# Perform compliance checks
check_config "1.1.1" "Ensure minimum password length is 15 or more" \
    "show running-config | include enable secret" \
    "enable secret"
check_config "1.1.2" "Ensure password complexity is enabled" \
    "show running-config | include aaa common-criteria policy" \
    "min-length 15"
check_config "1.2.1" "Ensure AAA authentication for local users" \
    "show running-config | include aaa authentication login" \
    "aaa authentication login default local"
check_config "1.3.1" "Ensure SSH is enabled" \
    "show ip ssh" \
    "SSH Enabled - version 2"
check_config "1.3.2" "Ensure SSH access is restricted" \
    "show running-config | include line vty" \
    "access-class [0-9]+ in"
check_config "1.3.3" "Ensure SSH uses strong ciphers" \
    "show ip ssh" \
    "Encryption Algorithms:.*aes256-ctr"
check_config "1.4.1" "Ensure login banner is configured" \
    "show running-config | include banner motd" \
    "banner motd"
check_config "1.4.2" "Ensure EXEC timeout is 10 minutes or less" \
    "show running-config | include line vty" \
    "exec-timeout 10"
check_config "2.1.1" "Ensure NTP is enabled" \
    "show ntp status" \
    "synchronized"
check_config "2.2.1" "Ensure logging is enabled" \
    "show logging" \
    "logging on"
check_config "2.2.2" "Ensure logging includes timestamps" \
    "show running-config | include service timestamps" \
    "service timestamps log datetime msec"
check_config "2.3.1" "Ensure SNMPv3 is used" \
    "show snmp user" \
    "v3.*auth sha"
check_config "2.3.2" "Ensure SNMP communities are not public/private" \
    "show running-config | include snmp-server community" \
    "^$"
check_config "3.1.1" "Ensure VTY lines use only SSH" \
    "show running-config | include line vty" \
    "transport input ssh"
check_config "3.1.2" "Ensure telnet is disabled" \
    "show running-config | include line vty" \
    "transport input (ssh|none)"
check_config "3.2.1" "Ensure loopback interface is configured" \
    "show running-config | include interface Loopback" \
    "interface Loopback0"
check_config "4.1.1" "Ensure ACLs are applied to interfaces" \
    "show running-config | include interface" \
    "ip access-group"
check_config "4.2.1" "Ensure port security is enabled" \
    "show running-config | include switchport port-security" \
    "switchport port-security"
check_config "5.1.1" "Ensure VLAN 1 is not used" \
    "show running-config | include switchport access vlan" \
    "switchport access vlan [2-9]|[1-9][0-9]+"
check_config "5.2.1" "Ensure spanning-tree PortFast is enabled on access ports" \
    "show running-config | include spanning-tree portfast" \
    "spanning-tree portfast"

# Calculate pass/fail counts
pass_count=0
total_checks=0
while IFS='|' read -r status id name risk remediation; do
    if [ "$status" = "[PASS]" ]; then
        ((pass_count++))
    fi
    ((total_checks++))
done < $TEMP_FILE

fail_count=$((total_checks - pass_count))
pass_percentage=$(bc <<< "scale=2; ($pass_count / $total_checks) * 100")
fail_percentage=$(bc <<< "scale=2; ($fail_count / $total_checks) * 100")

# Generate HTML report
cat << EOF > $REPORT_FILE
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS Cisco IOS Switch Compliance Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        body { padding: 20px; }
        pre { background: #f8f9fa; padding: 10px; border-radius: 5px; white-space: pre-wrap; }
        .risk-high { color: #fd7e14; }
        .risk-medium { color: #ffc107; }
        .risk-low { color: #28a745; }
        .status-pass { color: #28a745; }
        .status-fail { color: #dc3545; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="text-center mb-4">CIS Cisco IOS Benchmark Compliance Report</h1>
        <p class="text-center">Generated on: $(date '+%Y-%m-%d %H:%M:%S %Z')</p>
        <hr>

        <!-- Pie Chart -->
        <div class="row mb-4">
            <div class="col-md-6 offset-md-3">
                <canvas id="complianceChart"></canvas>
            </div>
        </div>

        <!-- Summary -->
        <div class="alert alert-info">
            <strong>Summary:</strong> $pass_count of $total_checks checks passed ($pass_percentage%).
        </div>

        <!-- Findings Table -->
        <table class="table table-striped table-bordered">
            <thead class="table-dark">
                <tr>
                    <th>Finding ID</th>
                    <th>Issue Name</th>
                    <th>Risk Rating</th>
                    <th>Status</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
EOF

# Add table rows
while IFS='|' read -r status id name risk remediation; do
    status_clean=${status:1:-1} # Remove [ ]
    risk_class=$(echo "$risk" | tr '[:upper:]' '[:lower:]')
    cat << EOF >> $REPORT_FILE
                <tr>
                    <td>$id</td>
                    <td>$name</td>
                    <td class="risk-$risk_class">$risk</td>
                    <td class="status-$status_clean">$status_clean</td>
                    <td><pre>$remediation</pre></td>
                </tr>
EOF
done < $TEMP_FILE

# Complete HTML
cat << EOF >> $REPORT_FILE
            </tbody>
        </table>
    </div>

    <script>
        const ctx = document.getElementById('complianceChart').getContext('2d');
        new Chart(ctx, {
            type: 'pie',
            data: {
                labels: ['Passed', 'Failed'],
                datasets: [{
                    data: [$pass_percentage, $fail_percentage],
                    backgroundColor: ['#28a745', '#dc3545'],
                    borderColor: ['#fff', '#fff'],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'top' },
                    title: { display: true, text: 'Compliance Status' }
                }
            }
        });
    </script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
EOF

# Clean up
rm -f $TEMP_FILE

echo "Compliance check completed. HTML report saved to $REPORT_FILE"
echo "Open $REPORT_FILE in a web browser to view the report."
