# cis-cisco

A Bash script to check CIS Benchmark compliance for Cisco switches running IOS, IOS XE, or NX-OS.
It interactively collects device credentials, performs platform-specific security checks, and generates an HTML report with visual summaries.

✨ Features

    ✅ Interactive CLI prompts for IP, credentials, and platform selection

    🔐 Platform-specific checks based on CIS Benchmarks (Level 1)

    📦 Auto-installs required dependencies (sshpass, bc)

    📊 Generates HTML report with pass/fail pie chart and detailed findings

    🧾 Includes risk ratings and remediation commands for each check

🖥️ Supported Platforms

    Cisco IOS / IOS XE

    Cisco NX-OS

🚀 How to Use
1. Clone the repository

git clone https://github.com/3tternp/cis-cisco.git
cd cis-cisco

2. Make the script executable

chmod +x cis-cisco.sh

3. Run the script

./cis-cisco.sh

4. Follow interactive prompts

    Choose platform (IOS or NX-OS)

    Enter switch IP address, SSH port, username, and password

    Wait for compliance checks to complete

<img width="795" height="313" alt="image" src="https://github.com/user-attachments/assets/107e1213-df53-4414-9394-f783a4973372" />
