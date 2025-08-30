```
    ____ _   _    _    ____  ____                 _
   / ___| \ | |  / \  |  _ \|  _ \ _   _  ___ ___(_)_ __   ___
  | |   |  \| | / _ \ | |_) | |_) | | | |/ __/ __| | '_ \ / _ \
  | |___| |\  |/ ___ \|  __/|  __/| |_| | (_| (__| | | | | (_) |
   \____|_| \_/_/   \_\_|   |_|    \__,_|\___\___|_|_| |_|\___/
```
  Single Shot Deploy, Poured into the Cloud... ☕ ☁️

# ☕ CNAPPuccino - Vulnerable Lab for CSPM Testing

A deliberately vulnerable Ubuntu 16.04 environment designed to test CNAPP (Cloud-Native Application Protection Platform) & CSPM (Cloud Security Posture Management) tools in a controlled setting.

## ⚠️ CRITICAL WARNING

**This creates an INTENTIONALLY VULNERABLE system with multiple security flaws.**

- **NEVER deploy on public networks or production environments**
- **Use only in isolated testing environments with restricted network access**
- **Ensure proper cleanup after testing**

## Design Philosophy

CNAPPuccino follows a **"Single Shot Deploy"** philosophy:

- **Radical Simplicity** - One command deployment with zero external dependencies
- **Universal Compatibility** - Works with ancient Bash versions (macOS default: Bash 3.2)
- **Infrastructure as Code Purity** - Fully idempotent, clean rollback with `terraform destroy`
- **Immediate Value** - Working vulnerable environment in under 3 minutes

**The Trinity**: Only requires Bash, Terraform, and AWS CLI. No Python, Docker, Ansible, or complex toolchains.

## Repository Structure

```
cnappuccino/
├── README.md                     # Overview and quick start
├── RUNTIME_TESTING.md            # Comprehensive CSPM testing guide
├── start.sh                      # Interactive TUI for deployment and testing
├── .gitignore                    # Excludes sensitive files and state
├── terraform/                    # Infrastructure as Code
│   ├── main.tf                   # Core AWS infrastructure
│   ├── variables.tf              # Configurable parameters
│   ├── outputs.tf                # Connection info and test commands
│   ├── cloud-init-bootstrap.sh.tmpl  # Stage 1: tiny user_data that downloads Stage 2
│   ├── user_data.sh              # Stage 2: full vulnerable environment bootstrap (downloaded at runtime)
│   └── assets/                   # Vulnerable assets and configurations
│       ├── configs/              # Configuration files for vulnerable services
│       │   ├── apache-vhost.conf         # Apache virtual host configuration
│       │   ├── cgi-enabled.conf          # CGI module configuration
│       │   ├── cnappuccino-vulnerable-preferences  # Vulnerable package preferences
│       │   ├── fastcgi-php.conf          # PHP FastCGI configuration
│       │   ├── nginx-vulnerable.conf     # Nginx vulnerable configuration
│       │   └── ubuntu-trusty-sources.list # Ubuntu 14.04 package sources
│       ├── scripts/              # Vulnerable scripts and testing tools
│       │   ├── ciem_test.sh              # CIEM privilege escalation testing
│       │   ├── command_injection_test.sh # Command injection testing
│       │   ├── exec.cgi                  # Vulnerable CGI script
│       │   ├── test-exploits.sh          # Comprehensive exploit testing suite
│       │   └── webshell.php              # PHP web shell
│       └── web/                  # Web application files
│           ├── index.html                # Main web page
│           ├── upload.php                # File upload vulnerability
│           └── view.php                  # Local file inclusion vulnerability
├── testing/                      # Local testing and development tools
│   ├── README.md                 # Testing documentation
│   ├── test_user_data.sh         # Local script validation runner
│   └── docker/                   # Docker-based test environment
│       ├── Dockerfile            # Ubuntu 16.04 test container
│       ├── docker-compose.yml    # Container orchestration
│       └── run_test.sh           # Container test runner
└── cnappuccino-state/            # Gitignored - Local state and SSH keys
    ├── cnappuccino-key           # Auto-generated SSH private key
    └── cnappuccino-key.pub       # Auto-generated SSH public key
```

**Auto-Generated (Gitignored):**
```
cnappuccino-state/               # Local state and SSH keys
├── cnappuccino-key              # Auto-generated SSH private key
└── cnappuccino-key.pub          # Auto-generated SSH public key
```

## Quick Start

### Prerequisites
- AWS CLI configured with appropriate permissions
- Terraform >= 1.6.0 installed
- SSH key pair created in AWS (optional - will auto-generate)

### Single Shot Deploy
```bash
# Clone and start
git clone https://github.com/adilio/cnappuccino.git && cd cnappuccino
chmod +x start.sh && ./start.sh

# Select option 2: 🚀 Deploy Lab (Stage 1)
# Your vulnerable environment will be ready in 10-15 minutes
```

### Security Options

#### **IP Whitelisting (Optional)**
CNAPPuccino starts with `0.0.0.0/0` access for initial posture scanning, but can be restricted:

```bash
# Configure restricted access after Stage 1 posture assessment
./start.sh
# Select option 1: ⚙️ Lab Configuration
# Change allowed_cidr from 0.0.0.0/0 to YOUR_IP/32
```

**Recommended workflow:**
1. **Stage 1**: Deploy with `0.0.0.0/0` for CSPM posture scanning
2. **After 24h**: Restrict to your IP for Stage 2 runtime testing

#### **Built-in Vulnerabilities**
- **IMDSv1 enabled**: Vulnerable metadata service allows unauthenticated access
- **Open security groups**: Initially allows global access for posture detection
- **Missing security controls**: Designed to trigger CSPM alerts

#### **Environment Variables**
```bash
# Optional: Set custom CIDR before deployment
export ALLOWED_CIDR="YOUR_IP/32"        # Restrict access from start
./start.sh
```

### Architecture: Two-Stage Bootstrap

CNAPPuccino uses a resilient two-stage bootstrap to stay under the EC2 16KB user_data limit and improve reliability:

- **Stage 1 (cloud-init, tiny)**: `terraform/cloud-init-bootstrap.sh.tmpl`
  - Delivered as compressed user_data via `base64gzip(templatefile(...))`
  - Waits for basic network, ensures `curl` + CA certificates
  - Downloads Stage 2 from GitHub raw and executes it (warns if checksum changes)

- **Stage 2 (full setup)**: `terraform/user_data.sh`
  - Installs packages, configures Apache/Nginx/PHP, lays down vulnerable assets
  - Writes phase status files for the monitor, with robust logging
  - Provides local fallbacks if GitHub asset downloads fail (CGI, LFI, vhost, Nginx, CIEM script, secrets)

This architecture ensures reliable boots even with transient network hiccups.

### Two-Stage Testing Approach

CNAPPuccino implements a realistic enterprise security testing workflow:

#### **Stage 1: Posture Assessment & Baseline (Deploy + 24h Soak)**
```bash
# After deployment, install your XDR/EDR agent manually
ssh ubuntu@<instance-ip>
# Install your preferred XDR/EDR security agent

# Let your security tools establish baseline:
# - CSPM scans detect static vulnerabilities
# - EDR/XDR establishes behavioral baseline
# - Compliance tools identify misconfigurations
```

**Recommended soak time: 24 hours** for proper baseline establishment.

#### **Stage 2: Runtime Exploitation (After 24h Soak)**
```bash
# Use start.sh option 5 for full runtime exploitation
./start.sh
# Select option 5: ⚡ Multi-Stage Runtime Exploits (Stage 2)
```

**What This Does (High-Risk, Multi-Stage Attack Simulation):**
- Executes a **5-phase attack chain** covering key **MITRE ATT&CK** and **OWASP Top 10** techniques:
  1. **System Reconnaissance** — T1083 *(File and Directory Discovery)*
  2. **Credential Harvesting** — T1552.001 *(Credentials in Files)*
  3. **File System Enumeration** — T1083
  4. **Process Enumeration** — T1057 *(Process Discovery)*
  5. **CIEM Privilege Escalation Simulation** *(EC2 Instance Role → Lambda Admin Role takeover)* — Demonstrates Cloud Infrastructure Entitlement Management risk
- **Cloud IAM/Lambda Abuse:** In execute mode, will attempt REAL `sts:AssumeRole` into a Lambda administration role followed by live Lambda creation/deletion
- **OWASP Top 10 Coverage:** A01:2021, A03:2021, A05:2021, A06:2021, A07:2021, A09:2021
- **MITRE Coverage:** T1059.004, T1083, T1552.001, T1057, T1190, T1078, T1552.006
- Simulates **lateral movement** and **privilege escalation** in a cloud environment once an attacker has compromised an EC2 workload

**⚠️ WARNING:** This option is intentionally **noisy** and **dangerous** in a real AWS account. Only run in an isolated lab with controlled IAM policies and after completing the 24h soak period.

### Instant Validation (No Soak Required)

For immediate deployment verification without waiting for the 24-hour soak:

#### **Option 3: Quick RCE Test**
```bash
./start.sh
# Select option 3: 🧪 Quick RCE Test
```

**What this does:**
- Tests **Shellshock-like** CGI command injection via eval of User-Agent header (mimics CVE-2014-6271 exploitation)
- Validates that the vulnerable environment is working correctly
- Outputs framework indicators (MITRE T1059.004/T1190, OWASP A06:2021)
- Confirms remote code execution capability from your terminal

  > _Note: Classic Bash function-import Shellshock payloads are patched and do not work, but the endpoint remains critically vulnerable to direct "Shellshock-style" header command injection._

**Example output:**
```
SHELLSHOCK_RCE_EXPLOIT_CVE-2014-6271
MITRE_T1059.004_T1190
OWASP_A06-2021
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux cnappuccino 3.13.0-170-generic ...
```

#### **Manual Quick Test**
```bash
# Get the target IP
export TARGET_IP=$(cd terraform && terraform output -raw public_ip)

# Execute direct RCE with framework indicators
curl -H "User-Agent: id; whoami; uname -a; echo 'RCE_INDICATOR';" \
     http://$TARGET_IP/cgi-bin/exec.cgi
```

**Use Case:** Perfect for validating deployment success before beginning the 24-hour soak period.

### Enhanced Bootstrap Monitoring

CNAPPuccino now includes professional-grade deployment monitoring to eliminate the mystery of "User Data Running":

#### **Live Progress Tracking**
```bash
./start.sh
# Select option 2: 🚀 Deploy Lab (Stage 1)
# Choose "y" when prompted to monitor bootstrap progress
```

**Features:**
- **Real-time Phase Monitoring**: See exactly which bootstrap phase is running
- **Expected Timeline**: Clear 10–15 minute timeline with phase-by-phase breakdown
- **Stuck Detection**: Automatic warnings if phases run longer than expected (5+ minutes)
- **SSH Connectivity Checks**: Validates instance is reachable before monitoring
- **Phase Descriptions**: Explains what each phase does
- **Faster updates**: Refresh every 3 seconds, showing the last 20 bootstrap log lines

#### **Bootstrap Diagnostics**
```bash
./start.sh
# Select option 9: 🔍 Bootstrap Diagnostics
```

**Comprehensive Diagnostics Include:**
- SSH connectivity and authentication status
- Current bootstrap phase and completion status
- Service health (Apache, Nginx, SSH)
- Listening ports validation
- Recent bootstrap log entries
- Failure diagnostics with root cause analysis

#### **Post-Deployment Validation**
After deployment, the system automatically:
- Validates deployment success/failure
- Provides clear next-step guidance
- Identifies specific issues if deployment failed
- Recommends appropriate troubleshooting actions

**Expected Bootstrap Timeline:**
1. **init** (0-1 min) - Setup directories and environment
2. **packages** (2-5 min) - Install Ubuntu packages ⭐ **LONGEST PHASE**
3. **assets** (5-7 min) - Download scripts/configs from GitHub raw (with local fallbacks)
4. **apache** (7-8 min) - Configure Apache with CGI support
5. **nginx** (8-9 min) - Configure Nginx with weak SSL
6. **services** (9-10 min) - Start all vulnerable services
7. **validation** (10-12 min) - Verify everything works

Notes:
- If GitHub is slow/unreachable, fallbacks ensure CGI RCE, PHP LFI, and dir listing still work.
- Apache’s CGI environment includes `LAMBDA_ADMIN_ROLE_ARN` and `AWS_DEFAULT_REGION` for CIEM testing.

## Vulnerability Overview

| Vulnerability | CVE | OWASP Top 10 | MITRE ATT&CK | Severity | Test Endpoint |
|---------------|-----|--------------|--------------|----------|---------------|
| **Shellshock-like CGI Command Injection** | CVE-2014-6271\* | A06:2021 | T1059.004, T1190 | Critical (9.8) | `http://$TARGET_IP/cgi-bin/exec.cgi` |
| **Heartbleed** | CVE-2014-0160 | A06:2021 | T1005, T1040 | Critical (7.5) | `https://$TARGET_IP:8443` |
| **File Upload** | - | A03:2021, A04:2021 | T1105, T1059.004 | High | `http://$TARGET_IP/upload.php` |
| **Local File Inclusion** | - | A03:2021 | T1005, T1083 | High | `http://$TARGET_IP/view.php` |
| **Directory Listing** | - | A01:2021, A05:2021 | T1083, T1552.001 | Medium | `http://$TARGET_IP:8080/secret/` |
| **Weak SSH** | - | A07:2021 | T1110.001, T1078.003 | High | `ssh://$TARGET_IP:22` |
| **Hardcoded Secrets** | - | A07:2021, A09:2021 | T1552.001, T1078 | High | Multiple locations |
| **Disabled Firewall** | - | A05:2021 | T1562.004 | Medium | System-wide |
| **Weak SSL/TLS** | - | A02:2021, A05:2021 | T1040, T1557 | Medium | `https://$TARGET_IP:8443` |
| **IMDSv1 Enabled** | - | A05:2021 | T1552.006 | Medium | EC2 Metadata Service | 

## What This Creates

**Enterprise-Grade Vulnerable Environment:**
- **Ubuntu 16.04 LTS** on **t3.medium** instance
- **Critical CVEs** (Heartbleed, Shellshock-like CGI) with remote exploitation
- **Multiple RCE vectors** (Shellshock-style CGI, file upload, SSH)
- **Hardcoded secrets** (AWS credentials, API keys) in multiple locations
- **Insecure configurations** (disabled firewall, weak SSL/TLS)
- **Web vulnerabilities** (LFI, directory listing, unrestricted upload)

  > _\* The CGI vulnerability is Shellshock-style: direct header injection of shell commands, not function-import._

**Two-Stage Testing Workflow:**
- **Stage 1**: Deploy and soak for 24 hours (posture assessment)
- **Stage 2**: Active exploitation after baseline establishment

## Testing Approach: Staged Security Assessment

### **Why Staged Testing?**
Enterprise security tools need time to establish baselines and detect anomalies. CNAPPuccino simulates real-world attack timelines where initial compromise is followed by a period of reconnaissance before active exploitation.

### **Stage 1: Posture Assessment (0-24 hours)**
**You deploy and let security tools establish baseline behavior.**

After deployment:
1. **Install your EDR/XDR agent** manually (vendor-agnostic approach)
2. **CSPM tools scan** for static vulnerabilities and misconfigurations
3. **Security baseline establishment** - normal process and network patterns
4. **Compliance scans** identify policy violations

**Key Point:** No active exploitation during this phase - purely posture assessment.

### **Stage 2: Runtime Exploitation (24+ hours)**
**You trigger active attacks to test behavioral detection.**

```bash
# Use start.sh for guided exploitation
./start.sh
# Option 5: ⚡ Multi-Stage Runtime Exploits (Stage 2)
```

**Attack simulation includes:**
- Remote code execution via direct CGI eval(User-Agent) injection
- Credential harvesting and file enumeration  
- Privilege escalation simulation
- CIEM testing (EC2 → Lambda privilege chains)

### **Immediate Testing (Optional)**
For quick validation without staging:
```bash
# Option 3: 🧪 Quick RCE Test (works immediately)
```

## CSPM Tool Testing

For comprehensive CSPM testing procedures, validation checklists, and detailed exploitation guides, see:

**📋 [Testing Guide](RUNTIME_TESTING.md)**

The testing guide includes:
- Step-by-step vulnerability validation
- OWASP Top 10 and MITRE ATT&CK mappings
- Compliance framework testing (PCI DSS, SOX, HIPAA)
- Real-time detection scenarios
- Expected findings and remediation guidance

### Quick CSPM Validation

Point your security scanner at the deployed instance to test detection of:

**Stage 1 (Posture) Detection:**
- End-of-life operating systems and missing patches
- Critical CVEs (Heartbleed, Shellshock) in static analysis
- Hardcoded credentials and secrets management failures
- Insecure configurations and missing security controls
- Compliance violations (PCI DSS, SOX, HIPAA frameworks)

**Stage 2 (Runtime) Detection:**  
- Remote code execution attempts and successful compromise
- Behavioral anomalies and process execution patterns
- Credential harvesting and lateral movement simulation
- Network communication anomalies and data exfiltration patterns

## Available Endpoints

| Service | Port | Purpose | Vulnerability Type |
|---------|------|---------|-------------------|
| Apache HTTP | 80 | Web server with CGI | Shellshock-like Command Injection |
| Nginx HTTP | 8080 | Directory listing | Information disclosure |
| Nginx HTTPS | 8443 | SSL/TLS service | Heartbleed, weak crypto |
| SSH | 22 | Remote access | Weak authentication |
| MySQL | 3306 | Database | Default configuration |

## Remote Exploitation Examples

### Execute Built-in Exploit Scripts
```bash
# Run Heartbleed exploit remotely via RCE
curl -H "User-Agent: /usr/bin/python3 /opt/cnappuccino/exploits/heartbleed.py $TARGET_IP 8443" \
     http://$TARGET_IP/cgi-bin/exec.cgi

# Run Shellshock test script remotely
curl -H "User-Agent: id; whoami; uname -a" \
     http://$TARGET_IP/cgi-bin/exec.cgi
```

### Simulate Attack Chain
```bash
# 1. Initial access (T1190 - Exploit Public-Facing Application)
curl -H "User-Agent: id; whoami" http://$TARGET_IP/cgi-bin/exec.cgi

# 2. System reconnaissance (T1083 - File and Directory Discovery)
curl -H "User-Agent: /bin/uname -a && /bin/cat /etc/issue | sed 's/\\\\l//'" http://$TARGET_IP/cgi-bin/exec.cgi

# 3. Credential harvesting (T1552.001 - Credentials In Files)
curl -H "User-Agent: /bin/cat /opt/cnappuccino/secret/aws_creds.txt" http://$TARGET_IP/cgi-bin/exec.cgi
```

For complete attack scenarios and detailed validation procedures, see [RUNTIME_TESTING.md](RUNTIME_TESTING.md).

## Cleanup

```bash
# Single command cleanup
terraform destroy -auto-approve

# Verify cleanup
aws ec2 describe-instances --filters "Name=tag:Name,Values=CNAPPuccino-*" --query "Reservations[].Instances[].State.Name"
```

## Local Testing & Development

For developers and contributors who want to test the user data script locally before deploying to AWS:

### Docker-Based Local Testing

```bash
# Test the user data script in a local Ubuntu 16.04 container
testing/test_user_data.sh

# Watch the script execution in real-time
testing/test_user_data.sh logs

# Debug issues inside the test container
testing/test_user_data.sh shell

# Clean up when done
testing/test_user_data.sh stop
```

### What Local Testing Validates

- ✅ **Package Installation** - Verifies vulnerable packages install correctly
- ✅ **Service Configuration** - Tests Apache, Nginx, PHP, MySQL setup
- ✅ **Vulnerability Creation** - Confirms Shellshock, Heartbleed vulnerabilities are present
- ✅ **CSPM Assets** - Validates hardcoded credentials and misconfigurations
- ✅ **Script Completion** - Ensures user data runs to completion without errors

### Requirements

- Docker and Docker Compose installed
- Sufficient disk space for Ubuntu 16.04 base image (~500MB)

**Note:** Local testing simulates the AWS environment but doesn't test AWS-specific features like EC2 metadata service or IAM roles.

For detailed local testing instructions, see: **[testing/README.md](testing/README.md)**

## Troubleshooting

### Bootstrap Diagnostics
```bash
./start.sh
# Select option 9: 🔍 Bootstrap Diagnostics
```

This provides comprehensive diagnostics including:
- SSH connectivity and authentication status
- Current bootstrap phase and completion status
- Service health (Apache, Nginx, SSH)
- Listening ports validation
- Recent bootstrap log entries
- Failure diagnostics with root cause analysis

### Common Issues & Solutions

#### **Stuck at "User Data Running"**
The bootstrap process takes 10-15 minutes and runs in phases:
1. **init** (0-1 min) - Setup directories and environment
2. **packages** (2-5 min) - Install Ubuntu 14.04 vulnerable packages ⭐ **LONGEST PHASE**
3. **assets** (5-7 min) - Download scripts/configs from S3
4. **apache** (7-8 min) - Configure Apache with CGI support
5. **nginx** (8-9 min) - Configure Nginx with weak SSL
6. **services** (9-10 min) - Start all vulnerable services
7. **validation** (10-12 min) - Verify everything works

**If stuck longer than expected:**
- Use Option 9 to see current phase and status
- Check AWS console for instance health
- Common issues: Package downloads, S3 access, service startup

#### **SSH Connection Failed**
```bash
# Check instance status
aws ec2 describe-instance-status --instance-ids $(terraform output -raw instance_id)

# Check security group allows SSH
aws ec2 describe-security-groups --group-ids $(terraform output -raw security_group_id)
```

#### **Services Not Starting**
```bash
# Check bootstrap logs
ssh ubuntu@$TARGET_IP 'tail -50 /var/log/cnappuccino-bootstrap.log'

# Check service status
ssh ubuntu@$TARGET_IP 'systemctl status apache2 nginx ssh'

# Check listening ports
ssh ubuntu@$TARGET_IP 'netstat -tlnp | grep -E ":(80|8080|8443|22) "'
```

#### **CGI Endpoint Not Working**
```bash
# Test CGI endpoint
curl -I http://$TARGET_IP/cgi-bin/exec.cgi

# Check Apache error logs
ssh ubuntu@$TARGET_IP 'tail -20 /var/log/apache2/error.log'
```

### Local Testing Issues
```bash
# Test the user data script locally first
testing/test_user_data.sh

# Check logs for errors
testing/test_user_data.sh logs

# Debug interactively
testing/test_user_data.sh shell
```

### Recovery Options
1. **Monitor Progress**: Use Option 9 for live diagnostics
2. **Clean Redeploy**: Use Option 8 to cleanup, then Option 2 to redeploy
3. **Manual Recovery**: SSH in and check `/var/log/cnappuccino-bootstrap.log`
4. **Force Cleanup**: Use Option 8 with "Nuclear Option" if standard cleanup fails

## Educational Use

This environment is designed for:
- **Security tool validation** - Test CSPM, vulnerability scanners, and monitoring tools
- **Penetration testing practice** - Safe environment for learning exploitation techniques  
- **Security awareness training** - Demonstrate real-world vulnerabilities
- **Compliance testing** - Verify security controls and detection capabilities

## Contributing

Contributions welcome! Please:
- Test changes in isolated environments
- Follow the "Single Shot Deploy" philosophy
- Maintain compatibility with Bash 3.2+
- Document new vulnerabilities thoroughly

## Legal Notice

This software is provided for educational and authorized testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. The creators assume no liability for misuse of this software.
