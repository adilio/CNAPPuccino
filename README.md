```
    ____ _   _    _    ____  ____                 _
   / ___| \ | |  / \  |  _ \|  _ \ _   _  ___ ___(_)_ __   ___
  | |   |  \| | / _ \ | |_) | |_) | | | |/ __/ __| | '_ \ / _ \
  | |___| |\  |/ ___ \|  __/|  __/| |_| | (_| (__| | | | | (_) |
   \____|_| \_/_/   \_\_|   |_|    \__,_|\___\___|_|_| |_|\___/
```

# CNAPPuccino - Vulnerable Lab for Security Testing

A deliberately vulnerable Ubuntu 16.04 environment for testing CNAPP (Cloud-Native Application Protection Platform) and CSPM (Cloud Security Posture Management) tools in controlled settings.

## Important Security Notice

This creates an intentionally vulnerable system with multiple security flaws for educational and testing purposes only.

- Use only in isolated testing environments with restricted network access
- Never deploy on public networks or production environments  
- Ensure proper cleanup after testing

## Prerequisites

- AWS CLI configured with appropriate permissions
- Terraform >= 1.6.0 installed
- Bash shell (works with Bash 3.2+ including macOS default)

## Quick Start

```bash
# Clone and start
git clone https://github.com/adilio/cnappuccino.git && cd cnappuccino
chmod +x start.sh && ./start.sh

# Select option 2: Deploy Lab (Stage 1)
# Your vulnerable environment will be ready in 10-15 minutes
```

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
│   └── user_data.sh              # Complete vulnerable environment setup (injected via Terraform)
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

## CLI Usage (non-interactive)
```bash
./start.sh [flags] <command>

Flags:
  --owner OWNER          Set owner tag (default: barista)
  --region REGION        AWS region (default: us-east-1)
  --instance-type TYPE   Instance type (default: t3.medium)
  --profile PROFILE      AWS profile (default: default)
  --help, -h             Show help

Commands:
  deploy   Quick deploy with current/default settings
  status   Show deployment status
  test     Run quick exploit tests
  cleanup  Destroy resources
  menu     Interactive menu (default)

Examples:
  ./start.sh --owner john deploy
  ./start.sh --region us-west-2 --owner test deploy
  ./start.sh status
  ./start.sh cleanup
```

## Instant Validation

For immediate deployment verification:

```bash
./start.sh
# Select option 3: Quick RCE Test
```

**Manual testing:**
```bash
# Get the target IP
export TARGET_IP=$(cd terraform && terraform output -raw public_ip)

# Test CGI command injection
curl -H "User-Agent: id; whoami; uname -a" http://$TARGET_IP/cgi-bin/exec.cgi

# Test PHP local file inclusion  
curl -s "http://$TARGET_IP/view.php?file=/etc/passwd"

# Test directory listing
curl -s "http://$TARGET_IP:8080/secret/"
```

## Two-Stage Testing Approach

### Stage 1: Posture Assessment (Deploy + 24h Soak)
After deployment, install your security tools and let them establish baseline behavior:
- CSPM scans detect static vulnerabilities
- EDR/XDR establishes behavioral baseline  
- Compliance tools identify misconfigurations

### Stage 2: Runtime Exploitation (After Soak Period)
```bash
./start.sh
# Select option 5: Multi-Stage Runtime Exploits (Stage 2)
```

This executes a 5-phase attack chain covering MITRE ATT&CK and OWASP Top 10 techniques including system reconnaissance, credential harvesting, and privilege escalation simulation.

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

An Ubuntu 16.04 environment with:
- Critical CVEs (Heartbleed, Shellshock-like CGI)
- Multiple remote code execution vectors
- Hardcoded secrets and credentials
- Insecure configurations (disabled firewall, weak SSL/TLS)
- Web vulnerabilities (LFI, directory listing, file upload)

## Available Services

| Service | Port | Purpose | Vulnerability Type |
|---------|------|---------|-------------------|
| Apache HTTP | 80 | Web server with CGI | Shellshock-like Command Injection |
| Nginx HTTP | 8080 | Directory listing | Information disclosure |
| Nginx HTTPS | 8443 | SSL/TLS service | Heartbleed, weak crypto |
| SSH | 22 | Remote access | Weak authentication |
| MySQL | 3306 | Database | Default configuration |

## CSMP Tool Testing

Point your security scanner at the deployed instance to test detection of:
- End-of-life operating systems and missing patches
- Critical CVEs (Heartbleed, Shellshock)
- Hardcoded credentials and secrets management failures
- Insecure configurations and missing security controls
- Compliance violations (PCI DSS, SOX, HIPAA)

For comprehensive testing procedures and detailed guides, see [RUNTIME_TESTING.md](RUNTIME_TESTING.md).

## Monitoring and Diagnostics

CNAPPuccino includes comprehensive monitoring to track deployment progress:

```bash
./start.sh
# Select option 4: Lab Status & Diagnostics
```

**Features:**
- Real-time bootstrap phase monitoring
- SSH connectivity validation  
- Service health checks
- Bootstrap log analysis

**Bootstrap Timeline (10-15 minutes):**
1. **init** (0-1 min) - Setup directories and environment
2. **packages** (2-5 min) - Install vulnerable packages (longest phase)
3. **assets** (5-7 min) - Download scripts/configs from GitHub
4. **apache** (7-8 min) - Configure Apache with CGI support
5. **nginx** (8-9 min) - Configure Nginx with weak SSL
6. **services** (9-10 min) - Start all vulnerable services
7. **validation** (10-12 min) - Verify everything works

## Troubleshooting

**Common Issues:**
- If stuck longer than 15 minutes, use Option 4 to see current phase
- Check AWS console for instance health and network connectivity
- SSH connection issues: Verify security group allows port 22 access
- Service failures: Check bootstrap logs via SSH at `/var/log/cnappuccino-bootstrap.log`

**Recovery Options:**
1. Use Option 4 for live diagnostics and status
2. Use Option 8 to cleanup, then Option 2 to redeploy
3. SSH into instance to manually check service status and logs

## Cleanup

```bash
# Use the interactive menu
./start.sh
# Select option 8: Cleanup

# Or direct command
terraform destroy -auto-approve
```

## Educational Use

This environment is designed for:
- Security tool validation and testing
- Penetration testing practice in controlled settings
- Security awareness training and demonstrations
- Compliance testing and detection verification

## Legal Notice

This software is provided for educational and authorized testing purposes only. Users are responsible for compliance with applicable laws. The creators assume no liability for misuse.