# CNAPPuccino — Vulnerable Cloud Lab (CSPM + Runtime)

Intentionally vulnerable Ubuntu environment for CSPM and runtime testing. Deploys on AWS EC2 with Apache, Nginx, PHP, and multiple exploitable paths.

## Safety First
- Do not deploy in production accounts or networks
- Use isolated test accounts and CIDR restrictions
- Clean up when done (Option 8)

## What You Get
- Web vulns: CGI RCE (`/cgi-bin/exec.cgi`), PHP LFI (`/view.php`), file upload (`/upload.php`), dir listing (`:8080/secret/`)
- System/cloud misconfig: weak SSH, IMDSv1, hardcoded secrets, weak SSL/TLS
- CIEM demo: EC2 instance role → Lambda Admin assume‑role (Option 5)

## Architecture (2‑Stage Bootstrap)
- Stage 1 (tiny user_data): `terraform/cloud-init-bootstrap.sh.tmpl`
  - base64gzip’d user_data; waits for network; ensures curl/CA
  - downloads Stage 2 from GitHub raw and executes (checksum logged)
- Stage 2 (full install): `terraform/user_data.sh`
  - installs packages and configures Apache/Nginx/PHP
  - writes phase markers and detailed logs
  - local fallbacks if downloads fail (exec.cgi, view.php, vhost, Nginx, CIEM script, secrets)

## Prerequisites
- AWS CLI configured, Terraform ≥ 1.6, Bash

## Quick Start
- Clone + menu: `git clone https://github.com/adilio/CNAPPuccino.git && cd cnappuccino && ./start.sh`
- Deploy: Option 2 (Stage 1). Ready in ~10–15 min
- Status: `./start.sh status` (shows IP and endpoints)
- Cleanup: Option 8

## Fast Validation (no soak)
- Quick RCE: Option 3
- Manual checks (replace IP):
  - `curl -s -H "User-Agent: id; whoami; hostname" http://IP/cgi-bin/exec.cgi`
  - `curl -s "http://IP/view.php?file=/etc/passwd"`
  - `curl -s "http://IP:8080/secret/"`

## Runtime Exploits (Option 5)
- Five stages: recon, credentials, file/process enum, CIEM
- CIEM uses `LAMBDA_ADMIN_ROLE_ARN` (injected into Apache CGI env) to attempt assume‑role and create a Lambda
- Recommended after 24h soak; can run immediately for demo

## Monitoring
- Enhanced progress (offered during Option 2)
  - Real‑time phase + last 20 log lines; refresh every 3s
  - Logs on instance: `/var/log/cnappuccino-bootstrap.log`
- Diagnostics: Option 9 (services, ports, recent logs)

## Vulnerable Endpoints (after deploy)
- CGI RCE: `http://<ip>/cgi-bin/exec.cgi`
- LFI: `http://<ip>/view.php?file=/etc/passwd`
- Upload: `http://<ip>/upload.php`
- Dir listing: `http://<ip>:8080/secret/`

## Troubleshooting
- Status: `./start.sh status`
- Monitor again: run the enhanced monitor from Option 2
- SSH + logs: `ssh ubuntu@<ip>` then `sudo tail -n 50 /var/log/cnappuccino-bootstrap.log`
- Services: `systemctl status apache2 nginx` and ports: `ss -tlnp | grep -E ':(80|8080|8443|22) '`
- Redeploy clean: Option 8 then Option 2

## Notes
- User data size: ≤16 KB (Stage 1 only). Stage 2 is downloaded at runtime
- Fallbacks ensure CGI RCE, LFI, and dir listing work even if asset downloads fail
- To pin Stage 2 to a commit/tag for deterministic boots, add a fixed ref in `main.tf`

## Contributing
- Keep the experience simple; avoid new dependencies
- Test changes in an isolated account
- Document new behaviors briefly and clearly

## Legal
Educational use only. You are responsible for compliant use and costs. The authors assume no liability for misuse.

