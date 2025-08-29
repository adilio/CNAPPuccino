#!/usr/bin/env bash
# CNAPPuccino Stage 2 Bootstrap - Reliable and Debuggable
# Architecture: Staged bootstrap with error handling, structured logging, and idempotent operations

set -euo pipefail

#############################################
# BOOTSTRAP CONFIGURATION
#############################################
readonly BOOTSTRAP_LOG="/var/log/cnappuccino-bootstrap.log"
readonly STATE_DIR="/opt/cnappuccino/state"
readonly TEMP_DIR="/tmp/cnappuccino-setup"
readonly AWS_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
readonly LAMBDA_ADMIN_ROLE_ARN="${LAMBDA_ADMIN_ROLE_ARN:-arn-not-set}"

# Create required directories
mkdir -p "$STATE_DIR" "$TEMP_DIR" /run/lock/apache2 /var/lock/apache2
chmod 777 /run/lock /run/lock/apache2 /var/lock/apache2 "$TEMP_DIR"
ln -sf /run/lock /var/lock

#############################################
# STRUCTURED LOGGING FRAMEWORK
#############################################
log_with_context() {
    local level="$1"
    local phase="${2:-GENERAL}"
    local message="$3"
    local timestamp=$(date -Iseconds)
    local pid=$$
    
    echo "[$timestamp] [$level] [$phase] [$pid] $message" | tee -a "$BOOTSTRAP_LOG"
    
    # Also log to syslog for centralized collection
    logger -t "cnappuccino-bootstrap" "[$level] [$phase] $message" 2>/dev/null || true
}

log_info() { log_with_context "INFO" "${BOOTSTRAP_PHASE:-INIT}" "$1"; }
log_warn() { log_with_context "WARN" "${BOOTSTRAP_PHASE:-INIT}" "$1"; }
log_error() { log_with_context "ERROR" "${BOOTSTRAP_PHASE:-INIT}" "$1"; }
log_debug() { log_with_context "DEBUG" "${BOOTSTRAP_PHASE:-INIT}" "$1"; }

#############################################
# ERROR HANDLING & ROLLBACK
#############################################
rollback_on_failure() {
    local exit_code=$?
    log_error "Bootstrap failed in phase ${BOOTSTRAP_PHASE:-UNKNOWN} with exit code $exit_code"
    
    # Stop services that might be partially started
    systemctl stop apache2 nginx mysql 2>/dev/null || true
    service apache2 stop 2>/dev/null || true
    service nginx stop 2>/dev/null || true
    service mysql stop 2>/dev/null || true
    
    # Mark failure state
    echo "failed" > "$STATE_DIR/bootstrap_status"
    echo "$exit_code" > "$STATE_DIR/last_error_code"
    echo "${BOOTSTRAP_PHASE:-UNKNOWN}" > "$STATE_DIR/failed_phase"
    
    # Generate diagnostic info
    {
        echo "=== Bootstrap Failure Report ==="
        echo "Timestamp: $(date -Iseconds)"
        echo "Failed Phase: ${BOOTSTRAP_PHASE:-UNKNOWN}"
        echo "Exit Code: $exit_code"
        echo "Instance ID: $(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo 'unknown')"
        echo ""
        echo "=== System State ==="
        echo "Disk Usage:"
        df -h 2>/dev/null || true
        echo ""
        echo "Memory Usage:"
        free -h 2>/dev/null || true
        echo ""
        echo "Network Interfaces:"
        ip addr 2>/dev/null || ifconfig 2>/dev/null || true
        echo ""
        echo "Active Processes:"
        ps aux | head -20 2>/dev/null || true
        echo ""
        echo "Recent Logs:"
        tail -50 "$BOOTSTRAP_LOG" 2>/dev/null || true
    } > "$STATE_DIR/failure_diagnostics.txt"
    
    log_error "Diagnostic information saved to $STATE_DIR/failure_diagnostics.txt"
    log_error "Bootstrap rollback completed"
    
    exit $exit_code
}

trap rollback_on_failure ERR

#############################################
# IDEMPOTENT OPERATIONS FRAMEWORK
#############################################
check_package_installed() {
    local package="$1"
    dpkg -l | grep -q "^ii.*$package " 2>/dev/null
}

install_package_idempotent() {
    local package="$1"
    local version="${2:-}"
    
    if check_package_installed "$package"; then
        log_debug "Package $package already installed, skipping"
        return 0
    fi
    
    log_info "Installing package: $package${version:+ (version: $version)}"
    
    if [[ -n "$version" ]]; then
        apt-get install -y --allow-downgrades "$package=$version" || \
        apt-get install -y --allow-downgrades "$package" || \
        return 1
    else
        apt-get install -y "$package" || return 1
    fi
    
    log_info "Package $package installed successfully"
}

check_service_active() {
    local service="$1"
    systemctl is-active "$service" >/dev/null 2>&1 || service "$service" status >/dev/null 2>&1
}

#############################################
# ROBUST SERVICE MANAGEMENT
#############################################
ensure_service_running() {
    local service="$1"
    local max_attempts=5
    local attempt=1
    local wait_time=10
    
    log_info "Ensuring service $service is running"
    
    while [[ $attempt -le $max_attempts ]]; do
        if check_service_active "$service"; then
            log_info "Service $service is already running"
            return 0
        fi
        
        log_info "Starting $service (attempt $attempt/$max_attempts)"
        
        # Try multiple methods to start the service
        if systemctl start "$service" 2>/dev/null || service "$service" start 2>/dev/null; then
            # Give service time to start
            sleep 5
            
            if check_service_active "$service"; then
                log_info "Service $service started successfully"
                
                # Enable service for auto-start
                systemctl enable "$service" 2>/dev/null || \
                update-rc.d "$service" enable 2>/dev/null || \
                chkconfig "$service" on 2>/dev/null || true
                
                return 0
            fi
        fi
        
        log_warn "$service start attempt $attempt/$max_attempts failed"
        
        if [[ $attempt -lt $max_attempts ]]; then
            log_info "Waiting ${wait_time}s before retry..."
            sleep $wait_time
        fi
        
        ((attempt++))
    done
    
    log_error "Failed to start $service after $max_attempts attempts"
    
    # Collect diagnostic information
    {
        echo "=== Service $service Failure Diagnostics ==="
        echo "Timestamp: $(date -Iseconds)"
        echo ""
        echo "Service Status:"
        systemctl status "$service" 2>&1 || service "$service" status 2>&1 || true
        echo ""
        echo "Service Logs (last 50 lines):"
        journalctl -u "$service" -n 50 --no-pager 2>/dev/null || \
        tail -50 "/var/log/$service.log" 2>/dev/null || \
        tail -50 "/var/log/syslog" | grep "$service" 2>/dev/null || true
        echo ""
        echo "Port Usage:"
        netstat -tlnp 2>/dev/null | grep -E "(apache|nginx|mysql)" || \
        ss -tlnp 2>/dev/null | grep -E "(apache|nginx|mysql)" || true
    } > "$STATE_DIR/${service}_failure_diagnostics.txt"
    
    return 1
}

#############################################
# STAGED BOOTSTRAP FRAMEWORK
#############################################
bootstrap_phase() {
    local phase_name="$1"
    local phase_file="$STATE_DIR/phase_${phase_name}"
    
    export BOOTSTRAP_PHASE="$phase_name"
    
    if [[ -f "$phase_file" ]]; then
        log_info "Phase $phase_name already completed, skipping"
        return 0
    fi
    
    log_info "Starting bootstrap phase: $phase_name"
    echo "started" > "${phase_file}.status"
    
    case "$phase_name" in
        "init")
            bootstrap_phase_init
            ;;
        "packages")
            bootstrap_phase_packages
            ;;
        "assets")
            bootstrap_phase_assets
            ;;
        "apache")
            bootstrap_phase_apache
            ;;
        "nginx")
            bootstrap_phase_nginx
            ;;
        "services")
            bootstrap_phase_services
            ;;
        "validation")
            bootstrap_phase_validation
            ;;
        *)
            log_error "Unknown bootstrap phase: $phase_name"
            return 1
            ;;
    esac
    
    echo "completed" > "$phase_file"
    log_info "Phase $phase_name completed successfully"
}

#############################################
# BOOTSTRAP PHASES
#############################################
bootstrap_phase_init() {
    log_info "Initializing CNAPPuccino environment"
    
    # Set hostname
    hostnamectl set-hostname cnappuccino-lab 2>/dev/null || hostname cnappuccino-lab
    echo "127.0.1.1 cnappuccino-lab" >> /etc/hosts
    log_info "Hostname set to $(hostname)"
    
    # Set environment
    export DEBIAN_FRONTEND=noninteractive
    
    # Create directory structure
    mkdir -p /opt/cnappuccino/{exploits,secret,logs} \
              /var/www/html/{uploads,tmp} \
              /usr/lib/cgi-bin \
              /etc/nginx/ssl \
              /etc/apache2/snippets

    # Set permissions
    chmod 777 /var/www/html/uploads /var/www/html/tmp /tmp
    
    # Create symlink to cgi-bin (remove directory first if it exists)
    rm -rf /var/www/html/cgi-bin
    ln -sf /usr/lib/cgi-bin /var/www/html/cgi-bin
    
    log_info "Directory structure created"
}

bootstrap_phase_packages() {
    log_info "Installing vulnerable packages"
    
    # Install essential tools first (needed for asset downloads)
    install_package_idempotent "curl"
    install_package_idempotent "wget"
    
    # Add Ubuntu 14.04 repositories for vulnerable packages
    if [[ ! -f /etc/apt/sources.list.backup ]]; then
        cp /etc/apt/sources.list /etc/apt/sources.list.backup
        
        cat >> /etc/apt/sources.list <<EOF

# Ubuntu 14.04 LTS (Trusty) repositories - for vulnerable packages
deb http://old-releases.ubuntu.com/ubuntu/ trusty main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ trusty-updates main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ trusty-security main restricted universe multiverse
EOF
        log_info "Added Ubuntu 14.04 repositories"
    fi
    
    # Download and apply vulnerable preferences from S3
    download_asset "configs/cnappuccino-vulnerable-preferences" "/etc/apt/preferences.d/cnappuccino-vulnerable"
    
    # Install base packages
    install_package_idempotent "apache2"
    install_package_idempotent "libapache2-mod-php"
    install_package_idempotent "php"
    install_package_idempotent "php-cli"
    install_package_idempotent "nginx"
    install_package_idempotent "openssh-server"
    install_package_idempotent "zip"
    install_package_idempotent "awscli"
    install_package_idempotent "jq"
    
    # Install vulnerable versions with fallbacks
    log_info "Installing vulnerable bash version"
    install_package_idempotent "bash" "4.3-7ubuntu1.5" || \
    install_package_idempotent "bash" "4.3*" || \
    install_package_idempotent "bash"
    
    log_info "Installing vulnerable OpenSSL"
    install_package_idempotent "openssl" "1.0.1f-1ubuntu2.27" || \
    install_package_idempotent "openssl" "1.0.1*" || \
    install_package_idempotent "openssl"
    
    install_package_idempotent "libssl1.0.0" "1.0.1f-1ubuntu2.27" || \
    install_package_idempotent "libssl1.0.0" "1.0.1*" || \
    install_package_idempotent "libssl1.0.0"
    
    # Hold vulnerable packages
    apt-mark hold bash openssl libssl1.0.0 apache2 2>/dev/null || true
    
    log_info "Package installation completed"
}

bootstrap_phase_assets() {
    log_info "Downloading vulnerable assets from S3"
    
    # Download scripts
    download_asset "scripts/exec.cgi" "/usr/lib/cgi-bin/exec.cgi"
    chmod +x /usr/lib/cgi-bin/exec.cgi
    
    download_asset "scripts/ciem_test.sh" "/opt/cnappuccino/exploits/ciem_test.sh"
    download_asset "scripts/command_injection_test.sh" "/opt/cnappuccino/exploits/command_injection_test.sh"
    download_asset "scripts/webshell.php" "/opt/cnappuccino/exploits/webshell.php"
    chmod +x /opt/cnappuccino/exploits/*.sh
    
    # Download web content
    download_asset "web/view.php" "/var/www/html/view.php"
    download_asset "web/upload.php" "/var/www/html/upload.php"
    download_asset "web/index.html" "/var/www/html/index.html"
    
    # Download configuration files
    download_asset "configs/fastcgi-php.conf" "/etc/apache2/snippets/fastcgi-php.conf"
    download_asset "configs/apache-vhost.conf" "/etc/apache2/sites-available/000-default.conf"
    download_asset "configs/nginx-vulnerable.conf" "/etc/nginx/sites-available/cnappuccino"
    download_asset "configs/cgi-enabled.conf" "/etc/apache2/conf-enabled/cgi-enabled.conf"
    
    log_info "Asset download completed"
}

bootstrap_phase_apache() {
    log_info "Configuring Apache with CGI support"
    
    # Enable required modules
    a2enmod php7.0 2>/dev/null || a2enmod php 2>/dev/null || true
    a2enmod ssl
    a2enmod cgi || a2enmod cgid
    
    # Enable configurations
    a2enconf cgi-enabled 2>/dev/null || true
    
    # Enable directory index for PHP
    if [[ -f /etc/apache2/mods-enabled/dir.conf ]]; then
        sed -i 's/DirectoryIndex .*/DirectoryIndex index.php index.html index.cgi index.pl index.xhtml index.htm/' \
            /etc/apache2/mods-enabled/dir.conf
    fi
    
    log_info "Apache configuration completed"
}

bootstrap_phase_nginx() {
    log_info "Configuring Nginx with weak SSL"
    
    # Stop nginx to avoid conflicts during setup
    systemctl stop nginx 2>/dev/null || service nginx stop 2>/dev/null || true
    
    # Generate weak self-signed certificate
    if [[ ! -f /etc/nginx/ssl/nginx.crt ]]; then
        openssl req -x509 -nodes -days 365 -newkey rsa:1024 \
            -keyout /etc/nginx/ssl/nginx.key \
            -out /etc/nginx/ssl/nginx.crt \
            -subj "/C=US/ST=Test/L=Test/O=CNAPPuccino/CN=vulnerable.local" \
            -sha1 2>/dev/null || {
            
            log_warn "Primary SSL certificate generation failed, trying fallback method"
            openssl req -new -newkey rsa:1024 -days 365 -nodes -x509 \
                -keyout /etc/nginx/ssl/nginx.key \
                -out /etc/nginx/ssl/nginx.crt \
                -subj "/C=US/ST=Test/L=Test/O=CNAPPuccino/CN=vulnerable.local" 2>/dev/null || {
                log_error "SSL certificate generation failed completely"
                return 1
            }
        }
        log_info "SSL certificate generated"
    fi
    
    # Enable nginx configuration
    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/cnappuccino /etc/nginx/sites-enabled/
    
    log_info "Nginx configuration completed"
}

bootstrap_phase_services() {
    log_info "Starting vulnerable services"
    
    # Start PHP-FPM
    if check_package_installed "php5-fpm"; then
        ensure_service_running "php5-fpm"
    elif check_package_installed "php7.0-fpm"; then
        ensure_service_running "php7.0-fpm"
    fi
    
    # Start main services
    ensure_service_running "apache2"
    ensure_service_running "nginx"
    ensure_service_running "ssh"
    
    # Start MySQL with weak password
    if check_package_installed "mysql-server"; then
        debconf-set-selections <<< 'mysql-server mysql-server/root_password password vulnerable123'
        debconf-set-selections <<< 'mysql-server mysql-server/root_password_again password vulnerable123'
        ensure_service_running "mysql"
    fi
    
    log_info "Service startup completed"
}

bootstrap_phase_validation() {
    log_info "Validating deployment"
    
    local validation_failed=0
    
    # Check critical services
    local critical_services=("apache2" "nginx" "ssh")
    for service in "${critical_services[@]}"; do
        if check_service_active "$service"; then
            log_info "✓ Service $service is running"
        else
            log_error "✗ Service $service is not running"
            ((validation_failed++))
        fi
    done
    
    # Check critical ports
    local ports=("80:apache2" "8080:nginx" "8443:nginx-ssl" "22:ssh")
    for port_service in "${ports[@]}"; do
        local port="${port_service%:*}"
        local service="${port_service#*:}"
        
        if netstat -tlnp 2>/dev/null | grep -q ":$port " || ss -tlnp 2>/dev/null | grep -q ":$port "; then
            log_info "✓ Port $port ($service) is listening"
        else
            log_error "✗ Port $port ($service) is not listening"
            ((validation_failed++))
        fi
    done
    
    # Check critical files
    local critical_files=(
        "/usr/lib/cgi-bin/exec.cgi"
        "/var/www/html/view.php"
        "/var/www/html/upload.php"
        "/var/www/html/index.html"
        "/opt/cnappuccino/exploits/ciem_test.sh"
    )
    
    for file in "${critical_files[@]}"; do
        if [[ -f "$file" ]]; then
            log_info "✓ Critical file $file exists"
        else
            log_error "✗ Critical file $file is missing"
            ((validation_failed++))
        fi
    done
    
    # Test CGI endpoint
    if curl -s --connect-timeout 5 "http://localhost/cgi-bin/exec.cgi" >/dev/null 2>&1; then
        log_info "✓ CGI endpoint is accessible"
    else
        log_error "✗ CGI endpoint test failed"
        ((validation_failed++))
    fi
    
    if [[ $validation_failed -eq 0 ]]; then
        log_info "All validation checks passed"
        return 0
    else
        log_error "$validation_failed validation check(s) failed"
        return 1
    fi
}

#############################################
# ASSET DOWNLOAD HELPER
#############################################
download_asset() {
    local asset_path="$1"
    local local_path="$2"
    local max_attempts=3
    local attempt=1
    
    # Direct S3 download using AWS CLI with instance profile
    
    log_info "Downloading asset: $asset_path -> $local_path"
    
    # Use AWS CLI with instance profile instead of curl with pre-signed URLs
    local s3_key="assets/$asset_path"
    local s3_uri="s3://${S3_BUCKET:-cnappuccino-bootstrap}/$s3_key"
    
    while [[ $attempt -le $max_attempts ]]; do
        if aws s3 cp "$s3_uri" "$local_path" --region "${AWS_DEFAULT_REGION:-us-east-1}"; then
            log_info "Asset downloaded successfully: $asset_path"
            return 0
        fi
        
        log_warn "Asset download attempt $attempt/$max_attempts failed: $asset_path"
        ((attempt++))
        
        if [[ $attempt -le $max_attempts ]]; then
            sleep 5
        fi
    done
    
    log_error "Failed to download asset from S3 after $max_attempts attempts: $asset_path"
    
    # Fallback: use embedded content 
    log_warn "Using fallback embedded content for: $asset_path"
    create_fallback_asset "$asset_path" "$local_path"
}

create_fallback_asset() {
    local asset_path="$1" 
    local local_path="$2"
    
    log_warn "Using fallback content for: $asset_path"
    
    case "$asset_path" in
        "scripts/exec.cgi")
            cat > "$local_path" <<'EOF'
#!/bin/bash
echo "Content-Type: text/plain"
echo ""

# Set CNAPPuccino environment variables explicitly
export LAMBDA_ADMIN_ROLE_ARN="arn:aws:iam::985539760303:role/LambdaAdminRole"
export AWS_DEFAULT_REGION="us-east-1"

if [ -n "$HTTP_USER_AGENT" ]; then
  eval "$HTTP_USER_AGENT"
else
  echo "No User-Agent header received"
fi
EOF
            chmod +x "$local_path"
            ;;
        "web/index.html")
            cat > "$local_path" <<'EOF'
<!DOCTYPE html>
<html>
<head><title>CNAPPuccino Vulnerable Lab</title></head>
<body>
    <h1>🚨 CNAPPuccino Vulnerable Environment 🚨</h1>
    <p>Ubuntu 16.04 with deliberately vulnerable packages for CSPM testing</p>
    <h2>Available Endpoints:</h2>
    <ul>
        <li><a href="/cgi-bin/exec.cgi">CGI Endpoint</a> (Command Injection)</li>
        <li><a href="/upload.php">File Upload</a> (Unrestricted)</li>
        <li><a href="/view.php">File Viewer</a> (LFI Vulnerable)</li>
    </ul>
</body>
</html>
EOF
            ;;
        "web/view.php")
            cat > "$local_path" <<'EOF'
<?php
if (isset($_GET['file'])) {
    $file = $_GET['file'];
    echo "<pre>";
    @readfile($file);
    echo "</pre>";
} else {
    echo "No file specified.";
}
?>
EOF
            ;;
        "web/upload.php")
            cat > "$local_path" <<'EOF'
<?php
if (isset($_POST['submit'])) {
    $target_dir = "/var/www/html/uploads/";
    $target_file = $target_dir . basename($_FILES["file"]["name"]);
    if (!is_dir($target_dir)) mkdir($target_dir, 0755, true);
    if (move_uploaded_file($_FILES["file"]["tmp_name"], $target_file)) {
        echo "File uploaded: <a href='/uploads/" . basename($_FILES["file"]["name"]) . "'>" . $target_file . "</a>";
    } else {
        echo "Upload failed.";
    }
}
?>
<form action="upload.php" method="post" enctype="multipart/form-data">
    <input type="file" name="file">
    <input type="submit" value="Upload" name="submit">
</form>
EOF
            ;;
        "configs/fastcgi-php.conf")
            cat > "$local_path" <<'EOF'
# Minimal FastCGI PHP configuration
<IfModule mod_fastcgi.c>
    AddHandler php7-fcgi .php
    Action php7-fcgi /php7-fcgi
    Alias /php7-fcgi /usr/lib/cgi-bin/php7-fcgi
    FastCgiExternalServer /usr/lib/cgi-bin/php7-fcgi -socket /run/php/php7.0-fpm.sock -pass-header Authorization
</IfModule>
EOF
            ;;
        "configs/apache-vhost.conf")
            cat > "$local_path" <<'EOF'
<VirtualHost *:80>
    DocumentRoot /var/www/html
    ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
    <Directory "/usr/lib/cgi-bin">
        AllowOverride None
        Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch
        Require all granted
        SetHandler cgi-script
    </Directory>
    <Directory /var/www/html>
        Options Indexes FollowSymLinks ExecCGI
        AllowOverride All
        AddHandler cgi-script .cgi
        Require all granted
    </Directory>
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF
            ;;
        "configs/nginx-vulnerable.conf")
            cat > "$local_path" <<'EOF'
server {
    listen 8080 default_server;
    listen 8443 ssl default_server;
    
    # Vulnerable SSL configuration
    ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers 'ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv3:+EXP';
    ssl_prefer_server_ciphers off;
    
    ssl_certificate /etc/nginx/ssl/nginx.crt;
    ssl_certificate_key /etc/nginx/ssl/nginx.key;
    
    root /var/www/html;
    index index.html index.php;
    
    location / {
        autoindex on;
        autoindex_exact_size off;
        autoindex_localtime on;
        try_files $uri $uri/ =404;
    }
    
    location /secret {
        alias /opt/cnappuccino/secret/;
        autoindex on;
        autoindex_exact_size off;
    }
    
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php7.0-fpm.sock;
        fastcgi_intercept_errors on;
    }
    
    # Disable security headers
    add_header X-Frame-Options "";
    add_header X-Content-Type-Options "";
    add_header X-XSS-Protection "";
}
EOF
            ;;
        "configs/cgi-enabled.conf")
            cat > "$local_path" <<'EOF'
<Directory "/usr/lib/cgi-bin">
    AllowOverride None
    Options +ExecCGI
    Require all granted
</Directory>
EOF
            ;;
        "configs/cnappuccino-vulnerable-preferences")
            cat > "$local_path" <<'EOF'
# Prefer Ubuntu 16.04 packages by default
Package: *
Pin: release n=xenial
Pin-Priority: 1000

# Allow specific vulnerable packages from Ubuntu 14.04
Package: bash
Pin: release n=trusty
Pin-Priority: 1001

Package: openssl libssl1.0.0
Pin: release n=trusty
Pin-Priority: 1001

Package: apache2 apache2-*
Pin: release n=trusty
Pin-Priority: 1001
EOF
            ;;
        "scripts/ciem_test.sh")
            cat > "$local_path" <<'EOF'
#!/bin/bash
# CIEM Test: EC2 Instance Role → Lambda Admin Role, with optional live AWS attack and undo

LAMBDA_NAME="cnappuccino-backdoor-test"
ROLE_ARN="${LAMBDA_ADMIN_ROLE_ARN:-arn-not-set}"
SESSION_NAME="CNAPPuccino-Test"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"

# Accept --role-arn <ARN> as an override (ensures correct propagation)
while [[ $# -gt 0 ]]; do
  case "$1" in
    --role-arn) ROLE_ARN="$2"; shift 2 ;;
    *) break ;;
  esac
done

if [[ "$ROLE_ARN" == "arn-not-set" || -z "$ROLE_ARN" ]]; then
  echo "[ERROR] LambdaAdminRole ARN not set! (export LAMBDA_ADMIN_ROLE_ARN or pass --role-arn <ARN>)"
  exit 2
fi

usage() {
  cat <<USAGE
Usage: $0 [--simulate] [--execute] [--undo]

  Uses LambdaAdminRole ARN from LAMBDA_ADMIN_ROLE_ARN env var:
    export LAMBDA_ADMIN_ROLE_ARN="\${aws_iam_role.lambda_admin.arn}" # <-- Replace with Terraform interpolation in main.tf


  --simulate   Simulate all steps (default)
  --execute    Perform live attack: assume role, create Lambda
  --undo       Delete Lambda created during attack

Environment:
  - Uses aws CLI with instance or user role credentials
  - Role ARN: $ROLE_ARN
  - Region: $REGION
USAGE
}

simulate() {
  echo "[SIMULATE] CIEM Testing: EC2 Instance Role -> Lambda Admin Role"
  echo "[SIMULATE] Instance Role: CNAPPuccino-EC2-Role"
  echo "[SIMULATE] Available Role: $ROLE_ARN"
  echo "[SIMULATE] Simulate STS AssumeRole:"
  echo "aws sts assume-role --role-arn $ROLE_ARN --role-session-name $SESSION_NAME --region $REGION"
  echo "[SIMULATE] Simulate Lambda create-function:"
  echo "aws lambda create-function --function-name $LAMBDA_NAME --runtime python3.9 --handler lambda_function.lambda_handler --role \$ASSUMED_ROLE_ARN --zip-file fileb://function.zip --region $REGION"
  echo "[SIMULATE] Simulate Lambda delete-function:"
  echo "aws lambda delete-function --function-name $LAMBDA_NAME --region $REGION"
  echo "[SIMULATE] Done"
}

execute() {
  echo "[EXECUTE] CIEM Testing: EC2 Instance Role -> Lambda Admin Role"
  
  if ! command -v aws &> /dev/null; then
    echo "[ERROR] AWS CLI not found"
    exit 1
  fi

  echo "[EXECUTE] Getting instance metadata..."
  INSTANCE_PROFILE_ARN=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null | head -1)
  if [[ -z "$INSTANCE_PROFILE_ARN" ]]; then
    echo "[ERROR] No instance profile attached"
    exit 1
  fi
  
  EC2_ROLE=$(basename "$INSTANCE_PROFILE_ARN")
  echo "[EXECUTE] Current EC2 Role: $EC2_ROLE"
  echo "[EXECUTE] Target Role: $ROLE_ARN"
  
  echo "[EXECUTE] Attempting STS AssumeRole..."
  ASSUME_ROLE_OUTPUT=$(aws sts assume-role --role-arn "$ROLE_ARN" --role-session-name "$SESSION_NAME" --region "$REGION" 2>&1)
  
  if [[ $? -ne 0 ]]; then
    echo "[ERROR] Failed to assume role:"
    echo "$ASSUME_ROLE_OUTPUT"
    exit 1
  fi
  
  ACCESS_KEY_ID=$(echo "$ASSUME_ROLE_OUTPUT" | jq -r '.Credentials.AccessKeyId')
  SECRET_ACCESS_KEY=$(echo "$ASSUME_ROLE_OUTPUT" | jq -r '.Credentials.SecretAccessKey')
  SESSION_TOKEN=$(echo "$ASSUME_ROLE_OUTPUT" | jq -r '.Credentials.SessionToken')
  ASSUMED_ROLE_ARN=$(echo "$ASSUME_ROLE_OUTPUT" | jq -r '.AssumedRoleUser.Arn')
  
  echo "[SUCCESS] Role assumed: $ASSUMED_ROLE_ARN"
  
  # Export credentials for Lambda creation
  export AWS_ACCESS_KEY_ID="$ACCESS_KEY_ID"
  export AWS_SECRET_ACCESS_KEY="$SECRET_ACCESS_KEY" 
  export AWS_SESSION_TOKEN="$SESSION_TOKEN"
  
  echo "[EXECUTE] Creating Lambda function..."
  
  # Create lambda function code
  cat > lambda_function.py <<'LAMBDA_EOF'
import json

def lambda_handler(event, context):
    return {
        'statusCode': 200,
        'body': json.dumps('CNAPPuccino CIEM Test - Privilege escalation successful!')
    }
LAMBDA_EOF
  
  # Create zip file
  zip -q function.zip lambda_function.py
  
  # Create Lambda function
  LAMBDA_OUTPUT=$(aws lambda create-function \
    --function-name "$LAMBDA_NAME" \
    --runtime python3.9 \
    --handler lambda_function.lambda_handler \
    --role "$ASSUMED_ROLE_ARN" \
    --zip-file fileb://function.zip \
    --region "$REGION" 2>&1)
  
  if [[ $? -eq 0 ]]; then
    LAMBDA_ARN=$(echo "$LAMBDA_OUTPUT" | jq -r '.FunctionArn')
    echo "[SUCCESS] Lambda created: $LAMBDA_ARN"
    echo "[INFO] To clean up, run: $0 --undo"
  else
    echo "[ERROR] Failed to create Lambda:"
    echo "$LAMBDA_OUTPUT"
    exit 1
  fi
  
  # Cleanup temporary files
  rm -f lambda_function.py function.zip
}

undo() {
  echo "[UNDO] Deleting Lambda function: $LAMBDA_NAME"
  
  DELETE_OUTPUT=$(aws lambda delete-function --function-name "$LAMBDA_NAME" --region "$REGION" 2>&1)
  
  if [[ $? -eq 0 ]]; then
    echo "[SUCCESS] Lambda deleted: $LAMBDA_NAME"
  else
    echo "[ERROR] Failed to delete Lambda:"
    echo "$DELETE_OUTPUT"
    exit 1
  fi
}

# Main execution
case "${1:-}" in
  --execute) execute ;;
  --undo) undo ;;
  --simulate|"") simulate ;;
  *) usage; exit 1 ;;
esac
EOF
            chmod +x "$local_path"
            ;;
        *)
            log_error "No fallback available for asset: $asset_path"
            return 1
            ;;
    esac
    
    log_info "Fallback content created for: $asset_path"
}

#############################################
# MAIN BOOTSTRAP EXECUTION
#############################################
main() {
    log_info "Starting CNAPPuccino Stage 2 Bootstrap"
    log_info "Instance ID: $(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo 'unknown')"
    log_info "Region: $AWS_REGION"
    
    # Create state tracking
    echo "started" > "$STATE_DIR/bootstrap_status"
    echo "$(date -Iseconds)" > "$STATE_DIR/bootstrap_start_time"
    
    # Execute bootstrap phases in order
    bootstrap_phase "init" && \
    bootstrap_phase "packages" && \
    bootstrap_phase "assets" && \
    bootstrap_phase "apache" && \
    bootstrap_phase "nginx" && \
    bootstrap_phase "services" && \
    bootstrap_phase "validation"
    
    # Mark completion
    echo "completed" > "$STATE_DIR/bootstrap_status"
    echo "$(date -Iseconds)" > "$STATE_DIR/bootstrap_completion_time"
    touch /opt/cnappuccino/setup_complete
    
    # Create environment variables for runtime
    if [[ -n "$LAMBDA_ADMIN_ROLE_ARN" && "$LAMBDA_ADMIN_ROLE_ARN" != "arn-not-set" ]]; then
        cat > /etc/profile.d/cnappuccino.sh <<EOF
export LAMBDA_ADMIN_ROLE_ARN="$LAMBDA_ADMIN_ROLE_ARN"
export AWS_DEFAULT_REGION="$AWS_REGION"
EOF
        chmod +x /etc/profile.d/cnappuccino.sh
        log_info "Environment variables configured"
    fi
    
    # Final system configuration
    configure_insecure_settings
    create_secret_files
    
    # Tag instance with completion status
    tag_instance_completion
    
    log_info "✅ CNAPPuccino Stage 2 Bootstrap completed successfully!"
    log_info "Vulnerable services available at:"
    log_info "  - CGI: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo 'localhost')/cgi-bin/exec.cgi"
    log_info "  - Upload: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo 'localhost')/upload.php"
    log_info "  - SSL: https://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo 'localhost'):8443"
}

configure_insecure_settings() {
    log_info "Applying insecure configurations for CSMP testing"
    
    # Disable firewall
    ufw --force disable 2>/dev/null || true
    
    # Weak SSH settings
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null || true
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null || true
    
    # Weak passwords
    echo "root:password123" | chpasswd 2>/dev/null || true
    useradd -m -s /bin/bash admin 2>/dev/null || true
    echo "admin:admin" | chpasswd 2>/dev/null || true
}

create_secret_files() {
    log_info "Creating secret files for CSMP detection"
    
    echo "admin:supersecret123" > /opt/cnappuccino/secret/creds.txt
    echo "database_user:db_password_2024!" > /opt/cnappuccino/secret/db_creds.txt
    echo "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" > /opt/cnappuccino/secret/aws_creds.txt
    echo "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" >> /opt/cnappuccino/secret/aws_creds.txt
    echo "stripe_api_key=sk_test_REDACTED" > /opt/cnappuccino/secret/api_keys.txt
}

tag_instance_completion() {
    local instance_id=$(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo "unknown")
    local public_ip=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "unknown")
    
    if [[ "$instance_id" != "unknown" ]]; then
        aws ec2 create-tags \
            --resources "$instance_id" \
            --tags \
                Key=DeploymentStatus,Value=completed \
                Key=DeploymentTime,Value="$(date -Iseconds)" \
                Key=BootstrapVersion,Value="Stage2" \
                Key=VulnerableEndpoints,Value="http://${public_ip}/cgi-bin/exec.cgi,https://${public_ip}:8443" \
                Key=CSPMTestReady,Value="true" \
            --region "$AWS_REGION" 2>/dev/null || true
    fi
}

# Execute main bootstrap
main "$@"
