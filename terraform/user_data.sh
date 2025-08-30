#!/usr/bin/env bash
# CNAPPuccino Stage 2 Bootstrap - Reliable and Debuggable
# Architecture: Staged bootstrap with error handling, structured logging, and idempotent operations
# Downloads assets from GitHub raw URLs for maximum reliability and no AWS dependencies

# Note: Removed 'set -euo pipefail' to allow graceful error handling within phases
# Individual phases handle their own errors and continue execution

#############################################
# BOOTSTRAP CONFIGURATION
#############################################
readonly BOOTSTRAP_LOG="/var/log/cnappuccino-bootstrap.log"
readonly STATE_DIR="/opt/cnappuccino/state"
readonly TEMP_DIR="/tmp/cnappuccino-setup"
readonly AWS_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
readonly LAMBDA_ADMIN_ROLE_ARN="${LAMBDA_ADMIN_ROLE_ARN:-arn-not-set}"
readonly GITHUB_RAW_BASE="https://raw.githubusercontent.com/adilio/CNAPPuccino/main/terraform/assets"

# CRITICAL: Create required directories FIRST before any other operations
# This must happen before logging setup to prevent silent failures
mkdir -p "$STATE_DIR" "$TEMP_DIR" /run/lock/apache2 /var/lock/apache2 2>/dev/null || {
    echo "CRITICAL: Failed to create required directories" >&2
    exit 1
}

# Set permissions on directories
chmod 755 "$TEMP_DIR" 2>/dev/null || true
chmod 755 "$STATE_DIR" 2>/dev/null || true
chmod 755 /run/lock/apache2 2>/dev/null || true
chmod 755 /var/lock/apache2 2>/dev/null || true
ln -sf /run/lock /var/lock 2>/dev/null || true

#############################################
# ASSET DOWNLOAD FUNCTIONS
#############################################

# Download asset from GitHub with retry logic
download_asset() {
    local asset_path="$1"
    local local_path="$2"
    local url="${GITHUB_RAW_BASE}/${asset_path}"
    local max_retries=3
    local retry=0

    log_info "Downloading asset: $asset_path -> $local_path"

    # Create parent directory if it doesn't exist
    mkdir -p "$(dirname "$local_path")"

    while [[ $retry -lt $max_retries ]]; do
        if curl -fsSL --connect-timeout 30 --max-time 60 "$url" -o "$local_path"; then
            log_info "✅ Asset downloaded successfully: $asset_path"
            return 0
        else
            retry=$((retry + 1))
            log_warn "⚠️ Download attempt $retry failed for: $asset_path"
            [[ $retry -lt $max_retries ]] && sleep $((retry * 2))
        fi
    done

    log_error "❌ Failed to download asset after $max_retries attempts: $asset_path"
    return 1
}

#############################################
# LOGGING FUNCTIONS
#############################################

# Create main log file with appropriate permissions
touch "$BOOTSTRAP_LOG" 2>/dev/null || {
    echo "CRITICAL: Cannot create bootstrap log file at $BOOTSTRAP_LOG" >&2
    exit 1
}
chmod 644 "$BOOTSTRAP_LOG" 2>/dev/null || {
    echo "CRITICAL: Cannot set permissions on bootstrap log file" >&2
    exit 1
}

# Log with context and structured output
log_with_context() {
    local level="$1"
    local phase="$2"
    local message="$3"
    local timestamp=$(date -Iseconds)

    echo "[$timestamp] [$level] [PHASE:$phase] $message"
    echo "[$timestamp] [$level] [PHASE:$phase] $message" >> "$BOOTSTRAP_LOG" 2>/dev/null || true
}

log_info() { log_with_context "INFO" "${BOOTSTRAP_PHASE:-INIT}" "$1"; }
log_warn() { log_with_context "WARN" "${BOOTSTRAP_PHASE:-INIT}" "$1"; }
log_error() { log_with_context "ERROR" "${BOOTSTRAP_PHASE:-INIT}" "$1"; }
log_debug() { log_with_context "DEBUG" "${BOOTSTRAP_PHASE:-INIT}" "$1"; }

#############################################
# ERROR HANDLING
#############################################

rollback_on_failure() {
    local exit_code=$?
    local error_phase="${BOOTSTRAP_PHASE:-UNKNOWN}"

    log_error "❌ Bootstrap failed in phase: $error_phase (exit code: $exit_code)"
    log_error "💀 Error occurred at line $(caller)"

    # Create failure state files
    echo "failed" > "$STATE_DIR/bootstrap_status" 2>/dev/null || true
    echo "$error_phase" > "$STATE_DIR/failed_phase" 2>/dev/null || true
    echo "$(date -Iseconds)" > "$STATE_DIR/bootstrap_fail_time" 2>/dev/null || true

    # Log diagnostic information
    log_error "========== BOOTSTRAP FAILURE DIAGNOSTICS =========="
    log_error "Phase: $error_phase"
    log_error "Working Directory: $(pwd)"
    log_error "Disk Space: $(df -h / | tail -1)"
    log_error "Memory Usage: $(free -h | head -2 | tail -1)"
    log_error "Network Status: $(ip route get 8.8.8.8 2>/dev/null | head -1 || echo 'Network unreachable')"
    log_error "AWS CLI Status: $(which aws 2>/dev/null && aws --version 2>/dev/null || echo 'AWS CLI not available')"
    log_error "Recent System Log: $(tail -5 /var/log/syslog 2>/dev/null || echo 'Syslog not accessible')"
    log_error "=================================================="

    # Cleanup
    log_info "🧹 Cleaning up temporary files..."
    rm -rf "$TEMP_DIR" 2>/dev/null || true

    # Allow further troubleshooting - don't exit immediately
    log_error "Bootstrap failed but instance remains accessible for troubleshooting"
    log_error "Check logs: tail -f $BOOTSTRAP_LOG"

    exit $exit_code
}

# Set trap for error handling (only for critical errors)
trap rollback_on_failure ERR

# Now that error handling is set up, redirect output to log file
exec > >(tee -a "$BOOTSTRAP_LOG") 2>&1

#############################################
# HELPER FUNCTIONS
#############################################

check_package_installed() {
    dpkg -l "$1" >/dev/null 2>&1
}

install_package_idempotent() {
    local package="$1"
    local apt_update_done="${2:-false}"
    
    if ! check_package_installed "$package"; then
        log_info "Installing package: $package"
        
        # Update package list if not already done
        if [[ "$apt_update_done" != "true" ]]; then
            apt-get update -qq || true
            apt_update_done="true"
        fi
        
        # Try to install with timeout to prevent hanging
        timeout 300 apt-get install -yq "$package" || {
            log_warn "Package installation timed out or failed: $package"
            return 1
        }
        
        # Verify installation
        if check_package_installed "$package"; then
            log_info "✅ Package installed: $package"
            return 0
        else
            log_warn "Package installation verification failed: $package"
            return 1
        fi
    else
        log_info "📦 Package already installed: $package"
        return 0
    fi
}

check_service_active() {
    local service_name="$1"
    systemctl is-active --quiet "$service_name" 2>/dev/null
}

ensure_service_running() {
    local service_name="$1"
    local max_attempts=5
    local attempt=0
    
    while [[ $attempt -lt $max_attempts ]]; do
        if check_service_active "$service_name"; then
            log_info "✅ Service is running: $service_name"
            return 0
        fi
        
        attempt=$((attempt + 1))
        log_info "🔄 Starting service (attempt $attempt/$max_attempts): $service_name"
        
        systemctl enable "$service_name" 2>/dev/null || true
        systemctl start "$service_name" 2>/dev/null || true
        
        sleep $((attempt * 2))
    done
    
    log_error "❌ Failed to start service after $max_attempts attempts: $service_name"
    systemctl status "$service_name" --no-pager || true
    return 1
}

#############################################
# BOOTSTRAP PHASES
#############################################

bootstrap_phase() {
    local phase_name="$1"
    local phase_function="$2"

    export BOOTSTRAP_PHASE="$phase_name"
    log_info "🚀 Starting phase: $phase_name"

    # Create phase tracking
    echo "$phase_name" > "$STATE_DIR/current_phase" 2>/dev/null || true
    echo "$(date -Iseconds)" > "$STATE_DIR/${phase_name}_start_time" 2>/dev/null || true

    # Execute phase function with error handling
    if "$phase_function" 2>&1; then
        echo "$(date -Iseconds)" > "$STATE_DIR/${phase_name}_complete_time" 2>/dev/null || true
        log_info "✅ Phase completed successfully: $phase_name"
        return 0
    else
        local exit_code=$?
        log_error "❌ Phase failed: $phase_name (exit code: $exit_code)"
        echo "$(date -Iseconds)" > "$STATE_DIR/${phase_name}_failed_time" 2>/dev/null || true
        return 1
    fi
}

bootstrap_phase_init() {
    log_info "Initializing CNAPPuccino bootstrap environment"
    
    # Download vulnerable packages preferences
    download_asset "configs/cnappuccino-vulnerable-preferences" "/etc/apt/preferences.d/cnappuccino-vulnerable"
    
    # Update package repositories
    log_info "📦 Updating package repositories..."
    apt-get update -qq
    
    log_info "✅ Initialization complete"
}

bootstrap_phase_packages() {
    log_info "Installing essential packages..."

    # Set non-interactive mode to prevent hanging
    export DEBIAN_FRONTEND=noninteractive

    # Update package list first
    log_info "📦 Updating package repositories..."
    apt-get update -qq || log_warn "⚠️ apt-get update failed, continuing..."

    # Install essential packages only - others can be installed as needed
    local essential_packages=(
        "curl" "wget" "apache2" "nginx"
    )

    for package in "${essential_packages[@]}"; do
        log_info "Installing $package..."
        if ! install_package_idempotent "$package" "true"; then
            log_warn "⚠️ Failed to install $package, continuing..."
        fi
    done

    # Try to install PHP if available
    log_info "Installing PHP..."
    if ! install_package_idempotent "php" "true"; then
        log_warn "⚠️ PHP installation failed, continuing without PHP..."
    fi

    # Try to install PHP Apache module if available
    if check_package_installed "php"; then
        if ! install_package_idempotent "libapache2-mod-php" "true"; then
            log_warn "⚠️ PHP Apache module installation failed, continuing..."
        fi
    fi

    log_info "✅ Essential package installation complete"
}

bootstrap_phase_assets() {
    log_info "Downloading and installing vulnerable assets..."

    # Create directories first
    mkdir -p /opt/cnappuccino/exploits /usr/lib/cgi-bin /var/www/html 2>/dev/null || true

    # Scripts (executable) - try to download but don't fail if unavailable
    if download_asset "scripts/exec.cgi" "/usr/lib/cgi-bin/exec.cgi"; then
        chmod +x /usr/lib/cgi-bin/exec.cgi 2>/dev/null || log_warn "⚠️ Could not set exec.cgi permissions"
    else
        log_warn "⚠️ Could not download exec.cgi, creating basic version..."
        echo '#!/bin/bash' > /usr/lib/cgi-bin/exec.cgi
        echo 'echo "Content-type: text/plain"' >> /usr/lib/cgi-bin/exec.cgi
        echo 'echo ""' >> /usr/lib/cgi-bin/exec.cgi
        echo 'echo "CNAPPuccino CGI Endpoint - Basic Version"' >> /usr/lib/cgi-bin/exec.cgi
        chmod +x /usr/lib/cgi-bin/exec.cgi 2>/dev/null || true
    fi

    # Try to download other scripts but don't fail
    download_asset "scripts/ciem_test.sh" "/opt/cnappuccino/exploits/ciem_test.sh" || log_warn "⚠️ Could not download ciem_test.sh"
    download_asset "scripts/command_injection_test.sh" "/opt/cnappuccino/exploits/command_injection_test.sh" || log_warn "⚠️ Could not download command_injection_test.sh"
    download_asset "scripts/webshell.php" "/opt/cnappuccino/exploits/webshell.php" || log_warn "⚠️ Could not download webshell.php"

    # Web content - try to download but don't fail
    download_asset "web/view.php" "/var/www/html/view.php" || log_warn "⚠️ Could not download view.php"
    download_asset "web/upload.php" "/var/www/html/upload.php" || log_warn "⚠️ Could not download upload.php"
    download_asset "web/index.html" "/var/www/html/index.html" || log_warn "⚠️ Could not download index.html"

    # Configuration files - try to download but don't fail
    download_asset "configs/fastcgi-php.conf" "/etc/apache2/snippets/fastcgi-php.conf" || log_warn "⚠️ Could not download fastcgi-php.conf"
    download_asset "configs/apache-vhost.conf" "/etc/apache2/sites-available/000-default.conf" || log_warn "⚠️ Could not download apache-vhost.conf"
    download_asset "configs/nginx-vulnerable.conf" "/etc/nginx/sites-available/cnappuccino" || log_warn "⚠️ Could not download nginx-vulnerable.conf"
    download_asset "configs/cgi-enabled.conf" "/etc/apache2/conf-enabled/cgi-enabled.conf" || log_warn "⚠️ Could not download cgi-enabled.conf"

    # Set proper permissions
    chmod +x /opt/cnappuccino/exploits/*.sh 2>/dev/null || true
    chown -R www-data:www-data /var/www/html/ 2>/dev/null || true

    log_info "✅ Asset installation complete (with fallbacks for missing files)"
}

bootstrap_phase_apache() {
    log_info "Configuring Apache with vulnerable settings..."

    if ! check_package_installed "apache2"; then
        log_warn "⚠️ Apache2 not installed, skipping Apache configuration..."
        return 0
    fi

    # Enable necessary modules (only if they exist)
    a2enmod cgi 2>/dev/null || log_warn "⚠️ CGI module not available"
    a2enmod rewrite 2>/dev/null || log_warn "⚠️ Rewrite module not available"
    a2enmod ssl 2>/dev/null || log_warn "⚠️ SSL module not available"

    # Disable conflicting CGI configuration that lacks SetHandler directive
    a2disconf serve-cgi-bin 2>/dev/null || log_warn "⚠️ serve-cgi-bin not enabled"

    # Enable the vulnerable site
    a2ensite 000-default 2>/dev/null || log_warn "⚠️ Could not enable 000-default site"
    a2dissite default-ssl 2>/dev/null || true

    # Test configuration
    if apache2ctl configtest 2>/dev/null; then
        log_info "✅ Apache configuration is valid"
    else
        log_warn "⚠️ Apache configuration has issues, but continuing..."
    fi

    # Restart Apache to apply all configuration changes (required for CGI to work)
    systemctl restart apache2 2>/dev/null || log_warn "⚠️ Could not restart Apache"

    log_info "✅ Apache configuration complete"
}

bootstrap_phase_nginx() {
    log_info "Configuring Nginx with vulnerable settings..."

    if ! check_package_installed "nginx"; then
        log_warn "⚠️ Nginx not installed, skipping Nginx configuration..."
        return 0
    fi

    # Enable the vulnerable site
    if [[ -f /etc/nginx/sites-available/cnappuccino ]]; then
        ln -sf /etc/nginx/sites-available/cnappuccino /etc/nginx/sites-enabled/cnappuccino 2>/dev/null || log_warn "⚠️ Could not enable cnappuccino site"
        rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
    else
        log_warn "⚠️ Nginx cnappuccino config not found, skipping site enablement..."
    fi

    # Create required directories
    mkdir -p /var/www/html/secret /var/www/html/uploads 2>/dev/null || log_warn "⚠️ Could not create web directories"
    echo "🔒 Secret data for testing" > /var/www/html/secret/confidential.txt 2>/dev/null || log_warn "⚠️ Could not create secret file"

    # Set permissions
    chown -R www-data:www-data /var/www/html/ 2>/dev/null || log_warn "⚠️ Could not set web directory ownership"
    chmod 755 /var/www/html/secret 2>/dev/null || true
    chmod 644 /var/www/html/secret/confidential.txt 2>/dev/null || true

    # Test configuration
    if nginx -t 2>/dev/null; then
        log_info "✅ Nginx configuration is valid"
    else
        log_warn "⚠️ Nginx configuration has issues, but continuing..."
    fi

    log_info "✅ Nginx configuration complete"
}

bootstrap_phase_services() {
    log_info "Starting and configuring services..."

    # Start services with retry logic - only start what's available
    if check_package_installed "apache2"; then
        ensure_service_running "apache2"
    else
        log_warn "⚠️ Apache2 not installed, skipping..."
    fi

    if check_package_installed "nginx"; then
        ensure_service_running "nginx"
    else
        log_warn "⚠️ Nginx not installed, skipping..."
    fi

    if check_package_installed "mysql-server" || check_package_installed "mysql-community-server"; then
        ensure_service_running "mysql"
    else
        log_warn "⚠️ MySQL not installed, skipping..."
    fi

    if check_package_installed "php7.0-fpm" || check_package_installed "php-fpm"; then
        ensure_service_running "php7.0-fpm" || ensure_service_running "php-fpm"
    else
        log_warn "⚠️ PHP-FPM not installed, skipping..."
    fi

    log_info "✅ Available services started successfully"
}

bootstrap_phase_validation() {
    log_info "Validating bootstrap completion..."
    
    # Test web services
    local apache_status=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ || echo "000")
    local nginx_status=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/ || echo "000")
    
    if [[ "$apache_status" == "200" ]]; then
        log_info "✅ Apache is responding correctly"
    else
        log_warn "⚠️ Apache returned status: $apache_status"
    fi
    
    if [[ "$nginx_status" == "200" ]]; then
        log_info "✅ Nginx is responding correctly"
    else
        log_warn "⚠️ Nginx returned status: $nginx_status"
    fi
    
    # Test CGI execution
    local cgi_test=$(curl -s -H "User-Agent: test" http://localhost/cgi-bin/exec.cgi | head -1 || echo "")
    if [[ -n "$cgi_test" ]]; then
        log_info "✅ CGI execution is working"
    else
        log_warn "⚠️ CGI execution may not be working properly"
    fi
    
    log_info "✅ Bootstrap validation complete"
}

#############################################
# MAIN BOOTSTRAP EXECUTION
#############################################
main() {
    log_info "Starting CNAPPuccino Stage 2 Bootstrap"
    log_info "Instance ID: $(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo 'unknown')"
    log_info "Region: $AWS_REGION"

    # Create state tracking
    echo "started" > "$STATE_DIR/bootstrap_status" 2>/dev/null || true
    echo "$(date -Iseconds)" > "$STATE_DIR/bootstrap_start_time" 2>/dev/null || true

    # Execute bootstrap phases with individual error handling
    log_info "🚀 Executing bootstrap phases..."

    if bootstrap_phase "INIT" bootstrap_phase_init; then
        log_info "✅ INIT phase completed"
    else
        log_error "❌ INIT phase failed, but continuing..."
    fi

    if bootstrap_phase "PACKAGES" bootstrap_phase_packages; then
        log_info "✅ PACKAGES phase completed"
    else
        log_error "❌ PACKAGES phase failed, but continuing..."
    fi

    if bootstrap_phase "ASSETS" bootstrap_phase_assets; then
        log_info "✅ ASSETS phase completed"
    else
        log_error "❌ ASSETS phase failed, but continuing..."
    fi

    if bootstrap_phase "APACHE" bootstrap_phase_apache; then
        log_info "✅ APACHE phase completed"
    else
        log_error "❌ APACHE phase failed, but continuing..."
    fi

    if bootstrap_phase "NGINX" bootstrap_phase_nginx; then
        log_info "✅ NGINX phase completed"
    else
        log_error "❌ NGINX phase failed, but continuing..."
    fi

    if bootstrap_phase "SERVICES" bootstrap_phase_services; then
        log_info "✅ SERVICES phase completed"
    else
        log_error "❌ SERVICES phase failed, but continuing..."
    fi

    if bootstrap_phase "VALIDATION" bootstrap_phase_validation; then
        log_info "✅ VALIDATION phase completed"
    else
        log_error "❌ VALIDATION phase failed, but continuing..."
    fi

    # Try to configure insecure settings
    configure_insecure_settings 2>/dev/null || log_warn "⚠️ Insecure settings configuration failed"

    # Try to create secret files
    create_secret_files 2>/dev/null || log_warn "⚠️ Secret files creation failed"

    # Try to tag instance
    tag_instance_completion 2>/dev/null || log_warn "⚠️ Instance tagging failed"

    # Mark as complete
    echo "completed" > "$STATE_DIR/bootstrap_status" 2>/dev/null || true
    echo "$(date -Iseconds)" > "$STATE_DIR/bootstrap_complete_time" 2>/dev/null || true

    log_info "🎉 CNAPPuccino bootstrap completed successfully!"
    log_info "📊 Check status: tail -f $BOOTSTRAP_LOG"
}

configure_insecure_settings() {
    log_info "Configuring intentionally insecure settings..."
    
    # Disable UFW firewall
    ufw --force disable 2>/dev/null || true
    
    # Enable password authentication for SSH (weak passwords)
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
    systemctl restart ssh
    
    # Create weak user accounts
    useradd -m -s /bin/bash admin 2>/dev/null || true
    echo "admin:admin" | chpasswd
    
    log_info "✅ Insecure settings configured"
}

create_secret_files() {
    log_info "Creating secret files for testing..."
    
    # Create files with sensitive information for LFI testing
    echo "DB_PASSWORD=super_secret_password_123" > /var/www/html/.env
    echo "API_KEY=sk-1234567890abcdef" >> /var/www/html/.env
    chmod 644 /var/www/html/.env
    
    log_info "✅ Secret files created"
}

tag_instance_completion() {
    # Try to tag the instance as completed (requires IAM permissions)
    local instance_id=$(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo "")
    if [[ -n "$instance_id" ]]; then
        aws ec2 create-tags --region "$AWS_REGION" --resources "$instance_id" --tags Key=BootstrapStatus,Value=Complete 2>/dev/null || true
    fi
}

# Execute main function with early logging
echo "=== CNAPPuccino Bootstrap Starting ==="
echo "Script: $0"
echo "PID: $$"
echo "Working Directory: $(pwd)"
echo "User: $(whoami)"
echo "Date: $(date)"
echo "======================================"

# Execute main function
main