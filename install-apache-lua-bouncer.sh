#!/bin/bash

# Exit script on first error
set -e

# --- Configuration Variables ---
BOUNCER_NAME="apache-lua-bouncer" # Bouncer name in CrowdSec
CONFIG_DIR="/etc/crowdsec/bouncers"
CONFIG_FILE="$CONFIG_DIR/apache-bouncer.yaml"
LUA_SCRIPT_DIR="/usr/share/crowdsec-apache-bouncer"
LUA_SCRIPT_FILE="$LUA_SCRIPT_DIR/crowdsec_bouncer.lua"
LOG_FILE="/var/log/crowdsec-apache-bouncer.log"
YAML_TEMPLATE_FILE="apache-bouncer.yaml" # Assumes it's in the same dir as the script
LUA_SOURCE_FILE="crowdsec_bouncer.lua"  # Assumes it's in the same dir as the script
LICENSE_FILE="LICENSE" # Default license file name

# --- Utility Functions ---
log_info() {
    echo "[INFO] $1"
}

log_warn() {
    echo "[WARN] $1"
}

log_error() {
    echo "[ERROR] $1" >&2
    exit 1
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_error "Command '$1' not found. Please ensure it is installed and in PATH."
    fi
}

# --- Root Check ---
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root (or with sudo)."
fi

# --- Check Source Files ---
if [[ ! -f "$LUA_SOURCE_FILE" ]]; then
    log_error "Lua source file '$LUA_SOURCE_FILE' not found in the current directory."
fi
if [[ ! -f "$YAML_TEMPLATE_FILE" ]]; then
    log_error "YAML template file '$YAML_TEMPLATE_FILE' not found in the current directory."
fi
# Check if LICENSE file exists for copying later (optional but good practice)
if [[ ! -f "$LICENSE_FILE" ]]; then
    log_warn "'$LICENSE_FILE' file not found in the current directory. Skipping license copy."
    COPY_LICENSE=false
else
    COPY_LICENSE=true
fi


# --- OS Detection and Dependency Installation ---
APACHE_PKG=""
MOD_LUA_PKG=""
LUA_SOCKET_PKG=""
LUA_CJSON_PKG=""
LUA_YAML_PKG=""
LUAROCKS_PKG=""
APACHE_SERVICE=""
APACHE_USER=""
PKG_MANAGER=""
INSTALL_CMD=""
UPDATE_CMD=""
ENABLE_LUA_CMD=""

if [ -f /etc/debian_version ]; then
    log_info "Detected Debian/Ubuntu based system."
    PKG_MANAGER="apt-get"
    UPDATE_CMD="apt-get update"
    INSTALL_CMD="apt-get install -y"
    APACHE_PKG="apache2"
    MOD_LUA_PKG="libapache2-mod-lua"
    LUA_SOCKET_PKG="lua-socket"
    LUA_CJSON_PKG="lua-cjson"
    LUA_YAML_PKG="lua-yaml" # Might not exist, check below
    LUAROCKS_PKG="luarocks"
    APACHE_SERVICE="apache2"
    APACHE_USER="www-data"
    ENABLE_LUA_CMD="a2enmod lua"

elif [ -f /etc/redhat-release ]; then
    log_info "Detected RHEL/CentOS/Fedora based system."
    if command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
    else
        log_error "Could not detect package manager (dnf or yum)."
    fi
    INSTALL_CMD="$PKG_MANAGER install -y"
    APACHE_PKG="httpd"
    MOD_LUA_PKG="mod_lua"
    # Lua packages often depend on EPEL or other repos
    LUA_SOCKET_PKG="lua-socket"
    LUA_CJSON_PKG="lua-cjson"
    LUA_YAML_PKG="lua-yaml" # Might not exist, check below
    LUAROCKS_PKG="luarocks"
    APACHE_SERVICE="httpd"
    APACHE_USER="apache"
    # mod_lua is usually enabled by default when installed on RHEL-based systems
    ENABLE_LUA_CMD="echo 'Manually verify that the lua module is loaded in /etc/httpd/conf.modules.d/'"

else
    log_error "Unknown Linux distribution. Cannot proceed."
fi

log_info "Updating package list..."
$UPDATE_CMD > /dev/null || log_warn "Could not update package list."

log_info "Installing required dependencies..."
$INSTALL_CMD $APACHE_PKG $MOD_LUA_PKG $LUA_SOCKET_PKG $LUA_CJSON_PKG

# Try installing lua-yaml, if it fails, try with luarocks
log_info "Attempting to install system package for lua-yaml..."
if ! $INSTALL_CMD $LUA_YAML_PKG &> /dev/null; then
    log_warn "Package '$LUA_YAML_PKG' could not be installed via $PKG_MANAGER. Attempting with LuaRocks..."
    if ! command -v luarocks &> /dev/null; then
        log_info "Installing LuaRocks..."
        $INSTALL_CMD $LUAROCKS_PKG
        check_command "luarocks"
    fi
    log_info "Installing 'lyaml' using LuaRocks..."
    if ! luarocks install lyaml; then
         log_error "Could not install 'lyaml' using LuaRocks. Please check LuaRocks installation and internet connectivity manually."
    fi
    log_info "'lyaml' installed successfully via LuaRocks."
else
    log_info "'$LUA_YAML_PKG' installed successfully via $PKG_MANAGER."
fi


log_info "Enabling mod_lua (if necessary)..."
if [[ "$PKG_MANAGER" == "apt-get" ]]; then
    $ENABLE_LUA_CMD
else
    $ENABLE_LUA_CMD # Just prints the message for RHEL
fi

log_info "Checking for CrowdSec ('cscli')..."
check_command "cscli"

# --- Create Directories and Copy Files ---
log_info "Creating directories..."
mkdir -p "$CONFIG_DIR"
mkdir -p "$LUA_SCRIPT_DIR"

log_info "Copying Lua script and configuration file..."
cp "$LUA_SOURCE_FILE" "$LUA_SCRIPT_FILE"
cp "$YAML_TEMPLATE_FILE" "$CONFIG_FILE"

# Copy LICENSE file if it exists
if [ "$COPY_LICENSE" = true ]; then
    log_info "Copying LICENSE file..."
    cp "$LICENSE_FILE" "$LUA_SCRIPT_DIR/"
fi

# --- Generate API Key ---
log_info "Generating API key for bouncer '$BOUNCER_NAME'..."

# Check if the bouncer already exists
if cscli bouncers list -o raw | grep -q "^${BOUNCER_NAME},"; then
    log_warn "Bouncer '$BOUNCER_NAME' already exists. A new key will be generated."
    # Delete the existing bouncer to generate a clean new key
    cscli bouncers delete "$BOUNCER_NAME" || log_warn "Could not delete existing bouncer '$BOUNCER_NAME'. Continuing..."
fi

# Generate the bouncer and capture the key
RAW_API_KEY=$(cscli bouncers add "$BOUNCER_NAME" -o raw)
if [ -z "$RAW_API_KEY" ]; then
    log_error "Could not generate API key using 'cscli bouncers add'. Check CrowdSec logs."
fi
# Extract just the key (raw output is only the key)
API_KEY=$(echo "$RAW_API_KEY" | tr -d '\n')

log_info "API key generated successfully."

# --- Update Configuration File ---
log_info "Updating API key in $CONFIG_FILE..."
# Use a different delimiter for sed in case the key contains '/'
if ! sed -i "s|PLACEHOLDER_API_KEY|$API_KEY|g" "$CONFIG_FILE"; then
     log_error "Could not update API key in $CONFIG_FILE."
fi

# --- Set Permissions ---
log_info "Setting permissions for configuration file and script..."
chown root:root "$CONFIG_FILE"
chmod 640 "$CONFIG_FILE" # Root can read/write, root group can read
chown root:root "$LUA_SCRIPT_FILE"
chmod 644 "$LUA_SCRIPT_FILE"
if [ "$COPY_LICENSE" = true ]; then
    chown root:root "$LUA_SCRIPT_DIR/$LICENSE_FILE"
    chmod 644 "$LUA_SCRIPT_DIR/$LICENSE_FILE"
fi


log_info "Creating and setting permissions for log file $LOG_FILE..."
touch "$LOG_FILE"
# Attempt to set ownership to Apache user. If chown fails (e.g., user doesn't exist yet), log warning.
if ! chown "$APACHE_USER":"$APACHE_USER" "$LOG_FILE"; then
    log_warn "Could not change ownership of $LOG_FILE to $APACHE_USER. Manual adjustment might be needed."
    log_warn "Setting permissions to 666 to allow broader write access as a fallback."
    chmod 666 "$LOG_FILE"
else
    chmod 640 "$LOG_FILE" # Apache user read/write, group read
fi

# --- Final Instructions ---
log_info "Installation finished successfully!"
echo ""
log_info "NEXT STEPS:"
echo "1. Add the following lines to your Apache configuration (within the relevant <VirtualHost> section):"
echo ""
echo "   --------------------------------------------------"
echo "   # Load the Lua script for the CrowdSec bouncer"
echo "   LuaLoadFile $LUA_SCRIPT_FILE"
echo ""
echo "   # Hook into the access checker phase"
echo "   LuaHookAccessChecker check_access"
echo "   --------------------------------------------------"
echo ""
echo "   Example configuration file locations:"
echo "   - Debian/Ubuntu: /etc/apache2/sites-available/your-site.conf"
echo "   - RHEL/CentOS/Fedora: /etc/httpd/conf.d/your-site.conf"
echo ""
echo "2. Test your Apache configuration:"
if [[ "$PKG_MANAGER" == "apt-get" ]]; then
    echo "   sudo apache2ctl configtest"
else
    echo "   sudo apachectl configtest"
fi
echo ""
echo "3. Restart Apache to apply the changes:"
if [[ "$PKG_MANAGER" == "apt-get" ]]; then
    echo "   sudo systemctl restart $APACHE_SERVICE"
else
    echo "   sudo systemctl restart $APACHE_SERVICE"
fi
echo ""
log_info "Check $LOG_FILE to monitor the bouncer's activity."

exit 0