#!/usr/bin/env bash
# install_pressbooks_bedrock.sh
# Idempotent Pressbooks + Bedrock + Apache + Let's Encrypt on Ubuntu 24.04
# Domain: pressbooks.qbnox.com

set -euo pipefail

### --- CONFIG SECTION --- ###
DOMAIN="pressbooks.qbnox.com"
SERVER_IP="101.53.135.111"

DB_NAME="pressbooks"
DB_USER="pressbooks"

# Default random DB password for this run
DB_PASS_RUN="$(openssl rand -hex 16)"

WP_ADMIN_USER="pbadmin"
WP_ADMIN_PASS_RUN="$(openssl rand -hex 16)"
WP_ADMIN_EMAIL="admin@${DOMAIN}"

APP_DIR="/var/www/pressbooksoss-bedrock"
PRINCE_DEB_URL="https://www.princexml.com/download/prince_16.1-1_ubuntu24.04_amd64.deb"

### --- FLAGS TO REPORT WHAT HAPPENED --- ###
NEW_DB_CREATED=false
NEW_WP_INSTALLED=false

### --- LOGGING --- ###
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOGFILE="setup_log_${TIMESTAMP}.txt"

exec > >(tee -a "$LOGFILE") 2>&1

echo "==============================================="
echo " Pressbooks Bedrock setup starting: $(date)"
echo " Log file: $LOGFILE"
echo " Domain: $DOMAIN"
echo "==============================================="

### --- BASIC SANITY --- ###
if [ "$(id -u)" -ne 0 ]; then
  echo "[!] Please run this script as root (or via sudo)."
  exit 1
fi

### --- PACKAGE INSTALL --- ###
echo "[*] Updating apt and installing base packages (idempotent)..."

apt-get update -y

apt-get install -y \
  software-properties-common curl git unzip ca-certificates lsb-release gnupg2 \
  apache2 mysql-server \
  certbot python3-certbot-apache \
  php-fpm php-cli php-mysql php-xml php-mbstring php-zip php-gd php-curl php-imagick php-xsl php-intl php-opcache \
  ghostscript imagemagick poppler-utils epubcheck libxml2-utils \
  redis-server php-redis \
  openssl composer

### --- PHP CONFIG TUNING --- ###
echo "[*] Tuning PHP settings for web workloads & 256MB uploads..."

PHP_VERSION="$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')"
PHP_FPM_INI="/etc/php/${PHP_VERSION}/fpm/php.ini"
PHP_CLI_INI="/etc/php/${PHP_VERSION}/cli/php.ini"

tune_php_ini() {
  local INI="$1"
  if [ -f "$INI" ]; then
    sed -i "s/^memory_limit = .*/memory_limit = 512M/" "$INI"
    sed -i "s/^upload_max_filesize = .*/upload_max_filesize = 256M/" "$INI"
    sed -i "s/^post_max_size = .*/post_max_size = 256M/" "$INI"
    sed -i "s/^max_execution_time = .*/max_execution_time = 600/" "$INI"
    sed -i "s/^max_input_time = .*/max_input_time = 600/" "$INI"
    sed -i "s@^;*date.timezone =.*@date.timezone = Asia/Kolkata@" "$INI"
  fi
}

tune_php_ini "$PHP_FPM_INI"
tune_php_ini "$PHP_CLI_INI"

systemctl restart "php${PHP_VERSION}-fpm"

### --- MYSQL DATABASE & USER SETUP --- ###
echo "[*] Checking MySQL database and user..."

DB_EXISTS=$(mysql -NBe "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME='${DB_NAME}'" || true)
if [ -z "$DB_EXISTS" ]; then
  echo "  [+] Creating database ${DB_NAME}..."
  mysql -e "CREATE DATABASE \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
  NEW_DB_CREATED=true
else
  echo "  [-] Database ${DB_NAME} already exists, skipping creation."
fi

USER_EXISTS=$(mysql -NBe "SELECT 1 FROM mysql.user WHERE user='${DB_USER}' AND host='localhost'" || true)
if [ -z "$USER_EXISTS" ]; then
  echo "  [+] Creating MySQL user ${DB_USER}..."
  mysql -e "CREATE USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS_RUN}';"
else
  echo "  [*] MySQL user ${DB_USER}@localhost exists, resetting password..."
  mysql -e "ALTER USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS_RUN}';"
fi

mysql -e "GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';"
mysql -e "FLUSH PRIVILEGES;"

DB_PASS_FINAL="$DB_PASS_RUN"

### --- WP-CLI INSTALL --- ###
echo "[*] Checking WP-CLI..."

if ! command -v wp >/dev/null 2>&1; then
  echo "  [+] Installing WP-CLI..."
  curl -sSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o /usr/local/bin/wp
  chmod +x /usr/local/bin/wp
else
  echo "  [-] WP-CLI already installed, skipping."
fi

### --- CLONE PRESSBOOKS BEDROCK --- ###
echo "[*] Checking pressbooksoss-bedrock directory..."

if [ ! -d "$APP_DIR" ]; then
  echo "  [+] Cloning repository..."
  mkdir -p /var/www
  git clone https://github.com/pressbooks/pressbooksoss-bedrock.git "$APP_DIR"
else
  echo "  [-] $APP_DIR already exists, skipping clone."
fi

# Ensure web user owns the app (for composer, wp, dotenv)
chown -R www-data:www-data "$APP_DIR"

cd "$APP_DIR"

export COMPOSER_ALLOW_SUPERUSER=1
export COMPOSER_NO_INTERACTION=1

### --- COMPOSER INSTALL --- ###
echo "[*] Running composer install (safe to re-run)..."
sudo -u www-data composer install --no-dev --prefer-dist --optimize-autoloader

### --- INSTALL PRINCEXML --- ###
echo "[*] Checking PrinceXML..."

if command -v prince >/dev/null 2>&1; then
  echo "  [-] PrinceXML already installed at $(command -v prince), skipping."
else
  echo "  [+] Installing PrinceXML from .deb..."
  PRINCE_DEB="/tmp/$(basename "$PRINCE_DEB_URL")"
  if [ ! -f "$PRINCE_DEB" ]; then
    curl -L "$PRINCE_DEB_URL" -o "$PRINCE_DEB"
  fi
  dpkg -i "$PRINCE_DEB" || apt-get install -f -y
fi

### --- PREPARE WP-CLI PACKAGE DIR FOR www-data --- ###
echo "[*] Ensuring wp-cli package directory for www-data..."

WPCLI_PKG_DIR="/var/www/.wp-cli"
mkdir -p "${WPCLI_PKG_DIR}/packages"
chown -R www-data:www-data "${WPCLI_PKG_DIR}"

### --- MANAGE .env VIA wp dotenv --- ###
echo "[*] Managing .env via wp dotenv..."

# Ensure wp-cli dotenv package is installed (for www-data)
if ! sudo -u www-data wp package list 2>/dev/null | grep -q "aaemnnosttv/wp-cli-dotenv-command"; then
  echo "  [+] Installing wp-cli dotenv package..."
  sudo -u www-data wp package install aaemnnosttv/wp-cli-dotenv-command:^2.0
else
  echo "  [-] wp-cli dotenv package already installed."
fi

if [ ! -f .env ]; then
  echo "  [+] Initializing .env from .env.example (if present)..."
  if [ -f .env.example ]; then
    sudo -u www-data wp dotenv init --template=.env.example
  else
    sudo -u www-data wp dotenv init
  fi
  echo "  [+] Generating salts in .env..."
  sudo -u www-data wp dotenv salts generate
else
  echo "  [-] .env already exists, updating values."
fi

# Set/update all key env vars
sudo -u www-data wp dotenv set DB_NAME "${DB_NAME}"
sudo -u www-data wp dotenv set DB_USER "${DB_USER}"
sudo -u www-data wp dotenv set DB_PASSWORD "${DB_PASS_FINAL}"
sudo -u www-data wp dotenv set DB_HOST "localhost"
sudo -u www-data wp dotenv set DB_PREFIX "wp_"

sudo -u www-data wp dotenv set WP_ENV "development"
sudo -u www-data wp dotenv set WP_HOME "https://${DOMAIN}"
sudo -u www-data wp dotenv set WP_SITEURL "\${WP_HOME}/wp"
sudo -u www-data wp dotenv set HTTP_HOST "${DOMAIN}"
sudo -u www-data wp dotenv set DOMAIN_CURRENT_SITE "${DOMAIN}"

sudo -u www-data wp dotenv set WP_ALLOW_MULTISITE "true"
sudo -u www-data wp dotenv set MULTISITE "true"
sudo -u www-data wp dotenv set SUBDOMAIN_INSTALL "false"
sudo -u www-data wp dotenv set PATH_CURRENT_SITE "/"
sudo -u www-data wp dotenv set SITE_ID_CURRENT_SITE "1"
sudo -u www-data wp dotenv set BLOG_ID_CURRENT_SITE "1"

sudo -u www-data wp dotenv set PB_PRINCE_COMMAND "/usr/bin/prince"

### --- FILE PERMISSIONS (FINAL PASS) --- ###
echo "[*] Ensuring file permissions (www-data, safe to re-run)..."
chown -R www-data:www-data "$APP_DIR"
find "$APP_DIR" -type d -exec chmod 755 {} \;
find "$APP_DIR" -type f -exec chmod 644 {} \;

### --- APACHE + PHP-FPM CONFIG --- ###
echo "[*] Configuring Apache for Bedrock + PHP-FPM & 256MB uploads..."

a2dismod mpm_prefork >/dev/null 2>&1 || true
a2enmod mpm_event rewrite ssl proxy_fcgi setenvif http2 headers

a2enconf "php${PHP_VERSION}-fpm" >/dev/null 2>&1 || true

VHOST_FILE="/etc/apache2/sites-available/pressbooks.conf"

if [ ! -f "$VHOST_FILE" ]; then
  echo "  [+] Creating Apache vhost for ${DOMAIN}..."
  cat >"$VHOST_FILE" <<EOF
<VirtualHost *:80>
    ServerName ${DOMAIN}
    ServerAdmin webmaster@${DOMAIN}

    DocumentRoot ${APP_DIR}/web
    DirectoryIndex index.php index.html

    <Directory ${APP_DIR}/web>
        AllowOverride All
        Require all granted
    </Directory>

    <FilesMatch \.php$>
        SetHandler "proxy:unix:/run/php/php${PHP_VERSION}-fpm.sock|fcgi://localhost/"
    </FilesMatch>

    # Allow uploads up to 256MB
    LimitRequestBody 268435456

    ErrorLog \${APACHE_LOG_DIR}/pressbooks_error.log
    CustomLog \${APACHE_LOG_DIR}/pressbooks_access.log combined

    KeepAlive On
    MaxKeepAliveRequests 100
    KeepAliveTimeout 2
</VirtualHost>
EOF
else
  echo "  [-] Apache vhost ${VHOST_FILE} already exists, not overwriting."
fi

a2dissite 000-default.conf >/dev/null 2>&1 || true
a2ensite pressbooks.conf >/dev/null 2>&1 || true

### --- APACHE TIMEOUT TUNING (GLOBAL) --- ###
echo "[*] Applying Apache timeout tuning for large uploads..."

APACHE_TIMEOUT_CONF="/etc/apache2/conf-available/pressbooks-timeout.conf"
cat >"$APACHE_TIMEOUT_CONF" <<EOF
# Increased timeouts for large file uploads and long-running PHP processes
Timeout 600
ProxyTimeout 600
EOF

a2enconf pressbooks-timeout.conf >/dev/null 2>&1 || true

systemctl reload apache2

### --- .htaccess FOR PRESSBOOKS / WORDPRESS MULTISITE --- ###
echo "[*] Checking .htaccess in web/..."

HTACCESS_FILE="${APP_DIR}/web/.htaccess"
if [ ! -f "$HTACCESS_FILE" ]; then
  echo "  [+] Creating .htaccess..."
  cat > "$HTACCESS_FILE" <<'EOF'
# BEGIN WordPress (Pressbooks / Bedrock)
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
RewriteBase /
RewriteRule ^index\.php$ - [L]

# add a trailing slash to /wp-admin
RewriteRule ^([_0-9a-zA-Z-]+/)?wp-admin$ $1wp-admin/ [R=301,L]

RewriteCond %{REQUEST_FILENAME} -f [OR]
RewriteCond %{REQUEST_FILENAME} -d
RewriteRule ^ - [L]
RewriteRule ^([_0-9a-zA-Z-]+/)?(wp-(content|admin|includes).*) wp/$2 [L]
RewriteRule ^([_0-9a-zA-Z-]+/)?(.*\.php)$ wp/$2 [L]
RewriteRule . index.php [L]
</IfModule>
# END WordPress
EOF
else
  echo "  [-] .htaccess already exists, not overwriting."
fi

### --- OS / NETWORK TUNING --- ###
echo "[*] Applying basic sysctl and ulimit tuning (idempotent files)..."

SYSCTL_FILE="/etc/sysctl.d/99-pressbooks-tuning.conf"
cat >"$SYSCTL_FILE" <<EOF
net.core.somaxconn = 1024
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65000
fs.file-max = 200000
vm.swappiness = 10
EOF

sysctl --system

LIMITS_FILE="/etc/security/limits.d/99-pressbooks.conf"
cat >"$LIMITS_FILE" <<EOF
www-data soft nofile 100000
www-data hard nofile 100000
EOF

### --- LET'S ENCRYPT (CERTBOT) --- ###
echo "[*] Checking Let's Encrypt certificate..."

CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
if [ -d "$CERT_DIR" ]; then
  echo "  [-] Certificate for ${DOMAIN} already exists, skipping certbot."
else
  echo "  [+] Obtaining Let's Encrypt certificate with certbot..."
  certbot --apache \
    -d "${DOMAIN}" \
    --non-interactive \
    --agree-tos \
    -m "${WP_ADMIN_EMAIL}" \
    --redirect || true
fi

systemctl restart apache2

### --- WORDPRESS MULTISITE INSTALL (PRESSBOOKS) --- ###
echo "[*] Checking WordPress core installation..."

WP_PATH="${APP_DIR}/web/wp"

if sudo -u www-data wp core is-installed --path="$WP_PATH" --quiet >/dev/null 2>&1; then
  echo "  [-] WordPress already installed, skipping core install."
else
  echo "  [+] Installing WordPress multisite via WP-CLI..."
  sudo -u www-data wp core multisite-install \
    --path="$WP_PATH" \
    --url="https://${DOMAIN}" \
    --title="Pressbooks Network" \
    --admin_user="${WP_ADMIN_USER}" \
    --admin_password="${WP_ADMIN_PASS_RUN}" \
    --admin_email="${WP_ADMIN_EMAIL}" \
    --skip-email \
    --quiet
  NEW_WP_INSTALLED=true
fi

### --- WP-CLI HELPER (ALWAYS AS www-data) --- ###
wp_cli() {
  sudo -u www-data wp "$@" --path="$WP_PATH" --quiet
}

### --- ACTIVATE PRESSBOOKS & OTHER PLUGINS --- ###
echo "[*] Ensuring Pressbooks, H5P, and helper plugins are installed and network-activated..."

# 1) Pressbooks (should be present via composer)
if wp_cli plugin is-installed pressbooks >/dev/null 2>&1; then
  echo "  [-] Pressbooks plugin already installed."
else
  echo "  [!] Pressbooks plugin not detected via wp-cli; check composer install."
fi

if wp_cli plugin is-active pressbooks --network >/dev/null 2>&1; then
  echo "  [-] Pressbooks plugin already network-active."
else
  echo "  [+] Activating Pressbooks plugin network-wide..."
  wp_cli plugin activate pressbooks --network
fi

# 2) H5P
if wp_cli plugin is-installed h5p >/dev/null 2>&1; then
  echo "  [-] H5P plugin already installed."
else
  echo "  [+] Installing H5P plugin..."
  wp_cli plugin install h5p
fi

if wp_cli plugin is-active h5p --network >/dev/null 2>&1; then
  echo "  [-] H5P plugin already network-active."
else
  echo "  [+] Activating H5P plugin network-wide..."
  wp_cli plugin activate h5p --network
fi

# 4) user-role-editor
if wp_cli plugin is-installed user-role-editor >/dev/null 2>&1; then
  echo "  [-] user-role-editor plugin already installed."
else
  echo "  [+] Installing user-role-editor plugin..."
  wp_cli plugin install user-role-editor
fi

if wp_cli plugin is-active user-role-editor --network >/dev/null 2>&1; then
  echo "  [-] user-role-editor plugin already network-active."
else
  echo "  [+] Activating user-role-editor plugin network-wide..."
  wp_cli plugin activate user-role-editor --network
fi

# 5) wp-super-cache
if wp_cli plugin is-installed wp-super-cache >/dev/null 2>&1; then
  echo "  [-] wp-super-cache plugin already installed."
else
  echo "  [+] Installing wp-super-cache plugin..."
  wp_cli plugin install wp-super-cache
fi

if wp_cli plugin is-active wp-super-cache --network >/dev/null 2>&1; then
  echo "  [-] wp-super-cache plugin already network-active."
else
  echo "  [+] Activating wp-super-cache plugin network-wide..."
  wp_cli plugin activate wp-super-cache --network
fi

# 6) redis-cache
if wp_cli plugin is-installed redis-cache >/dev/null 2>&1; then
  echo "  [-] redis-cache plugin already installed."
else
  echo "  [+] Installing redis-cache plugin..."
  wp_cli plugin install redis-cache
fi

if wp_cli plugin is-active redis-cache --network >/dev/null 2>&1; then
  echo "  [-] redis-cache plugin already network-active."
else
  echo "  [+] Activating redis-cache plugin network-wide..."
  wp_cli plugin activate redis-cache --network
fi

# 7) Google reCAPTCHA (Advanced Google reCAPTCHA plugin)
echo "[*] Installing Google reCAPTCHA plugin (Advanced Google reCAPTCHA)..."

if wp_cli plugin is-installed advanced-google-recaptcha >/dev/null 2>&1; then
  echo "  [-] advanced-google-recaptcha plugin already installed."
else
  echo "  [+] Installing advanced-google-recaptcha plugin..."
  wp_cli plugin install advanced-google-recaptcha
fi

if wp_cli plugin is-active advanced-google-recaptcha --network >/dev/null 2>&1; then
  echo "  [-] advanced-google-recaptcha already network-active."
else
  echo "  [+] Activating advanced-google-recaptcha network-wide..."
  wp_cli plugin activate advanced-google-recaptcha --network || \
    echo "  [!] Could not network-activate advanced-google-recaptcha (non-fatal)."
fi

echo "  [!] NOTE: To fully enable Google reCAPTCHA, go to:"
echo "      Network Admin → Settings → Advanced Google reCAPTCHA"
echo "      and paste your Site Key and Secret Key."

### --- SUMMARY --- ###
echo "====================================================================="
echo " Pressbooks Bedrock installation / update COMPLETE"
echo "---------------------------------------------------------------------"
echo "  Site URL:      https://${DOMAIN}"
echo "  Admin login:   https://${DOMAIN}/wp/wp-login.php"
echo
if $NEW_DB_CREATED; then
  echo "  [DB] New database created: ${DB_NAME}"
else
  echo "  [DB] Database ${DB_NAME} already existed (unchanged)."
fi

echo
echo "  [DB] DB user:  ${DB_USER}@localhost"
echo "       DB pass (this run): ${DB_PASS_FINAL}"
echo
if $NEW_WP_INSTALLED; then
  echo "  [WP] New WordPress multisite install performed."
  echo "       Admin user: ${WP_ADMIN_USER}"
  echo "       Admin pass (this run): ${WP_ADMIN_PASS_RUN}"
else
  echo "  [WP] WordPress core was already installed; admin credentials unchanged."
fi

echo
echo "  App directory:  ${APP_DIR}"
echo "  Log file:       ${LOGFILE}"
echo "====================================================================="

