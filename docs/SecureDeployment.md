# Secure Deployment

## Why Secure Deployment Matters

Deployment security is critical because misconfigured servers are responsible for the majority of data breaches. A secure deployment protects against:

- **Unauthorized access** to sensitive data
- **Code execution** through misconfigured permissions
- **Data interception** via unencrypted connections
- **Service disruption** from denial of service attacks
- **Information leakage** through exposed sensitive files

### Deployment Security Statistics

- **80%** of breaches involve misconfigured servers
- **60%** of data breaches occur within minutes of deployment
- **40%** of organizations have experienced cloud misconfigurations
- **Average cost** of deployment-related breach: $4.87 million

## HTTPS Configuration

### SSL/TLS Certificate Management

#### Let's Encrypt (Free Certificates)
```bash
# Install Certbot
sudo apt update
sudo apt install certbot python3-certbot-apache

# Generate certificate
sudo certbot --apache -d yourdomain.com -d www.yourdomain.com

# Automatic renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

#### Commercial SSL Certificates
```bash
# Generate CSR (Certificate Signing Request)
openssl req -new -newkey rsa:2048 -nodes -keyout yourdomain.key -out yourdomain.csr

# Submit CSR to certificate authority
# Install certificate files
sudo cp yourdomain.crt /etc/ssl/certs/
sudo cp yourdomain.key /etc/ssl/private/
sudo cp intermediate.crt /etc/ssl/certs/
```

### Apache HTTPS Configuration

```apache
# /etc/apache2/sites-available/yourdomain-ssl.conf
<VirtualHost *:443>
    ServerName yourdomain.com
    ServerAlias www.yourdomain.com
    DocumentRoot /var/www/yourdomain/public

    # SSL Configuration
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/yourdomain.crt
    SSLCertificateKeyFile /etc/ssl/private/yourdomain.key
    SSLCertificateChainFile /etc/ssl/certs/intermediate.crt

    # HSTS (HTTP Strict Transport Security)
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

    # Security Headers
    Header always set X-Frame-Options DENY
    Header always set X-Content-Type-Options nosniff
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"

    # SSL Protocol and Cipher Configuration
    SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384
    SSLHonorCipherOrder on
    SSLCompression off

    # OCSP Stapling
    SSLUseStapling on
    SSLStaplingCache "shmcb:logs/stapling-cache(150000)"

    <Directory /var/www/yourdomain/public>
        Options -Indexes -FollowSymLinks
        AllowOverride All
        Require all granted

        # Additional security for Laravel
        php_value upload_max_filesize 10M
        php_value post_max_size 12M
        php_value memory_limit 256M
    </Directory>
</VirtualHost>

# Redirect HTTP to HTTPS
<VirtualHost *:80>
    ServerName yourdomain.com
    ServerAlias www.yourdomain.com
    Redirect permanent / https://yourdomain.com/
</VirtualHost>
```

### Nginx HTTPS Configuration

```nginx
# /etc/nginx/sites-available/yourdomain
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    # SSL Configuration
    ssl_certificate /etc/ssl/certs/yourdomain.crt;
    ssl_certificate_key /etc/ssl/private/yourdomain.key;
    ssl_trusted_certificate /etc/ssl/certs/intermediate.crt;

    # SSL Protocols and Ciphers
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256;
    ssl_prefer_server_ciphers off;

    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # Security Headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;

    # Root directory
    root /var/www/yourdomain/public;
    index index.php index.html;

    # Hide nginx version
    server_tokens off;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }

    # Secure file access
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    # Restrict access to sensitive files
    location ~ \.(env|log|htaccess|htpasswd)$ {
        deny all;
        return 444;
    }

    # Cache static assets
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

### SSL/TLS Best Practices

#### Certificate Configuration
```bash
# Test SSL configuration
openssl s_client -connect yourdomain.com:443 -servername yourdomain.com

# Check certificate details
openssl x509 -in yourdomain.crt -text -noout

# Verify certificate chain
openssl verify -CAfile intermediate.crt yourdomain.crt
```

#### SSL Labs Testing
```bash
# Test SSL configuration quality
# Visit: https://www.ssllabs.com/ssltest/
```

## Server File Permissions

### Linux File Permissions

#### Understanding Permissions
```bash
# File permission format: rwxrwxrwx (owner, group, others)
# r = read (4), w = write (2), x = execute (1)

# View permissions
ls -la /var/www/

# Change ownership
sudo chown -R www-data:www-data /var/www/yourdomain

# Set directory permissions (755)
sudo find /var/www/yourdomain -type d -exec chmod 755 {} \;

# Set file permissions (644)
sudo find /var/www/yourdomain -type f -exec chmod 644 {} \;
```

#### Laravel-Specific Permissions
```bash
# Laravel storage and bootstrap cache permissions
sudo chown -R www-data:www-data /var/www/yourdomain/storage
sudo chown -R www-data:www-data /var/www/yourdomain/bootstrap/cache
sudo chmod -R 775 /var/www/yourdomain/storage
sudo chmod -R 775 /var/www/yourdomain/bootstrap/cache

# Make artisan executable
sudo chmod +x /var/www/yourdomain/artisan
```

### Secure Directory Structure

```bash
/var/www/yourdomain/
├── app/                    # 755
├── bootstrap/             # 755
│   └── cache/            # 775
├── config/               # 755
├── database/             # 755
├── public/               # 755
│   ├── index.php        # 644
│   └── .htaccess       # 644
├── resources/           # 755
├── routes/              # 755
├── storage/             # 775
│   ├── app/            # 775
│   ├── framework/      # 775
│   └── logs/           # 775
├── tests/               # 755
├── vendor/              # 755
├── artisan             # 755
├── composer.json       # 644
├── composer.lock       # 644
├── package.json        # 644
├── webpack.mix.js      # 644
├── .env.example        # 644
└── .env               # 600 (restrictive!)
```

### File Permission Audit Script

```bash
#!/bin/bash
# secure-permissions.sh - Audit and fix file permissions

TARGET_DIR="/var/www/yourdomain"
WEB_USER="www-data"
WEB_GROUP="www-data"

echo "🔍 Auditing file permissions in $TARGET_DIR"

# Check .env file permissions
ENV_FILE="$TARGET_DIR/.env"
if [ -f "$ENV_FILE" ]; then
    PERMS=$(stat -c "%a" "$ENV_FILE")
    if [ "$PERMS" != "600" ]; then
        echo "❌ .env file has insecure permissions: $PERMS (should be 600)"
        chmod 600 "$ENV_FILE"
        echo "✅ Fixed .env permissions"
    fi
fi

# Check storage directory permissions
STORAGE_DIR="$TARGET_DIR/storage"
if [ -d "$STORAGE_DIR" ]; then
    find "$STORAGE_DIR" -type d -exec chmod 775 {} \;
    find "$STORAGE_DIR" -type f -exec chmod 664 {} \;
    chown -R "$WEB_USER:$WEB_GROUP" "$STORAGE_DIR"
    echo "✅ Fixed storage directory permissions"
fi

# Check bootstrap cache permissions
BOOTSTRAP_CACHE="$TARGET_DIR/bootstrap/cache"
if [ -d "$BOOTSTRAP_CACHE" ]; then
    chmod 775 "$BOOTSTRAP_CACHE"
    chown -R "$WEB_USER:$WEB_GROUP" "$BOOTSTRAP_CACHE"
    echo "✅ Fixed bootstrap cache permissions"
fi

# Find world-writable files (security risk)
echo "🔍 Checking for world-writable files..."
WORLD_WRITABLE=$(find "$TARGET_DIR" -type f -perm -002 2>/dev/null)
if [ -n "$WORLD_WRITABLE" ]; then
    echo "❌ Found world-writable files:"
    echo "$WORLD_WRITABLE"
    echo "Consider removing world write permissions"
fi

# Find files with incorrect ownership
echo "🔍 Checking file ownership..."
INCORRECT_OWNER=$(find "$TARGET_DIR" -not -user "$WEB_USER" -type f \( -name "*.php" -o -name "*.log" \) 2>/dev/null | head -10)
if [ -n "$INCORRECT_OWNER" ]; then
    echo "⚠️ Found files not owned by $WEB_USER:"
    echo "$INCORRECT_OWNER"
fi

echo "🎉 Permission audit completed!"
```

## Hiding Sensitive Files

### Web Server Configuration

#### Apache .htaccess

```apache
# /var/www/yourdomain/public/.htaccess

# Hide sensitive files
<FilesMatch "\.(env|log|htaccess|htpasswd|ini|conf|bak|backup|old)$">
    Order Allow,Deny
    Deny from all
    Require all denied
</FilesMatch>

# Hide version control files
<FilesMatch "(\.git|\.svn|\.hg)">
    Order Allow,Deny
    Deny from all
    Require all denied
</FilesMatch>

# Hide backup files
<FilesMatch "\.(bak|backup|old|orig|tmp|temp)$">
    Order Allow,Deny
    Deny from all
    Require all denied
</FilesMatch>

# Hide PHP error logs
<Files "error_log">
    Order Allow,Deny
    Deny from all
    Require all denied
</Files>

# Hide composer files
<FilesMatch "(composer\.json|composer\.lock)">
    Order Allow,Deny
    Deny from all
    Require all denied
</FilesMatch>
```

#### Nginx Configuration

```nginx
# /etc/nginx/sites-available/yourdomain

server {
    # ... SSL configuration ...

    # Hide sensitive files
    location ~ /\.(env|git|svn|hg) {
        deny all;
        return 444;
    }

    location ~ \.(log|htaccess|htpasswd|ini|conf|bak|backup|old|orig|tmp|temp)$ {
        deny all;
        return 444;
    }

    location ~ (composer\.json|composer\.lock|package\.json|webpack\.mix\.js)$ {
        deny all;
        return 444;
    }

    location ~ \.php$ {
        # ... PHP configuration ...

        # Prevent access to certain PHP files
        location ~ /(artisan|console)$ {
            deny all;
            return 444;
        }
    }
}
```

### Laravel-Specific File Protection

```php
<?php
// routes/web.php - Additional file protection

// Prevent access to sensitive Laravel files
Route::get('/artisan', function () {
    abort(404);
});

Route::get('/console', function () {
    abort(404);
});

// Prevent access to composer files
Route::get('/composer.{json,lock}', function () {
    abort(404);
});

// Prevent access to environment files
Route::get('/.env{,.example}', function () {
    abort(404);
});
```

### File Location Strategy

```bash
# Secure file placement strategy

# 1. Public files (accessible via web)
/var/www/yourdomain/public/
├── index.php
├── assets/
├── uploads/        # User-uploaded files (with access control)
└── .htaccess

# 2. Application files (not web-accessible)
/var/www/yourdomain/
├── app/
├── config/
├── database/
├── resources/
├── routes/
├── tests/
├── vendor/
├── composer.json
├── composer.lock
└── artisan

# 3. Sensitive files (restricted access)
/var/www/yourdomain/
├── .env           # 600 permissions
├── storage/logs/  # 775 permissions
└── bootstrap/cache/ # 775 permissions

# 4. Backup files (outside web root)
/var/backups/yourdomain/
├── database/
└── files/
```

## Basic Firewall Rules

### UFW (Uncomplicated Firewall)

```bash
# Install UFW
sudo apt install ufw

# Enable UFW
sudo ufw enable

# Allow SSH (before enabling firewall!)
sudo ufw allow ssh
sudo ufw allow 22

# Allow HTTP and HTTPS
sudo ufw allow 80
sudo ufw allow 443

# Allow MySQL (if needed from specific IPs)
sudo ufw allow from 192.168.1.0/24 to any port 3306

# Deny everything else by default
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Check status
sudo ufw status verbose

# View numbered rules
sudo ufw status numbered
```

### iptables (Advanced Configuration)

```bash
#!/bin/bash
# secure-firewall.sh - Configure iptables firewall

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback interface
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (rate limited)
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTP
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# Allow HTTPS
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow MySQL from specific IPs
iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 3306 -j ACCEPT

# Allow ping
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "Dropped: " --log-level 4

# Save rules
sudo iptables-save > /etc/iptables/rules.v4

# Make persistent
sudo apt install iptables-persistent
sudo systemctl enable netfilter-persistent
```

### Fail2Ban Integration

```bash
# Install Fail2Ban
sudo apt install fail2ban

# Configure SSH protection
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Edit /etc/fail2ban/jail.local
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

# Configure Apache protection
[apache-noscript]
enabled = true
port = http,https
filter = apache-noscript
logpath = /var/log/apache2/error.log
maxretry = 6

[apache-badbots]
enabled = true
port = http,https
filter = apache-badbots
logpath = /var/log/apache2/access.log
maxretry = 2

# Restart Fail2Ban
sudo systemctl restart fail2ban

# Check status
sudo fail2ban-client status
```

### Application-Level Firewall

```php
<?php
class ApplicationFirewall
{
    private array $blacklist = [];
    private array $whitelist = [];

    public function __construct()
    {
        // Load IP blacklists
        $this->loadIPLists();
    }

    public function checkRequest(): bool
    {
        $clientIP = $_SERVER['REMOTE_ADDR'];
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $requestUri = $_SERVER['REQUEST_URI'] ?? '';

        // Check IP blacklist
        if ($this->isBlacklisted($clientIP)) {
            $this->logBlockedRequest($clientIP, 'IP blacklist');
            return false;
        }

        // Check suspicious user agents
        if ($this->isSuspiciousUserAgent($userAgent)) {
            $this->logBlockedRequest($clientIP, 'Suspicious user agent');
            return false;
        }

        // Check for malicious patterns in URI
        if ($this->containsMaliciousPatterns($requestUri)) {
            $this->logBlockedRequest($clientIP, 'Malicious URI pattern');
            return false;
        }

        return true;
    }

    private function loadIPLists(): void
    {
        // Load from files or database
        $this->blacklist = [
            '192.168.1.100', // Example blocked IP
            '10.0.0.1',
        ];

        $this->whitelist = [
            '192.168.1.0/24', // Local network
        ];
    }

    private function isBlacklisted(string $ip): bool
    {
        return in_array($ip, $this->blacklist);
    }

    private function isSuspiciousUserAgent(string $userAgent): bool
    {
        $suspiciousPatterns = [
            '/sqlmap/i',
            '/nikto/i',
            '/dirbuster/i',
            '/acunetix/i',
            '/nessus/i',
        ];

        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                return true;
            }
        }

        return false;
    }

    private function containsMaliciousPatterns(string $uri): bool
    {
        $maliciousPatterns = [
            '/\.\./', // Directory traversal
            '/<script/i', // XSS attempts
            '/union\s+select/i', // SQL injection
            '/eval\(/i', // Code injection
            '/base64_decode/i', // Obfuscation
        ];

        foreach ($maliciousPatterns as $pattern) {
            if (preg_match($pattern, $uri)) {
                return true;
            }
        }

        return false;
    }

    private function logBlockedRequest(string $ip, string $reason): void
    {
        $logEntry = sprintf(
            "[FIREWALL BLOCK] IP: %s, Reason: %s, URI: %s, User-Agent: %s, Time: %s\n",
            $ip,
            $reason,
            $_SERVER['REQUEST_URI'] ?? '',
            $_SERVER['HTTP_USER_AGENT'] ?? '',
            date('Y-m-d H:i:s')
        );

        error_log($logEntry);
    }
}

// Usage in application bootstrap
$firewall = new ApplicationFirewall();
if (!$firewall->checkRequest()) {
    http_response_code(403);
    echo "Access Denied";
    exit;
}
```

## Deployment Security Checklist

### HTTPS Configuration
- [ ] SSL/TLS certificates installed and valid
- [ ] HTTP traffic redirected to HTTPS
- [ ] HSTS headers configured
- [ ] Secure cipher suites enabled
- [ ] Certificate chain complete

### File Permissions
- [ ] Web server user has minimal permissions
- [ ] Sensitive files have restrictive permissions (.env = 600)
- [ ] Storage directories have proper permissions (775)
- [ ] No world-writable files exist
- [ ] File ownership is correct

### File Protection
- [ ] Sensitive files blocked from web access
- [ ] Version control files hidden
- [ ] Backup files not accessible
- [ ] PHP error logs protected
- [ ] Composer files hidden

### Firewall Configuration
- [ ] Unnecessary ports closed
- [ ] SSH access restricted
- [ ] Database ports protected
- [ ] Rate limiting implemented
- [ ] Fail2Ban configured

### Server Hardening
- [ ] Latest security patches applied
- [ ] Unnecessary services disabled
- [ ] Root login disabled
- [ ] SSH key authentication enabled
- [ ] Automatic updates configured

## Automated Deployment Scripts

### Secure Deployment Script

```bash
#!/bin/bash
# secure-deploy.sh

set -e  # Exit on any error

echo "🚀 Starting secure deployment..."

# Pre-deployment checks
echo "🔍 Running pre-deployment checks..."

# Check if running as root (dangerous)
if [ "$EUID" -eq 0 ]; then
    echo "❌ Do not run deployment as root"
    exit 1
fi

# Check disk space
REQUIRED_SPACE=1000000  # 1GB in KB
AVAILABLE_SPACE=$(df /var/www | tail -1 | awk '{print $4}')
if [ "$AVAILABLE_SPACE" -lt "$REQUIRED_SPACE" ]; then
    echo "❌ Insufficient disk space"
    exit 1
fi

# Backup current deployment
echo "💾 Creating backup..."
BACKUP_DIR="/var/backups/$(date +%Y%m%d_%H%M%S)"
sudo mkdir -p "$BACKUP_DIR"
sudo cp -r /var/www/yourdomain "$BACKUP_DIR/"

# Deploy application
echo "📦 Deploying application..."
sudo cp -r /tmp/deployment/* /var/www/yourdomain/

# Set secure permissions
echo "🔒 Setting secure permissions..."
sudo chown -R www-data:www-data /var/www/yourdomain
sudo find /var/www/yourdomain -type f -exec chmod 644 {} \;
sudo find /var/www/yourdomain -type d -exec chmod 755 {} \;
sudo chmod 600 /var/www/yourdomain/.env
sudo chmod 775 /var/www/yourdomain/storage
sudo chmod 775 /var/www/yourdomain/bootstrap/cache

# Install dependencies
echo "📦 Installing dependencies..."
cd /var/www/yourdomain
composer install --no-dev --optimize-autoloader
npm ci --production

# Run database migrations
echo "🗄️ Running migrations..."
php artisan migrate --force

# Clear and cache configuration
echo "⚙️ Optimizing application..."
php artisan config:cache
php artisan route:cache
php artisan view:cache
php artisan event:cache

# Install Node.js dependencies and build assets
echo "🎨 Building assets..."
npm run production

# Run tests
echo "🧪 Running tests..."
if ! php artisan test --no-coverage; then
    echo "❌ Tests failed - rolling back..."
    sudo rm -rf /var/www/yourdomain
    sudo mv "$BACKUP_DIR/yourdomain" /var/www/
    exit 1
fi

# Health check
echo "🏥 Running health checks..."
if curl -f -s http://localhost/health-check > /dev/null; then
    echo "✅ Application health check passed"
else
    echo "❌ Application health check failed - rolling back..."
    sudo rm -rf /var/www/yourdomain
    sudo mv "$BACKUP_DIR/yourdomain" /var/www/
    exit 1
fi

# Clean up old backups (keep last 5)
echo "🧹 Cleaning up old backups..."
cd /var/backups
ls -t | tail -n +6 | xargs -r sudo rm -rf

# Restart services
echo "🔄 Restarting services..."
sudo systemctl reload nginx
sudo systemctl reload php8.2-fpm

# Log deployment
echo "$(date): Deployment completed successfully" >> /var/log/deployments.log

echo "🎉 Secure deployment completed successfully!"
```

### Rollback Script

```bash
#!/bin/bash
# rollback.sh

echo "🔄 Starting rollback..."

# Find latest backup
LATEST_BACKUP=$(ls -t /var/backups | head -1)

if [ -z "$LATEST_BACKUP" ]; then
    echo "❌ No backup found"
    exit 1
fi

echo "📦 Rolling back to: $LATEST_BACKUP"

# Stop services
sudo systemctl stop nginx
sudo systemctl stop php8.2-fpm

# Restore backup
sudo rm -rf /var/www/yourdomain
sudo cp -r "/var/backups/$LATEST_BACKUP" /var/www/yourdomain

# Restart services
sudo systemctl start php8.2-fpm
sudo systemctl start nginx

# Health check
if curl -f -s http://localhost/health-check > /dev/null; then
    echo "✅ Rollback successful"
else
    echo "❌ Rollback failed - manual intervention required"
    exit 1
fi
```

## Monitoring and Alerting

### Server Monitoring Setup

```bash
# Install monitoring tools
sudo apt install nagios-nrpe-server nagios-plugins
sudo apt install prometheus node-exporter

# Configure log monitoring
sudo apt install logwatch
sudo logwatch --detail high --mailto admin@yourdomain.com --range today

# Set up automated security scans
sudo apt install lynis
sudo lynis audit system --cronjob
```

### Deployment Monitoring

```php
<?php
class DeploymentMonitor
{
    public static function logDeployment(array $details): void
    {
        $logEntry = [
            'timestamp' => date('c'),
            'type' => 'DEPLOYMENT',
            'version' => $details['version'] ?? 'unknown',
            'environment' => $details['environment'] ?? 'production',
            'user' => $details['user'] ?? 'automated',
            'duration' => $details['duration'] ?? 0,
            'status' => $details['status'] ?? 'unknown',
            'commit_hash' => $details['commit_hash'] ?? null,
        ];

        // Log to file
        $jsonEntry = json_encode($logEntry, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        file_put_contents('/var/log/deployments.log', $jsonEntry . "\n", FILE_APPEND | LOCK_EX);

        // Send alert for failed deployments
        if (($details['status'] ?? 'unknown') === 'failed') {
            self::sendFailureAlert($details);
        }
    }

    public static function checkPostDeploymentHealth(): array
    {
        $issues = [];

        // Check file permissions
        if (!self::checkFilePermissions()) {
            $issues[] = 'File permissions incorrect after deployment';
        }

        // Check database connectivity
        if (!self::checkDatabaseConnection()) {
            $issues[] = 'Database connection failed';
        }

        // Check application responsiveness
        if (!self::checkApplicationHealth()) {
            $issues[] = 'Application health check failed';
        }

        return $issues;
    }

    private static function checkFilePermissions(): bool
    {
        $envFile = '/var/www/yourdomain/.env';
        return file_exists($envFile) && decoct(fileperms($envFile) & 0777) === '600';
    }

    private static function checkDatabaseConnection(): bool
    {
        try {
            $pdo = new PDO(
                "mysql:host=" . getenv('DB_HOST') . ";dbname=" . getenv('DB_DATABASE'),
                getenv('DB_USERNAME'),
                getenv('DB_PASSWORD')
            );
            return true;
        } catch (PDOException $e) {
            return false;
        }
    }

    private static function checkApplicationHealth(): bool
    {
        $context = stream_context_create([
            'http' => [
                'timeout' => 5,
                'ignore_errors' => true
            ]
        ]);

        $response = file_get_contents('http://localhost/health-check', false, $context);
        return $response !== false && strpos($response, 'OK') !== false;
    }

    private static function sendFailureAlert(array $details): void
    {
        $message = "🚨 Deployment Failed\n\n";
        $message .= "Version: {$details['version']}\n";
        $message .= "Environment: {$details['environment']}\n";
        $message .= "Error: {$details['error'] ?? 'Unknown error'}\n";
        $message .= "Time: " . date('Y-m-d H:i:s') . "\n";

        // Send email alert
        mail(
            getenv('ADMIN_EMAIL') ?: 'admin@yourdomain.com',
            'Deployment Failure Alert',
            $message
        );
    }
}
```

## Summary: Secure Deployment Rules

1. **Always use HTTPS** - Redirect HTTP traffic and use strong SSL/TLS
2. **Set restrictive file permissions** - Follow principle of least privilege
3. **Hide sensitive files** - Block access to .env, logs, and configuration files
4. **Configure firewall properly** - Close unnecessary ports and implement rate limiting
5. **Use automated deployment** - Implement CI/CD with security checks
6. **Monitor deployments** - Log deployment activities and monitor health
7. **Have rollback procedures** - Be able to quickly revert problematic deployments
8. **Regular security audits** - Scan for vulnerabilities after deployment
9. **Implement least privilege** - Run services with minimal required permissions
10. **Keep systems updated** - Apply security patches regularly

## Next Steps

Now that you understand secure deployment, explore:

- **[API Security Basics](APISecurityBasics.md)** - Secure API authentication and rate limiting
- **[Error Handling & Logging](ErrorHandlingLogging.md)** - Secure error management
- **[Dependency Security](DependencySecurity.md)** - Secure package management

Remember: Security is not just about code - deployment configuration is equally critical. A perfectly secure application can be compromised through misconfigured servers!