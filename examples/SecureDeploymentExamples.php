<?php

/**
 * Secure Deployment Examples: HTTPS, File Permissions, Firewall, and Security Scripts
 *
 * Practical examples for secure server deployment and configuration
 */

declare(strict_types=1);

// =============================================================================
// 1. HTTPS CONFIGURATION EXAMPLES
// =============================================================================

class HTTPSConfiguration
{
    /**
     * Generate self-signed SSL certificate for development
     */
    public static function generateSelfSignedCertificate(string $domain, string $outputDir): void
    {
        $keyFile = $outputDir . '/' . $domain . '.key';
        $certFile = $outputDir . '/' . $domain . '.crt';
        $csrFile = $outputDir . '/' . $domain . '.csr';

        // Generate private key
        exec("openssl genrsa -out {$keyFile} 2048", $output, $returnVar);
        if ($returnVar !== 0) {
            throw new RuntimeException('Failed to generate private key');
        }

        // Generate certificate signing request
        $config = "
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = State
L = City
O = Organization
OU = Department
CN = {$domain}

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = {$domain}
DNS.2 = www.{$domain}
";

        file_put_contents($outputDir . '/openssl.cnf', $config);

        exec("openssl req -new -key {$keyFile} -out {$csrFile} -config {$outputDir}/openssl.cnf", $output, $returnVar);
        if ($returnVar !== 0) {
            throw new RuntimeException('Failed to generate CSR');
        }

        // Generate self-signed certificate
        exec("openssl x509 -req -days 365 -in {$csrFile} -signkey {$keyFile} -out {$certFile} -extensions v3_req -extfile {$outputDir}/openssl.cnf", $output, $returnVar);
        if ($returnVar !== 0) {
            throw new RuntimeException('Failed to generate certificate');
        }

        // Clean up config file
        unlink($outputDir . '/openssl.cnf');

        echo "✅ Self-signed certificate generated successfully\n";
        echo "Key: {$keyFile}\n";
        echo "Certificate: {$certFile}\n";
    }

    /**
     * Check SSL certificate validity
     */
    public static function checkCertificate(string $domain, int $port = 443): array
    {
        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => false,
                'verify_peer_name' => false
            ]
        ]);

        $socket = stream_socket_client("ssl://{$domain}:{$port}", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);

        if (!$socket) {
            throw new RuntimeException("Failed to connect: {$errstr} ({$errno})");
        }

        $params = stream_context_get_params($socket);
        $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate']);

        stream_socket_shutdown($socket, STREAM_SHUT_RDWR);

        return [
            'subject' => $cert['subject']['CN'] ?? 'Unknown',
            'issuer' => $cert['issuer']['CN'] ?? 'Unknown',
            'valid_from' => date('Y-m-d H:i:s', $cert['validFrom_time_t']),
            'valid_to' => date('Y-m-d H:i:s', $cert['validTo_time_t']),
            'is_expired' => $cert['validTo_time_t'] < time(),
            'days_remaining' => ceil(($cert['validTo_time_t'] - time()) / 86400),
            'serial_number' => $cert['serialNumberHex'] ?? 'Unknown'
        ];
    }

    /**
     * Configure HSTS preload list check
     */
    public static function checkHSTSPreloadEligibility(string $domain): array
    {
        $issues = [];

        // Check HTTPS redirect
        $httpContext = stream_context_create(['http' => ['method' => 'GET', 'timeout' => 5]]);
        $httpResponse = @file_get_contents("http://{$domain}", false, $httpContext);

        if ($httpResponse === false) {
            $issues[] = 'HTTP site not accessible';
        } else {
            $headers = $this->parseHeaders($http_response_header ?? []);
            if (!isset($headers['location']) || !str_starts_with($headers['location'], 'https://')) {
                $issues[] = 'HTTP does not redirect to HTTPS';
            }
        }

        // Check HTTPS certificate
        try {
            $certInfo = self::checkCertificate($domain);
            if ($certInfo['is_expired']) {
                $issues[] = 'SSL certificate is expired';
            }
        } catch (Exception $e) {
            $issues[] = 'SSL certificate check failed: ' . $e->getMessage();
        }

        // Check HSTS header
        $httpsContext = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => 5,
                'header' => "Host: {$domain}\r\n"
            ]
        ]);

        $httpsResponse = @file_get_contents("https://{$domain}", false, $httpsContext);
        $headers = $this->parseHeaders($http_response_header ?? []);

        if (!isset($headers['strict-transport-security'])) {
            $issues[] = 'HSTS header not present';
        } else {
            $hsts = $headers['strict-transport-security'];
            if (!str_contains($hsts, 'max-age=31536000') ||
                !str_contains($hsts, 'includeSubDomains') ||
                !str_contains($hsts, 'preload')) {
                $issues[] = 'HSTS header does not meet preload requirements';
            }
        }

        return [
            'eligible' => empty($issues),
            'issues' => $issues
        ];
    }

    private function parseHeaders(array $headers): array
    {
        $parsed = [];
        foreach ($headers as $header) {
            if (strpos($header, ':') !== false) {
                [$key, $value] = explode(':', $header, 2);
                $parsed[strtolower(trim($key))] = trim($value);
            }
        }
        return $parsed;
    }
}

// =============================================================================
// 2. FILE PERMISSIONS MANAGEMENT EXAMPLES
// =============================================================================

class SecureFilePermissions
{
    private string $webRoot;
    private string $webUser;
    private string $webGroup;

    public function __construct(string $webRoot, string $webUser = 'www-data', string $webGroup = 'www-data')
    {
        $this->webRoot = rtrim($webRoot, '/');
        $this->webUser = $webUser;
        $this->webGroup = $webGroup;
    }

    /**
     * Set secure permissions for Laravel application
     */
    public function setLaravelPermissions(): void
    {
        $this->log("🔒 Setting Laravel permissions for {$this->webRoot}");

        // Set ownership
        $this->setOwnership($this->webRoot, $this->webUser, $this->webGroup);

        // Set directory permissions (755)
        $this->setDirectoryPermissions($this->webRoot, 0755, [
            'storage',
            'bootstrap/cache'
        ]);

        // Set file permissions (644)
        $this->setFilePermissions($this->webRoot, 0644);

        // Special permissions for sensitive areas
        $this->setRestrictedPermissions("{$this->webRoot}/.env", 0600);
        $this->setWritablePermissions("{$this->webRoot}/storage", 0775);
        $this->setWritablePermissions("{$this->webRoot}/bootstrap/cache", 0775);

        // Make artisan executable
        $this->setExecutablePermissions("{$this->webRoot}/artisan", 0755);

        $this->log("✅ Laravel permissions set successfully");
    }

    /**
     * Audit current permissions
     */
    public function auditPermissions(): array
    {
        $issues = [];

        $this->log("🔍 Auditing file permissions...");

        // Check .env file
        $envFile = $this->webRoot . '/.env';
        if (file_exists($envFile)) {
            $perms = fileperms($envFile) & 0777;
            if ($perms !== 0600) {
                $issues[] = ".env file has insecure permissions: " . decoct($perms) . " (should be 600)";
            }
        }

        // Check for world-writable files
        $worldWritable = $this->findWorldWritableFiles($this->webRoot);
        if (!empty($worldWritable)) {
            $issues[] = "Found world-writable files: " . implode(', ', array_slice($worldWritable, 0, 5));
        }

        // Check storage permissions
        $storageDir = $this->webRoot . '/storage';
        if (is_dir($storageDir)) {
            $perms = fileperms($storageDir) & 0777;
            if ($perms < 0755) {
                $issues[] = "Storage directory permissions too restrictive: " . decoct($perms);
            }
        }

        // Check ownership
        $incorrectOwner = $this->findIncorrectOwnership($this->webRoot);
        if (!empty($incorrectOwner)) {
            $issues[] = "Found files not owned by {$this->webUser}: " . count($incorrectOwner) . " files";
        }

        return $issues;
    }

    /**
     * Fix common permission issues
     */
    public function fixPermissionIssues(): void
    {
        $issues = $this->auditPermissions();

        if (empty($issues)) {
            $this->log("✅ No permission issues found");
            return;
        }

        $this->log("🔧 Fixing permission issues...");

        // Fix .env permissions
        $envFile = $this->webRoot . '/.env';
        if (file_exists($envFile)) {
            chmod($envFile, 0600);
            $this->log("✅ Fixed .env permissions");
        }

        // Fix world-writable files
        $worldWritable = $this->findWorldWritableFiles($this->webRoot);
        foreach ($worldWritable as $file) {
            chmod($file, 0644);
        }
        if (!empty($worldWritable)) {
            $this->log("✅ Fixed " . count($worldWritable) . " world-writable files");
        }

        // Fix ownership
        $this->setOwnership($this->webRoot, $this->webUser, $this->webGroup);
        $this->log("✅ Fixed file ownership");

        $this->log("🎉 Permission issues resolved");
    }

    private function setOwnership(string $path, string $user, string $group): void
    {
        exec("chown -R {$user}:{$group} {$path} 2>/dev/null", $output, $returnVar);
        if ($returnVar !== 0) {
            throw new RuntimeException("Failed to set ownership for {$path}");
        }
    }

    private function setDirectoryPermissions(string $path, int $perms, array $excludeDirs = []): void
    {
        $excludePattern = '';
        if (!empty($excludeDirs)) {
            $excludePattern = ' -not -path "*/' . implode('/*" -not -path "*/', $excludeDirs) . '/*"';
        }

        exec("find {$path} -type d{$excludePattern} -exec chmod {$perms} {} \\;", $output, $returnVar);
        if ($returnVar !== 0) {
            throw new RuntimeException("Failed to set directory permissions");
        }
    }

    private function setFilePermissions(string $path, int $perms): void
    {
        exec("find {$path} -type f -exec chmod {$perms} {} \\;", $output, $returnVar);
        if ($returnVar !== 0) {
            throw new RuntimeException("Failed to set file permissions");
        }
    }

    private function setRestrictedPermissions(string $path, int $perms): void
    {
        if (file_exists($path)) {
            chmod($path, $perms);
        }
    }

    private function setWritablePermissions(string $path, int $perms): void
    {
        if (is_dir($path)) {
            exec("chmod {$perms} {$path}");
            exec("find {$path} -type d -exec chmod {$perms} {} \\;");
            exec("find {$path} -type f -exec chmod " . ($perms & 0666) . " {} \\;");
        }
    }

    private function setExecutablePermissions(string $path, int $perms): void
    {
        if (file_exists($path)) {
            chmod($path, $perms);
        }
    }

    private function findWorldWritableFiles(string $path): array
    {
        exec("find {$path} -type f -perm -002 2>/dev/null", $output);
        return $output;
    }

    private function findIncorrectOwnership(string $path): array
    {
        exec("find {$path} -not -user {$this->webUser} -type f 2>/dev/null | head -20", $output);
        return $output;
    }

    private function log(string $message): void
    {
        echo $message . "\n";
    }
}

// =============================================================================
// 3. FIREWALL CONFIGURATION EXAMPLES
// =============================================================================

class FirewallManager
{
    /**
     * Configure UFW firewall rules
     */
    public static function configureUFW(array $rules): void
    {
        // Reset UFW
        exec('sudo ufw --force reset', $output, $returnVar);

        // Set default policies
        exec('sudo ufw default deny incoming', $output, $returnVar);
        exec('sudo ufw default allow outgoing', $output, $returnVar);

        // Apply custom rules
        foreach ($rules as $rule) {
            $command = 'sudo ufw ' . $rule;
            exec($command, $output, $returnVar);
            if ($returnVar !== 0) {
                throw new RuntimeException("Failed to apply firewall rule: {$rule}");
            }
        }

        // Enable UFW
        exec('sudo ufw --force enable', $output, $returnVar);
        if ($returnVar !== 0) {
            throw new RuntimeException('Failed to enable UFW');
        }

        echo "✅ UFW firewall configured successfully\n";
    }

    /**
     * Get UFW status
     */
    public static function getUFWStatus(): array
    {
        exec('sudo ufw status verbose', $output, $returnVar);

        return [
            'status' => $returnVar === 0 ? 'active' : 'inactive',
            'rules' => $output
        ];
    }

    /**
     * Configure iptables firewall
     */
    public static function configureIPTables(): void
    {
        $rules = [
            '# Flush existing rules',
            'iptables -F',
            'iptables -X',
            'iptables -t nat -F',
            'iptables -t nat -X',
            'iptables -t mangle -F',
            'iptables -t mangle -X',

            '# Default policies',
            'iptables -P INPUT DROP',
            'iptables -P FORWARD DROP',
            'iptables -P OUTPUT ACCEPT',

            '# Allow loopback',
            'iptables -A INPUT -i lo -j ACCEPT',

            '# Allow established connections',
            'iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',

            '# Allow SSH with rate limiting',
            'iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set',
            'iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP',
            'iptables -A INPUT -p tcp --dport 22 -j ACCEPT',

            '# Allow HTTP and HTTPS',
            'iptables -A INPUT -p tcp --dport 80 -j ACCEPT',
            'iptables -A INPUT -p tcp --dport 443 -j ACCEPT',

            '# Allow ping',
            'iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT',

            '# Log dropped packets',
            'iptables -A INPUT -j LOG --log-prefix "Dropped: " --log-level 4'
        ];

        foreach ($rules as $rule) {
            if (str_starts_with($rule, '#')) {
                continue; // Skip comments
            }

            exec("sudo {$rule}", $output, $returnVar);
            if ($returnVar !== 0) {
                throw new RuntimeException("Failed to apply iptables rule: {$rule}");
            }
        }

        // Save rules
        exec('sudo iptables-save > /etc/iptables/rules.v4', $output, $returnVar);

        echo "✅ iptables firewall configured successfully\n";
    }

    /**
     * Configure Fail2Ban
     */
    public static function configureFail2Ban(): void
    {
        $config = "
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600

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

[php-url-fopen]
enabled = true
port = http,https
filter = php-url-fopen
logpath = /var/log/apache2/access.log
maxretry = 2
";

        file_put_contents('/tmp/jail.local', $config);
        exec('sudo mv /tmp/jail.local /etc/fail2ban/jail.local', $output, $returnVar);

        if ($returnVar !== 0) {
            throw new RuntimeException('Failed to configure Fail2Ban');
        }

        // Restart Fail2Ban
        exec('sudo systemctl restart fail2ban', $output, $returnVar);

        echo "✅ Fail2Ban configured successfully\n";
    }
}

// =============================================================================
// 4. DEPLOYMENT SECURITY SCRIPTS
// =============================================================================

class DeploymentSecurity
{
    private string $projectRoot;
    private string $backupDir;
    private array $config;

    public function __construct(string $projectRoot, array $config = [])
    {
        $this->projectRoot = rtrim($projectRoot, '/');
        $this->backupDir = $config['backup_dir'] ?? '/var/backups';
        $this->config = array_merge([
            'health_check_url' => 'http://localhost/health-check',
            'max_backup_age_days' => 7,
            'required_space_mb' => 100,
        ], $config);
    }

    /**
     * Perform secure deployment
     */
    public function deploy(array $deploymentData): bool
    {
        $this->log("🚀 Starting secure deployment...");

        try {
            // Pre-deployment checks
            $this->runPreDeploymentChecks();

            // Create backup
            $backupPath = $this->createBackup();

            // Deploy application
            $this->deployApplication($deploymentData);

            // Set secure permissions
            $this->setSecurePermissions();

            // Run post-deployment tasks
            $this->runPostDeploymentTasks();

            // Health check
            if (!$this->runHealthCheck()) {
                throw new RuntimeException('Health check failed');
            }

            // Log successful deployment
            $this->logDeployment($deploymentData, 'success');

            $this->log("🎉 Deployment completed successfully!");
            return true;

        } catch (Exception $e) {
            $this->log("❌ Deployment failed: " . $e->getMessage());

            // Attempt rollback
            $this->rollback($backupPath);

            // Log failed deployment
            $this->logDeployment($deploymentData, 'failed', $e->getMessage());

            return false;
        }
    }

    private function runPreDeploymentChecks(): void
    {
        $this->log("🔍 Running pre-deployment checks...");

        // Check available disk space
        $availableSpace = disk_free_space('/') / 1024 / 1024; // MB
        if ($availableSpace < $this->config['required_space_mb']) {
            throw new RuntimeException("Insufficient disk space: {$availableSpace}MB available");
        }

        // Check if running as root (dangerous)
        if (posix_getuid() === 0) {
            throw new RuntimeException('Do not run deployment as root');
        }

        // Check if required tools are available
        $requiredTools = ['composer', 'npm', 'php'];
        foreach ($requiredTools as $tool) {
            if (!command_exists($tool)) {
                throw new RuntimeException("Required tool not found: {$tool}");
            }
        }

        $this->log("✅ Pre-deployment checks passed");
    }

    private function createBackup(): string
    {
        $this->log("💾 Creating backup...");

        $timestamp = date('Y-m-d_H-i-s');
        $backupPath = $this->backupDir . '/backup_' . $timestamp;

        // Ensure backup directory exists
        if (!is_dir($this->backupDir)) {
            mkdir($this->backupDir, 0755, true);
        }

        // Create backup
        exec("cp -r {$this->projectRoot} {$backupPath}", $output, $returnVar);
        if ($returnVar !== 0) {
            throw new RuntimeException('Failed to create backup');
        }

        $this->log("✅ Backup created: {$backupPath}");
        return $backupPath;
    }

    private function deployApplication(array $deploymentData): void
    {
        $this->log("📦 Deploying application...");

        $sourceDir = $deploymentData['source_dir'] ?? '/tmp/deployment';

        if (!is_dir($sourceDir)) {
            throw new RuntimeException("Source directory not found: {$sourceDir}");
        }

        // Remove old files (keep important data)
        $this->preserveDataDuringDeployment();

        // Copy new files
        exec("cp -r {$sourceDir}/* {$this->projectRoot}/", $output, $returnVar);
        if ($returnVar !== 0) {
            throw new RuntimeException('Failed to copy application files');
        }

        $this->log("✅ Application deployed");
    }

    private function preserveDataDuringDeployment(): void
    {
        // Preserve .env file
        $envBackup = '/tmp/.env.backup';
        if (file_exists($this->projectRoot . '/.env')) {
            copy($this->projectRoot . '/.env', $envBackup);
        }

        // Preserve storage directory
        $storageBackup = '/tmp/storage.backup';
        if (is_dir($this->projectRoot . '/storage')) {
            exec("cp -r {$this->projectRoot}/storage {$storageBackup}", $output, $returnVar);
        }
    }

    private function setSecurePermissions(): void
    {
        $this->log("🔒 Setting secure permissions...");

        $permissions = new SecureFilePermissions($this->projectRoot);
        $permissions->setLaravelPermissions();

        $this->log("✅ Permissions set");
    }

    private function runPostDeploymentTasks(): void
    {
        $this->log("⚙️ Running post-deployment tasks...");

        $oldDir = getcwd();
        chdir($this->projectRoot);

        try {
            // Install PHP dependencies
            exec('composer install --no-dev --optimize-autoloader', $output, $returnVar);
            if ($returnVar !== 0) {
                throw new RuntimeException('Composer install failed');
            }

            // Install Node dependencies
            exec('npm ci --production', $output, $returnVar);
            if ($returnVar !== 0) {
                throw new RuntimeException('NPM install failed');
            }

            // Run database migrations
            exec('php artisan migrate --force', $output, $returnVar);
            if ($returnVar !== 0) {
                throw new RuntimeException('Database migration failed');
            }

            // Clear and cache Laravel
            exec('php artisan config:cache', $output, $returnVar);
            exec('php artisan route:cache', $output, $returnVar);
            exec('php artisan view:cache', $output, $returnVar);

            // Build assets
            exec('npm run production', $output, $returnVar);
            if ($returnVar !== 0) {
                throw new RuntimeException('Asset building failed');
            }

        } finally {
            chdir($oldDir);
        }

        $this->log("✅ Post-deployment tasks completed");
    }

    private function runHealthCheck(): bool
    {
        $this->log("🏥 Running health checks...");

        $url = $this->config['health_check_url'];
        $context = stream_context_create([
            'http' => [
                'timeout' => 10,
                'ignore_errors' => true
            ]
        ]);

        $response = @file_get_contents($url, false, $context);

        if ($response === false) {
            return false;
        }

        // Check if response contains success indicator
        return str_contains($response, 'OK') || str_contains($response, 'healthy');
    }

    private function rollback(string $backupPath): void
    {
        $this->log("🔄 Rolling back deployment...");

        try {
            // Remove failed deployment
            exec("rm -rf {$this->projectRoot}/*", $output, $returnVar);

            // Restore backup
            exec("cp -r {$backupPath}/* {$this->projectRoot}/", $output, $returnVar);

            // Restore secure permissions
            $permissions = new SecureFilePermissions($this->projectRoot);
            $permissions->setLaravelPermissions();

            $this->log("✅ Rollback completed");

        } catch (Exception $e) {
            $this->log("❌ Rollback failed: " . $e->getMessage());
            throw new RuntimeException('Rollback failed: ' . $e->getMessage());
        }
    }

    private function logDeployment(array $data, string $status, string $error = null): void
    {
        $logEntry = [
            'timestamp' => date('c'),
            'status' => $status,
            'version' => $data['version'] ?? 'unknown',
            'commit_hash' => $data['commit_hash'] ?? null,
            'user' => $data['user'] ?? 'automated',
            'error' => $error
        ];

        $logFile = $this->projectRoot . '/storage/logs/deployment.log';
        $logDir = dirname($logFile);

        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }

        file_put_contents($logFile, json_encode($logEntry) . "\n", FILE_APPEND | LOCK_EX);
    }

    /**
     * Clean up old backups
     */
    public function cleanupOldBackups(): void
    {
        $this->log("🧹 Cleaning up old backups...");

        if (!is_dir($this->backupDir)) {
            return;
        }

        $maxAge = $this->config['max_backup_age_days'] * 24 * 60 * 60; // seconds
        $now = time();

        $backups = glob($this->backupDir . '/backup_*');
        $removed = 0;

        foreach ($backups as $backup) {
            if (is_dir($backup)) {
                $mtime = filemtime($backup);
                if (($now - $mtime) > $maxAge) {
                    exec("rm -rf {$backup}", $output, $returnVar);
                    if ($returnVar === 0) {
                        $removed++;
                    }
                }
            }
        }

        $this->log("✅ Removed {$removed} old backups");
    }

    private function log(string $message): void
    {
        echo "[" . date('H:i:s') . "] {$message}\n";
    }
}

// =============================================================================
// 5. APPLICATION FIREWALL EXAMPLES
// =============================================================================

class ApplicationFirewall
{
    private array $blacklist = [];
    private array $whitelist = [];
    private string $logFile;

    public function __construct(string $logFile = null)
    {
        $this->logFile = $logFile ?? '/var/log/application_firewall.log';
        $this->loadLists();
    }

    /**
     * Check if request should be blocked
     */
    public function shouldBlockRequest(): bool
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $requestUri = $_SERVER['REQUEST_URI'] ?? '';
        $queryString = $_SERVER['QUERY_STRING'] ?? '';

        // Check IP blacklist
        if ($this->isIPBlacklisted($ip)) {
            $this->logBlock('IP blacklist', $ip, $requestUri);
            return true;
        }

        // Check suspicious user agents
        if ($this->isSuspiciousUserAgent($userAgent)) {
            $this->logBlock('Suspicious user agent', $ip, $requestUri, $userAgent);
            return true;
        }

        // Check for malicious patterns
        if ($this->containsMaliciousPatterns($requestUri . '?' . $queryString)) {
            $this->logBlock('Malicious pattern', $ip, $requestUri);
            return true;
        }

        // Check request frequency (simple rate limiting)
        if ($this->isRateLimitExceeded($ip)) {
            $this->logBlock('Rate limit exceeded', $ip, $requestUri);
            return true;
        }

        return false;
    }

    /**
     * Add IP to blacklist
     */
    public function blacklistIP(string $ip): void
    {
        if (!in_array($ip, $this->blacklist)) {
            $this->blacklist[] = $ip;
            $this->saveLists();
        }
    }

    /**
     * Remove IP from blacklist
     */
    public function whitelistIP(string $ip): void
    {
        $this->blacklist = array_diff($this->blacklist, [$ip]);
        $this->saveLists();
    }

    private function loadLists(): void
    {
        // Load from database or file in production
        $this->blacklist = [
            '192.168.1.100',
            '10.0.0.1',
        ];

        $this->whitelist = [
            '127.0.0.1',
            '::1',
        ];
    }

    private function saveLists(): void
    {
        // Save to database or file in production
        // For demo, we'll just keep in memory
    }

    private function isIPBlacklisted(string $ip): bool
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
            '/masscan/i',
            '/zgrab/i',
        ];

        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                return true;
            }
        }

        return false;
    }

    private function containsMaliciousPatterns(string $input): bool
    {
        $maliciousPatterns = [
            '/\.\./', // Directory traversal
            '/<script/i', // XSS attempts
            '/javascript:/i', // JavaScript injection
            '/vbscript:/i', // VBScript injection
            '/data:/i', // Data URL injection
            '/union\s+select/i', // SQL injection
            '/eval\(/i', // Code injection
            '/base64_decode/i', // Obfuscation
            '/\x00/', // Null byte injection
            '/etc\/passwd/i', // File inclusion attempts
        ];

        foreach ($maliciousPatterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return true;
            }
        }

        return false;
    }

    private function isRateLimitExceeded(string $ip): bool
    {
        $cacheKey = 'rate_limit_' . md5($ip);
        $maxRequests = 100; // requests per minute
        $window = 60; // seconds

        // Simple file-based rate limiting (use Redis/Memcached in production)
        $cacheFile = sys_get_temp_dir() . '/' . $cacheKey;

        $now = time();
        $requests = [];

        if (file_exists($cacheFile)) {
            $requests = json_decode(file_get_contents($cacheFile), true) ?: [];
            // Remove old requests outside the window
            $requests = array_filter($requests, function($timestamp) use ($now, $window) {
                return ($now - $timestamp) < $window;
            });
        }

        // Add current request
        $requests[] = $now;

        // Check if limit exceeded
        if (count($requests) > $maxRequests) {
            return true;
        }

        // Save updated requests
        file_put_contents($cacheFile, json_encode($requests));

        return false;
    }

    private function logBlock(string $reason, string $ip, string $uri, string $extra = ''): void
    {
        $logEntry = sprintf(
            "[%s] BLOCKED - %s | IP: %s | URI: %s | User-Agent: %s | %s\n",
            date('Y-m-d H:i:s'),
            $reason,
            $ip,
            $uri,
            $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
            $extra
        );

        error_log($logEntry);

        // Also log to file if configured
        if ($this->logFile) {
            file_put_contents($this->logFile, $logEntry, FILE_APPEND | LOCK_EX);
        }
    }

    /**
     * Get firewall statistics
     */
    public function getStatistics(): array
    {
        // In production, read from log files or database
        return [
            'blacklisted_ips' => count($this->blacklist),
            'whitelisted_ips' => count($this->whitelist),
            'total_blocks_today' => 0, // Would count from logs
            'most_common_reason' => 'Rate limiting', // Would analyze logs
        ];
    }
}

// =============================================================================
// USAGE EXAMPLES AND TESTING
// =============================================================================

/*
// HTTPS CONFIGURATION
try {
    // Generate self-signed certificate
    HTTPSConfiguration::generateSelfSignedCertificate('example.com', '/etc/ssl/certs');

    // Check certificate validity
    $certInfo = HTTPSConfiguration::checkCertificate('example.com');
    print_r($certInfo);

    // Check HSTS preload eligibility
    $hstsCheck = HTTPSConfiguration::checkHSTSPreloadEligibility('example.com');
    print_r($hstsCheck);
} catch (Exception $e) {
    echo "HTTPS Error: " . $e->getMessage() . "\n";
}

// FILE PERMISSIONS
$permissions = new SecureFilePermissions('/var/www/myapp');
$issues = $permissions->auditPermissions();

if (!empty($issues)) {
    echo "Found permission issues:\n";
    foreach ($issues as $issue) {
        echo "- {$issue}\n";
    }
    $permissions->fixPermissionIssues();
} else {
    echo "No permission issues found\n";
}

// FIREWALL CONFIGURATION
$ufwRules = [
    'allow ssh',
    'allow 80',
    'allow 443',
    'allow from 192.168.1.0/24 to any port 3306'
];

try {
    FirewallManager::configureUFW($ufwRules);
    $status = FirewallManager::getUFWStatus();
    print_r($status);
} catch (Exception $e) {
    echo "Firewall Error: " . $e->getMessage() . "\n";
}

// DEPLOYMENT SECURITY
$deployment = new DeploymentSecurity('/var/www/myapp', [
    'backup_dir' => '/var/backups',
    'health_check_url' => 'http://localhost/health-check'
]);

$deploymentData = [
    'version' => '1.2.3',
    'commit_hash' => 'abc123def456',
    'user' => 'deployer',
    'source_dir' => '/tmp/deployment'
];

$success = $deployment->deploy($deploymentData);
echo $success ? "Deployment successful\n" : "Deployment failed\n";

// Clean up old backups
$deployment->cleanupOldBackups();

// APPLICATION FIREWALL
$firewall = new ApplicationFirewall('/var/log/app_firewall.log');

// In your application bootstrap
if ($firewall->shouldBlockRequest()) {
    http_response_code(403);
    echo "Access Denied";
    exit;
}

// Block suspicious IP
$firewall->blacklistIP('192.168.1.100');

// Get statistics
$stats = $firewall->getStatistics();
print_r($stats);
*/
?>
