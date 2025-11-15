# Secure Configuration

## Why Configuration Security Matters

Application configuration contains sensitive information that attackers target:

- **Database credentials** - Access to data
- **API keys** - Unauthorized service access
- **Encryption keys** - Data decryption
- **Debug information** - System reconnaissance
- **Server details** - Attack planning

Poor configuration security is responsible for many data breaches.

## Environment Variables (.env files)

### The Problem with .env Files

Laravel and many PHP frameworks use `.env` files to store configuration. These files are often:

- **Committed to version control** (accidentally)
- **Readable by web server** (misconfiguration)
- **Exposed in error messages** (debug mode)

### Secure .env File Management

#### 1. Never Commit .env Files

```bash
# .gitignore should always include:
.env
.env.local
.env.production
.env.staging

# Never commit these files!
```

#### 2. Secure File Permissions

```bash
# Set restrictive permissions on .env files
chmod 600 .env
chown www-data:www-data .env

# Ensure web server cannot read .env directly
# Place .env outside web root if possible
```

#### 3. Use Environment-Specific Configurations

```bash
# Directory structure
project/
├── .env.example          # Template (safe to commit)
├── .env.local           # Local development
├── .env.staging         # Staging environment
└── .env.production      # Production environment
```

#### 4. Encrypt Sensitive Values

```php
<?php
// Don't store plain text secrets
// BAD:
DB_PASSWORD=mysecretpassword
API_KEY=sk_live_123456789

// GOOD: Use encrypted values or environment variables
DB_PASSWORD=${DB_PASSWORD_ENCRYPTED}
API_KEY=${API_KEY_ENCRYPTED}
```

### Laravel .env Security

#### Laravel Environment Detection

```php
<?php
// config/app.php - Secure environment detection
'env' => env('APP_ENV', 'production'),

// Ensure production environment is properly detected
```

#### Secure Laravel Configuration

```php
<?php
// config/app.php - Production settings
'debug' => env('APP_DEBUG', false), // NEVER true in production
'env' => env('APP_ENV', 'production'),

// config/database.php - Secure database config
'connections' => [
    'mysql' => [
        'host' => env('DB_HOST', '127.0.0.1'),
        'database' => env('DB_DATABASE'),
        'username' => env('DB_USERNAME'),
        'password' => env('DB_PASSWORD'),
        'charset' => 'utf8mb4',
        'options' => [
            PDO::MYSQL_ATTR_SSL_CA => env('MYSQL_SSL_CA'), // Use SSL
            PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => true,
        ],
    ],
],
```

## Debug Mode Security

### The Dangers of Debug Mode

Debug mode exposes sensitive information:

```php
// Debug enabled - DANGEROUS in production
APP_DEBUG=true

// Exposed information:
- Full file paths
- Database queries with parameters
- Session data
- Environment variables
- Stack traces with sensitive data
```

### Secure Debug Configuration

#### Laravel Debug Management

```php
<?php
// config/app.php
'debug' => env('APP_DEBUG', false),

// Bootstrap/app.php - Environment-specific debug
$app->useEnvironmentPath(__DIR__.'/../');
$app->loadEnvironmentFrom('.env');

// Only enable debug for specific environments
if ($app->environment(['local', 'development'])) {
    $app->make('config')->set('app.debug', true);
}
```

#### PHP Error Reporting

```php
<?php
// Production error reporting - hide sensitive info
ini_set('display_errors', '0');          // Don't display errors
ini_set('display_startup_errors', '0');  // Hide startup errors
error_reporting(E_ALL & ~E_DEPRECATED); // Log all but deprecated

// Development error reporting - show everything
if (getenv('APP_ENV') === 'development') {
    ini_set('display_errors', '1');
    ini_set('display_startup_errors', '1');
    error_reporting(E_ALL);
}
```

#### Custom Error Handler

```php
<?php
class SecureErrorHandler
{
    public static function setup(): void
    {
        // Custom error handler
        set_error_handler([self::class, 'handleError']);

        // Custom exception handler
        set_exception_handler([self::class, 'handleException']);

        // Fatal error handler
        register_shutdown_function([self::class, 'handleShutdown']);
    }

    public static function handleError(int $errno, string $errstr, string $errfile, int $errline): bool
    {
        // Log error securely
        self::logError('PHP Error', [
            'errno' => $errno,
            'errstr' => self::sanitizeErrorMessage($errstr),
            'errfile' => basename($errfile), // Don't expose full paths
            'errline' => $errline,
        ]);

        // Don't display errors in production
        if (getenv('APP_ENV') === 'production') {
            return true; // Prevent default error handler
        }

        return false; // Use default error handler in development
    }

    public static function handleException(Throwable $exception): void
    {
        self::logError('Uncaught Exception', [
            'message' => self::sanitizeErrorMessage($exception->getMessage()),
            'file' => basename($exception->getFile()),
            'line' => $exception->getLine(),
            'trace' => self::sanitizeStackTrace($exception->getTraceAsString()),
        ]);

        // Show user-friendly error page
        if (getenv('APP_ENV') === 'production') {
            http_response_code(500);
            echo self::getErrorPage();
            exit;
        }

        // Re-throw in development
        throw $exception;
    }

    public static function handleShutdown(): void
    {
        $error = error_get_last();
        if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
            self::logError('Fatal Error', [
                'message' => self::sanitizeErrorMessage($error['message']),
                'file' => basename($error['file']),
                'line' => $error['line'],
            ]);

            if (getenv('APP_ENV') === 'production') {
                http_response_code(500);
                echo self::getErrorPage();
            }
        }
    }

    private static function sanitizeErrorMessage(string $message): string
    {
        // Remove sensitive information from error messages
        $patterns = [
            '/(password|passwd|pwd)[\'"]?\s*[:=]\s*[\'"][^\'"]*[\'"]/i',
            '/(key|token|secret)[\'"]?\s*[:=]\s*[\'"][^\'"]*[\'"]/i',
            '/(mysql|database).*?@/i',
        ];

        foreach ($patterns as $pattern) {
            $message = preg_replace($pattern, '[REDACTED]', $message);
        }

        return $message;
    }

    private static function sanitizeStackTrace(string $trace): string
    {
        // Remove full paths from stack trace
        $lines = explode("\n", $trace);
        $sanitized = [];

        foreach ($lines as $line) {
            // Replace full paths with relative paths
            $line = preg_replace('/\/var\/www\/[^)]*\//', '/app/', $line);
            $sanitized[] = $line;
        }

        return implode("\n", $sanitized);
    }

    private static function logError(string $type, array $data): void
    {
        $logMessage = sprintf(
            "[%s] %s in %s:%d - %s",
            date('Y-m-d H:i:s'),
            $type,
            $data['file'] ?? 'unknown',
            $data['line'] ?? 0,
            $data['message'] ?? 'No message'
        );

        error_log($logMessage);
    }

    private static function getErrorPage(): string
    {
        return <<<'HTML'
<!DOCTYPE html>
<html>
<head>
    <title>Server Error</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .error { color: #d9534f; font-size: 24px; }
    </style>
</head>
<body>
    <h1 class="error">Oops! Something went wrong.</h1>
    <p>We're working to fix this issue. Please try again later.</p>
    <p>If the problem persists, contact support.</p>
</body>
</html>
HTML;
    }
}

// Setup secure error handling
SecureErrorHandler::setup();
```

## PHP Version Hiding

### Why Hide PHP Version?

PHP version disclosure helps attackers:

- **Identify vulnerabilities** in specific PHP versions
- **Target known exploits** for that version
- **Plan attacks** based on PHP capabilities

### Hiding PHP Version

#### 1. PHP Configuration

```ini
; php.ini - Hide PHP version
expose_php = Off
```

#### 2. Web Server Configuration

```apache
# Apache .htaccess
<IfModule mod_headers.c>
    Header unset X-Powered-By
    Header unset Server
</IfModule>

# Nginx configuration
server {
    # Hide nginx version
    server_tokens off;

    # Hide PHP version
    fastcgi_hide_header X-Powered-By;
    fastcgi_hide_header Server;
}
```

#### 3. PHP Code Headers

```php
<?php
// Remove PHP version from headers
header_remove('X-Powered-By');
header_remove('Server');

// Custom server header (optional)
header('Server: Web Server');
```

#### 4. Laravel Specific

```php
<?php
// In Laravel middleware
class SecurityHeadersMiddleware
{
    public function handle($request, $next)
    {
        $response = $next($request);

        // Remove PHP/Laravel version headers
        $response->headers->remove('X-Powered-By');
        $response->headers->remove('Server');

        return $response;
    }
}
```

## Production PHP Configuration

### Secure php.ini Settings

```ini
; php.ini - Production Security Settings

; Error Handling
display_errors = Off
display_startup_errors = Off
error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT
log_errors = On
error_log = /var/log/php_errors.log

; File Uploads
file_uploads = On
upload_max_filesize = 10M
max_file_uploads = 5
post_max_size = 12M

; Session Security
session.cookie_secure = 1
session.cookie_httponly = 1
session.cookie_samesite = "Strict"
session.use_only_cookies = 1
session.gc_maxlifetime = 1440
session.save_path = "/var/secure/sessions"

; Resource Limits
max_execution_time = 30
max_input_time = 60
memory_limit = 128M

; Security
expose_php = Off
allow_url_fopen = Off
allow_url_include = Off
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source

; OpenSSL
openssl.cafile = /etc/ssl/certs/ca-certificates.crt

; Timezone
date.timezone = "UTC"
```

### PHP-FPM Configuration

```ini
; /etc/php/7.4/fpm/php-fpm.conf
[www]

; Security settings
security.limit_extensions = .php .php3 .php4 .php5 .php7

; Process management
pm = dynamic
pm.max_children = 50
pm.start_servers = 5
pm.min_spare_servers = 5
pm.max_spare_servers = 35

; Logging
log_level = notice
access.log = /var/log/php-fpm/access.log
```

### Opcache Security

```ini
; opcache.ini - Production settings
opcache.enable = 1
opcache.enable_cli = 0
opcache.memory_consumption = 256
opcache.max_accelerated_files = 7963
opcache.revalidate_freq = 0
opcache.validate_timestamps = 0 ; Set to 1 in development
opcache.save_comments = 0
opcache.enable_file_override = 0
```

## Database Configuration Security

### Secure Database Connections

```php
<?php
class SecureDatabaseConfig
{
    public static function getSecurePDO(string $env): PDO
    {
        $config = self::getDatabaseConfig($env);

        $dsn = sprintf(
            'mysql:host=%s;dbname=%s;charset=utf8mb4',
            $config['host'],
            $config['database']
        );

        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci',
            PDO::MYSQL_ATTR_SSL_CA => $config['ssl_ca'] ?? null,
            PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => true,
        ];

        return new PDO($dsn, $config['username'], $config['password'], $options);
    }

    private static function getDatabaseConfig(string $env): array
    {
        // Load from secure environment variables
        return [
            'host' => getenv('DB_HOST') ?: 'localhost',
            'database' => getenv('DB_NAME') ?: 'app_db',
            'username' => getenv('DB_USER'),
            'password' => getenv('DB_PASS'),
            'ssl_ca' => getenv('DB_SSL_CA'),
        ];
    }
}
```

### Laravel Database Security

```php
<?php
// config/database.php - Secure configuration
return [
    'connections' => [
        'mysql' => [
            'driver' => 'mysql',
            'host' => env('DB_HOST', '127.0.0.1'),
            'port' => env('DB_PORT', '3306'),
            'database' => env('DB_DATABASE'),
            'username' => env('DB_USERNAME'),
            'password' => env('DB_PASSWORD'),
            'unix_socket' => env('DB_SOCKET'),
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'prefix' => '',
            'strict' => true, // Strict mode for security
            'engine' => null,
            'options' => [
                PDO::MYSQL_ATTR_SSL_CA => env('MYSQL_SSL_CA'),
                PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => env('MYSQL_SSL_VERIFY_SERVER_CERT', true),
                PDO::ATTR_PERSISTENT => false, // Don't use persistent connections
            ],
        ],
    ],
];
```

## Application Configuration Security

### Secure API Keys Management

```php
<?php
class SecureApiKeyManager
{
    private static array $keys = [];

    public static function loadKeys(): void
    {
        // Load from secure environment variables
        self::$keys = [
            'stripe_secret' => getenv('STRIPE_SECRET_KEY'),
            'aws_access' => getenv('AWS_ACCESS_KEY_ID'),
            'aws_secret' => getenv('AWS_SECRET_ACCESS_KEY'),
            'jwt_secret' => getenv('JWT_SECRET'),
        ];

        // Validate required keys exist
        $required = ['stripe_secret', 'jwt_secret'];
        foreach ($required as $key) {
            if (empty(self::$keys[$key])) {
                throw new RuntimeException("Required configuration key missing: {$key}");
            }
        }
    }

    public static function getKey(string $name): ?string
    {
        return self::$keys[$name] ?? null;
    }

    public static function validateConfiguration(): array
    {
        $issues = [];

        // Check file permissions
        $envFile = __DIR__ . '/../.env';
        if (file_exists($envFile)) {
            $perms = fileperms($envFile) & 0777;
            if ($perms !== 0600) {
                $issues[] = '.env file has incorrect permissions (should be 600)';
            }
        }

        // Check debug mode
        if (getenv('APP_DEBUG') === 'true' && getenv('APP_ENV') === 'production') {
            $issues[] = 'Debug mode enabled in production';
        }

        // Check required environment variables
        $required = ['APP_KEY', 'DB_PASSWORD', 'REDIS_PASSWORD'];
        foreach ($required as $var) {
            if (empty(getenv($var))) {
                $issues[] = "Missing required environment variable: {$var}";
            }
        }

        return $issues;
    }
}
```

## Deployment Configuration

### Secure Deployment Script

```bash
#!/bin/bash
# secure-deploy.sh

set -e  # Exit on any error

echo "🚀 Starting secure deployment..."

# Check environment
if [ "$ENVIRONMENT" != "production" ]; then
    echo "❌ This script should only run in production"
    exit 1
fi

# Validate configuration
echo "🔍 Validating configuration..."
php artisan config:cache
php artisan route:cache
php artisan view:cache

# Check for security issues
echo "🛡️ Running security checks..."
if php artisan tinker --execute="echo app()->environment()" | grep -q "production"; then
    echo "✅ Environment correctly set to production"
else
    echo "❌ Environment not set to production"
    exit 1
fi

# Set secure permissions
echo "🔒 Setting secure permissions..."
find . -type f -name "*.php" -exec chmod 644 {} \;
find . -type d -exec chmod 755 {} \;
chmod 600 .env
chmod 600 storage/logs/*.log

# Clear sensitive caches
echo "🧹 Clearing sensitive data..."
php artisan config:clear
php artisan cache:clear
php artisan view:clear

# Health check
echo "🏥 Running health checks..."
curl -f -s http://localhost/health-check > /dev/null
if [ $? -eq 0 ]; then
    echo "✅ Application health check passed"
else
    echo "❌ Application health check failed"
    exit 1
fi

echo "🎉 Secure deployment completed successfully!"
```

### Configuration Validation

```php
<?php
// Laravel command to validate configuration
namespace App\Console\Commands;

use Illuminate\Console\Command;

class ValidateConfig extends Command
{
    protected $signature = 'config:validate';
    protected $description = 'Validate production configuration security';

    public function handle()
    {
        $this->info('🔍 Validating configuration security...');

        $issues = [];

        // Check debug mode
        if (config('app.debug') && app()->environment('production')) {
            $issues[] = 'Debug mode enabled in production';
        }

        // Check session security
        $sessionConfig = config('session');
        if (!$sessionConfig['secure']) {
            $issues[] = 'Session cookies not marked as secure';
        }
        if (!$sessionConfig['http_only']) {
            $issues[] = 'Session cookies not marked as http-only';
        }

        // Check database SSL
        $dbConfig = config('database.connections.mysql');
        if (empty($dbConfig['options'][PDO::MYSQL_ATTR_SSL_CA])) {
            $issues[] = 'Database not configured to use SSL';
        }

        // Report issues
        if (empty($issues)) {
            $this->info('✅ All configuration checks passed!');
            return 0;
        }

        foreach ($issues as $issue) {
            $this->error("❌ {$issue}");
        }

        return 1;
    }
}
```

## Monitoring and Alerting

### Configuration Change Monitoring

```php
<?php
class ConfigurationMonitor
{
    private static string $configHashFile = '/var/secure/config_hash.txt';

    public static function checkConfigurationChanges(): void
    {
        $currentHash = self::calculateConfigHash();

        if (file_exists(self::$configHashFile)) {
            $storedHash = trim(file_get_contents(self::$configHashFile));

            if ($storedHash !== $currentHash) {
                // Configuration changed - alert administrators
                self::alertConfigChange($storedHash, $currentHash);

                // Update stored hash
                file_put_contents(self::$configHashFile, $currentHash);
            }
        } else {
            // First run - store initial hash
            file_put_contents(self::$configHashFile, $currentHash);
        }
    }

    private static function calculateConfigHash(): string
    {
        $configFiles = [
            __DIR__ . '/../.env',
            __DIR__ . '/../config/app.php',
            __DIR__ . '/../config/database.php',
            '/etc/php/7.4/fpm/php-fpm.conf',
        ];

        $hashes = [];
        foreach ($configFiles as $file) {
            if (file_exists($file)) {
                $hashes[] = hash_file('sha256', $file);
            }
        }

        return hash('sha256', implode('', $hashes));
    }

    private static function alertConfigChange(string $oldHash, string $newHash): void
    {
        $message = sprintf(
            "Configuration change detected!\nOld hash: %s\nNew hash: %s\nTime: %s",
            $oldHash,
            $newHash,
            date('Y-m-d H:i:s')
        );

        // Log alert
        error_log("SECURITY ALERT: " . $message);

        // Send email alert (implement based on your needs)
        // mail('admin@example.com', 'Configuration Change Alert', $message);
    }
}
```

## Configuration Security Checklist

### Environment Variables
- [ ] .env files excluded from version control
- [ ] Secure file permissions (600) on .env files
- [ ] Environment-specific configuration files
- [ ] No sensitive data in .env files (use external vaults)

### Debug and Error Handling
- [ ] Debug mode disabled in production
- [ ] Custom error handlers that don't expose sensitive data
- [ ] Error messages sanitized of credentials and paths
- [ ] Error logging enabled with secure storage

### PHP Configuration
- [ ] PHP version not exposed in headers
- [ ] Secure php.ini settings for production
- [ ] Disabled dangerous PHP functions
- [ ] Proper resource limits set

### Application Security
- [ ] Secure session configuration
- [ ] Database connections use SSL
- [ ] API keys stored securely
- [ ] Configuration validation on startup

### Deployment Security
- [ ] Automated security checks in deployment
- [ ] Configuration validation scripts
- [ ] Secure file permissions set during deployment
- [ ] Configuration change monitoring

## Next Steps

Now that you understand secure configuration, explore:

- **[File Upload Security](FileUploadSecurity.md)** - Secure file handling
- **[Secure Headers](SecureHeaders.md)** - HTTP security headers
- **[Authentication & Password Handling](AuthenticationPasswordHandling.md)** - User security

Remember: Secure configuration is the foundation of application security. Regular audits and monitoring are essential to maintain security posture!
