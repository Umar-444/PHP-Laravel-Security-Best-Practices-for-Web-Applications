<?php

/**
 * Secure Configuration and Headers Examples
 *
 * Practical examples of secure application configuration and HTTP security headers
 */

declare(strict_types=1);

// =============================================================================
// 1. SECURE .ENV FILE MANAGEMENT
// =============================================================================

class SecureEnvManager
{
    private static array $encryptedKeys = [];

    /**
     * Load and validate environment configuration securely
     */
    public static function loadSecureConfig(): array
    {
        $config = [];

        // Required environment variables with validation
        $requiredVars = [
            'APP_ENV' => ['production', 'staging', 'development'],
            'APP_KEY' => null, // Any non-empty value
            'DB_HOST' => 'FILTER_VALIDATE_IP',
            'DB_NAME' => null,
            'DB_USER' => null,
            'DB_PASS' => null,
            'REDIS_HOST' => 'FILTER_VALIDATE_IP',
            'REDIS_PASS' => null,
        ];

        foreach ($requiredVars as $var => $validation) {
            $value = getenv($var);

            if ($value === false) {
                throw new RuntimeException("Required environment variable missing: {$var}");
            }

            // Type-specific validation
            if ($validation === 'FILTER_VALIDATE_IP' && !filter_var($value, FILTER_VALIDATE_IP)) {
                throw new RuntimeException("Invalid IP address for: {$var}");
            }

            if (is_array($validation) && !in_array($value, $validation)) {
                throw new RuntimeException("Invalid value for {$var}. Allowed: " . implode(', ', $validation));
            }

            $config[$var] = $value;
        }

        // Validate configuration consistency
        self::validateConfigConsistency($config);

        return $config;
    }

    /**
     * Validate configuration consistency across environment
     */
    private static function validateConfigConsistency(array $config): void
    {
        $env = $config['APP_ENV'];

        // Production-specific validations
        if ($env === 'production') {
            // Must use secure connections
            if (empty($config['DB_SSL_CA'] ?? getenv('DB_SSL_CA'))) {
                throw new RuntimeException('SSL required for database in production');
            }

            // Must have Redis password
            if (empty($config['REDIS_PASS'])) {
                throw new RuntimeException('Redis password required in production');
            }
        }

        // Development-specific validations
        if ($env === 'development') {
            // Allow insecure settings for development
            // But warn about security
            error_log('WARNING: Running in development mode with potentially insecure settings');
        }
    }

    /**
     * Securely store encrypted sensitive values
     */
    public static function setEncryptedValue(string $key, string $value): void
    {
        $encryptionKey = getenv('CONFIG_ENCRYPTION_KEY');
        if (!$encryptionKey) {
            throw new RuntimeException('CONFIG_ENCRYPTION_KEY not set');
        }

        $encrypted = self::encrypt($value, $encryptionKey);
        self::$encryptedKeys[$key] = $encrypted;
    }

    /**
     * Retrieve decrypted sensitive values
     */
    public static function getDecryptedValue(string $key): ?string
    {
        if (!isset(self::$encryptedKeys[$key])) {
            return null;
        }

        $encryptionKey = getenv('CONFIG_ENCRYPTION_KEY');
        if (!$encryptionKey) {
            throw new RuntimeException('CONFIG_ENCRYPTION_KEY not set');
        }

        return self::decrypt(self::$encryptedKeys[$key], $encryptionKey);
    }

    /**
     * Simple encryption/decryption (use proper encryption in production)
     */
    private static function encrypt(string $data, string $key): string
    {
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
        return base64_encode($iv . $encrypted);
    }

    private static function decrypt(string $data, string $key): string
    {
        $data = base64_decode($data);
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        return openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
    }

    /**
     * Generate secure .env template
     */
    public static function generateSecureEnvTemplate(): string
    {
        return <<<'ENV'
# Application Configuration
APP_NAME="Secure PHP App"
APP_ENV=production
APP_KEY=base64:your_app_key_here
APP_DEBUG=false
APP_URL=https://yourdomain.com

# Database Configuration
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=your_database
DB_USERNAME=your_db_user
DB_PASSWORD=your_secure_password
DB_SSL_CA=/etc/ssl/certs/ca-certificates.crt

# Session Configuration
SESSION_DRIVER=database
SESSION_LIFETIME=120
SESSION_ENCRYPT=false
SESSION_PATH=/
SESSION_DOMAIN=.yourdomain.com
SESSION_SECURE_COOKIE=true
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=strict

# Cache Configuration
CACHE_DRIVER=redis
REDIS_HOST=127.0.0.1
REDIS_PASSWORD=your_redis_password
REDIS_PORT=6379

# Queue Configuration
QUEUE_CONNECTION=redis

# Mail Configuration
MAIL_MAILER=smtp
MAIL_HOST=your_smtp_host
MAIL_PORT=587
MAIL_USERNAME=your_email@domain.com
MAIL_PASSWORD=your_secure_password
MAIL_ENCRYPTION=tls

# Encryption Keys (Keep these secure!)
CONFIG_ENCRYPTION_KEY=your_config_encryption_key
JWT_SECRET=your_jwt_secret_key

# Security Headers
SECURITY_HEADERS_ENABLED=true
CSP_ENABLED=true
HSTS_ENABLED=true

# Logging
LOG_CHANNEL=daily
LOG_LEVEL=error

# Backup Configuration
BACKUP_DISK=secure_backup
BACKUP_RETENTION_DAYS=30
ENV;
    }
}

// =============================================================================
// 2. SECURE ERROR HANDLING AND DEBUG MANAGEMENT
// =============================================================================

class SecureErrorHandler
{
    private static bool $debugMode = false;
    private static string $logFile = '/var/log/secure_app/errors.log';

    /**
     * Initialize secure error handling
     */
    public static function initialize(): void
    {
        // Set error reporting based on environment
        $environment = getenv('APP_ENV') ?: 'production';

        if ($environment === 'development') {
            self::$debugMode = true;
            error_reporting(E_ALL);
            ini_set('display_errors', '1');
            ini_set('display_startup_errors', '1');
        } else {
            self::$debugMode = false;
            error_reporting(E_ALL & ~E_DEPRECATED & ~E_STRICT);
            ini_set('display_errors', '0');
            ini_set('display_startup_errors', '0');
        }

        // Set custom error handlers
        set_error_handler([self::class, 'handleError']);
        set_exception_handler([self::class, 'handleException']);
        register_shutdown_function([self::class, 'handleShutdown']);

        // Ensure log file exists and is secure
        self::setupLogFile();
    }

    /**
     * Setup secure log file
     */
    private static function setupLogFile(): void
    {
        $logDir = dirname(self::$logFile);

        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }

        if (!file_exists(self::$logFile)) {
            touch(self::$logFile);
        }

        // Set secure permissions
        chmod(self::$logFile, 0600);
        chmod($logDir, 0755);
    }

    /**
     * Handle PHP errors
     */
    public static function handleError(int $errno, string $errstr, string $errfile, int $errline): bool
    {
        // Sanitize error message
        $sanitizedMessage = self::sanitizeErrorMessage($errstr);
        $safeFile = basename($errfile); // Don't expose full paths

        $errorInfo = [
            'type' => 'PHP Error',
            'level' => $errno,
            'message' => $sanitizedMessage,
            'file' => $safeFile,
            'line' => $errline,
            'timestamp' => date('Y-m-d H:i:s'),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        ];

        self::logError($errorInfo);

        // Return true to prevent default error handler in production
        return !self::$debugMode;
    }

    /**
     * Handle uncaught exceptions
     */
    public static function handleException(Throwable $exception): void
    {
        $errorInfo = [
            'type' => 'Uncaught Exception',
            'class' => get_class($exception),
            'message' => self::sanitizeErrorMessage($exception->getMessage()),
            'file' => basename($exception->getFile()),
            'line' => $exception->getLine(),
            'trace' => self::sanitizeStackTrace($exception->getTraceAsString()),
            'timestamp' => date('Y-m-d H:i:s'),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        ];

        self::logError($errorInfo);

        if (!self::$debugMode) {
            self::showErrorPage();
        } else {
            // Re-throw in development
            throw $exception;
        }
    }

    /**
     * Handle fatal errors
     */
    public static function handleShutdown(): void
    {
        $error = error_get_last();

        if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
            $errorInfo = [
                'type' => 'Fatal Error',
                'message' => self::sanitizeErrorMessage($error['message']),
                'file' => basename($error['file']),
                'line' => $error['line'],
                'timestamp' => date('Y-m-d H:i:s'),
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            ];

            self::logError($errorInfo);

            if (!self::$debugMode) {
                self::showErrorPage();
            }
        }
    }

    /**
     * Sanitize error messages to remove sensitive information
     */
    private static function sanitizeErrorMessage(string $message): string
    {
        // Remove passwords, keys, and sensitive data
        $patterns = [
            '/password[\'"]?\s*[:=]\s*[\'"][^\'"]*[\'"]/i',
            '/key[\'"]?\s*[:=]\s*[\'"][^\'"]*[\'"]/i',
            '/secret[\'"]?\s*[:=]\s*[\'"][^\'"]*[\'"]/i',
            '/token[\'"]?\s*[:=]\s*[\'"][^\'"]*[\'"]/i',
            '/(mysql|pgsql|mongodb).*?@/i', // Database connection strings
            '/\/var\/www\/[^)]*\//', // Full paths
        ];

        foreach ($patterns as $pattern) {
            $message = preg_replace($pattern, '[REDACTED]', $message);
        }

        return $message;
    }

    /**
     * Sanitize stack trace to remove sensitive paths
     */
    private static function sanitizeStackTrace(string $trace): string
    {
        // Replace full paths with relative paths
        $trace = preg_replace('/\/var\/www\/[^)]*\//', '/app/', $trace);
        $trace = preg_replace('/\/home\/[^\/]*\//', '/home/user/', $trace);

        return $trace;
    }

    /**
     * Log error securely
     */
    private static function logError(array $errorInfo): void
    {
        $logMessage = sprintf(
            "[%s] %s: %s in %s:%d - IP: %s\n",
            $errorInfo['timestamp'],
            $errorInfo['type'],
            $errorInfo['message'],
            $errorInfo['file'],
            $errorInfo['line'] ?? 0,
            $errorInfo['ip']
        );

        // Add stack trace if available
        if (isset($errorInfo['trace'])) {
            $logMessage .= "Stack Trace:\n" . $errorInfo['trace'] . "\n";
        }

        $logMessage .= str_repeat('-', 80) . "\n";

        // Write to secure log file
        file_put_contents(self::$logFile, $logMessage, FILE_APPEND | LOCK_EX);
    }

    /**
     * Show user-friendly error page
     */
    private static function showErrorPage(): void
    {
        if (!headers_sent()) {
            http_response_code(500);
            header('Content-Type: text/html; charset=utf-8');
            header('X-Content-Type-Options: nosniff');
        }

        echo <<<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Application Error</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .error-container {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 2rem;
            text-align: center;
            max-width: 500px;
            margin: 1rem;
        }
        .error-icon {
            font-size: 3rem;
            color: #e74c3c;
            margin-bottom: 1rem;
        }
        .error-title {
            color: #2c3e50;
            margin-bottom: 1rem;
            font-size: 1.5rem;
        }
        .error-message {
            color: #7f8c8d;
            margin-bottom: 1.5rem;
            line-height: 1.6;
        }
        .error-actions {
            margin-top: 1.5rem;
        }
        .btn {
            display: inline-block;
            padding: 0.75rem 1.5rem;
            background-color: #3498db;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            transition: background-color 0.3s;
        }
        .btn:hover {
            background-color: #2980b9;
        }
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-icon">⚠️</div>
        <h1 class="error-title">Oops! Something went wrong</h1>
        <p class="error-message">
            We encountered an unexpected error while processing your request.
            Our team has been notified and is working to fix the issue.
        </p>
        <div class="error-actions">
            <a href="/" class="btn">Return to Homepage</a>
        </div>
    </div>
</body>
</html>
HTML;
        exit;
    }
}

// =============================================================================
// 3. SECURE HTTP HEADERS IMPLEMENTATION
// =============================================================================

class SecureHeaders
{
    /**
     * Set comprehensive security headers
     */
    public static function setSecurityHeaders(): void
    {
        // Remove existing security headers that might be insecure
        header_remove('X-Powered-By');
        header_remove('Server');

        // Content Security Policy
        $csp = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' https://trusted-cdn.com",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "img-src 'self' data: https: blob:",
            "font-src 'self' https://fonts.gstatic.com",
            "connect-src 'self' https://api.trusted.com",
            "media-src 'self'",
            "object-src 'none'",
            "child-src 'self'",
            "frame-ancestors 'none'",
            "form-action 'self'",
            "upgrade-insecure-requests"
        ];

        header('Content-Security-Policy: ' . implode('; ', $csp));

        // Other security headers
        header('X-Frame-Options: DENY');
        header('X-Content-Type-Options: nosniff');
        header('X-XSS-Protection: 1; mode=block');
        header('Referrer-Policy: strict-origin-when-cross-origin');

        // HTTPS Strict Transport Security (only for HTTPS)
        if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
        }

        // Feature Policy / Permissions Policy
        header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()');

        // Custom server header
        header('Server: Secure Web Server');
    }

    /**
     * Set headers for different content types
     */
    public static function setContentTypeHeaders(string $contentType): void
    {
        $headers = [
            'html' => [
                'Content-Type' => 'text/html; charset=utf-8',
                'X-Content-Type-Options' => 'nosniff',
            ],
            'json' => [
                'Content-Type' => 'application/json; charset=utf-8',
                'X-Content-Type-Options' => 'nosniff',
            ],
            'xml' => [
                'Content-Type' => 'application/xml; charset=utf-8',
                'X-Content-Type-Options' => 'nosniff',
            ],
            'css' => [
                'Content-Type' => 'text/css; charset=utf-8',
                'X-Content-Type-Options' => 'nosniff',
            ],
            'js' => [
                'Content-Type' => 'application/javascript; charset=utf-8',
                'X-Content-Type-Options' => 'nosniff',
            ],
        ];

        if (isset($headers[$contentType])) {
            foreach ($headers[$contentType] as $name => $value) {
                header("{$name}: {$value}");
            }
        }
    }

    /**
     * Generate CSP nonce for inline scripts/styles
     */
    public static function generateCSPNonce(): string
    {
        $nonce = bin2hex(random_bytes(16));

        // Update CSP header to include nonce
        header("Content-Security-Policy: script-src 'self' 'nonce-{$nonce}'; style-src 'self' 'nonce-{$nonce}'");

        return $nonce;
    }

    /**
     * Validate and set CORS headers
     */
    public static function setCORSHeaders(string $allowedOrigin = null): void
    {
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';

        // Validate allowed origin
        $allowedOrigins = $allowedOrigin ? [$allowedOrigin] : [
            'https://yourdomain.com',
            'https://www.yourdomain.com',
            'https://app.yourdomain.com',
        ];

        if (in_array($origin, $allowedOrigins)) {
            header('Access-Control-Allow-Origin: ' . $origin);
            header('Access-Control-Allow-Credentials: true');
            header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
            header('Access-Control-Allow-Headers: Content-Type, Authorization, X-CSRF-TOKEN');
            header('Access-Control-Max-Age: 86400'); // 24 hours
        }

        // Handle preflight requests
        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            exit(0);
        }
    }
}

// =============================================================================
// 4. PHP VERSION HIDING AND SERVER SECURITY
// =============================================================================

class ServerSecurity
{
    /**
     * Hide PHP and server version information
     */
    public static function hideServerInfo(): void
    {
        // Remove PHP version from headers
        header_remove('X-Powered-By');

        // Custom server header
        header('Server: Secure Web Server v1.0');

        // Remove other identifying headers
        header_remove('X-AspNet-Version');
        header_remove('X-AspNetMvc-Version');

        // Disable PHP version in errors
        ini_set('expose_php', '0');
    }

    /**
     * Secure PHP configuration for production
     */
    public static function setSecurePHPConfig(): void
    {
        // Error handling
        ini_set('display_errors', '0');
        ini_set('display_startup_errors', '0');
        ini_set('log_errors', '1');
        ini_set('error_log', '/var/log/php_secure_errors.log');

        // File uploads
        ini_set('file_uploads', '1');
        ini_set('upload_max_filesize', '10M');
        ini_set('max_file_uploads', '5');
        ini_set('post_max_size', '12M');

        // Session security
        ini_set('session.cookie_secure', '1');
        ini_set('session.cookie_httponly', '1');
        ini_set('session.cookie_samesite', 'Strict');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.gc_maxlifetime', '1440');
        ini_set('session.save_path', '/var/secure/sessions');

        // Resource limits
        ini_set('max_execution_time', '30');
        ini_set('max_input_time', '60');
        ini_set('memory_limit', '128M');

        // Security restrictions
        ini_set('allow_url_fopen', '0');
        ini_set('allow_url_include', '0');
        ini_set('disable_functions', 'exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source');

        // Performance and security
        ini_set('opcache.enable', '1');
        ini_set('opcache.memory_consumption', '256');
        ini_set('opcache.max_accelerated_files', '7963');
        ini_set('opcache.revalidate_freq', '0');
        ini_set('opcache.validate_timestamps', getenv('APP_ENV') === 'production' ? '0' : '1');
    }

    /**
     * Validate server security configuration
     */
    public static function validateSecurityConfig(): array
    {
        $issues = [];

        // Check PHP configuration
        if (ini_get('expose_php') === '1') {
            $issues[] = 'PHP version is exposed in headers';
        }

        if (ini_get('display_errors') === '1') {
            $issues[] = 'Error display is enabled';
        }

        if (ini_get('allow_url_include') === '1') {
            $issues[] = 'URL include is enabled (security risk)';
        }

        // Check file permissions
        $sensitiveFiles = [
            __DIR__ . '/../.env',
            __DIR__ . '/../config/database.php',
            '/etc/php/7.4/fpm/php-fpm.conf',
        ];

        foreach ($sensitiveFiles as $file) {
            if (file_exists($file)) {
                $perms = fileperms($file) & 0777;
                if ($perms > 0640) {
                    $issues[] = "Insecure permissions on {$file} (" . decoct($perms) . ')';
                }
            }
        }

        // Check environment
        if (getenv('APP_DEBUG') === 'true' && getenv('APP_ENV') === 'production') {
            $issues[] = 'Debug mode enabled in production';
        }

        return $issues;
    }

    /**
     * Generate security report
     */
    public static function generateSecurityReport(): string
    {
        $issues = self::validateSecurityConfig();

        $report = "🔍 Server Security Report\n";
        $report .= "Generated: " . date('Y-m-d H:i:s') . "\n";
        $report .= "Environment: " . (getenv('APP_ENV') ?: 'unknown') . "\n";
        $report .= "Server: " . ($_SERVER['SERVER_SOFTWARE'] ?? 'unknown') . "\n\n";

        if (empty($issues)) {
            $report .= "✅ All security checks passed!\n";
        } else {
            $report .= "❌ Security issues found:\n";
            foreach ($issues as $issue) {
                $report .= "  - {$issue}\n";
            }
        }

        return $report;
    }
}

// =============================================================================
// 5. LARAVEL SECURE CONFIGURATION
// =============================================================================

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\App;

class SecurityHeadersMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);

        // Remove Laravel version header
        $response->headers->remove('X-Powered-By');

        // Content Security Policy
        $csp = $this->buildCSP();
        $response->headers->set('Content-Security-Policy', $csp);

        // Security headers
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-XSS-Protection', '1; mode=block');
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');

        // HSTS for HTTPS
        if ($request->secure()) {
            $response->headers->set('Strict-Transport-Security',
                'max-age=31536000; includeSubDomains; preload');
        }

        // Permissions Policy
        $response->headers->set('Permissions-Policy',
            'camera=(), microphone=(), geolocation=(), payment=()');

        return $response;
    }

    private function buildCSP(): string
    {
        $policies = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data: https:",
            "font-src 'self'",
            "connect-src 'self'",
            "media-src 'self'",
            "object-src 'none'",
            "child-src 'self'",
            "frame-ancestors 'none'",
            "form-action 'self'",
        ];

        if (App::environment('production')) {
            $policies[] = "upgrade-insecure-requests";
        }

        return implode('; ', $policies);
    }
}

// Laravel Service Provider for secure configuration
namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Validator;

class SecurityServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        // Custom validation rules
        Validator::extend('secure_password', function ($attribute, $value, $parameters, $validator) {
            return preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/', $value);
        });

        // Validate configuration on boot
        $this->validateConfiguration();
    }

    private function validateConfiguration(): void
    {
        $issues = [];

        // Check debug mode
        if (config('app.debug') && app()->environment('production')) {
            $issues[] = 'Debug mode enabled in production';
        }

        // Check session security
        if (!config('session.secure')) {
            $issues[] = 'Session cookies not marked as secure';
        }

        if (!config('session.http_only')) {
            $issues[] = 'Session cookies not marked as http-only';
        }

        // Log issues
        if (!empty($issues)) {
            \Log::warning('Security configuration issues detected', ['issues' => $issues]);
        }
    }
}

// =============================================================================
// INITIALIZATION AND USAGE
// =============================================================================

class SecureApplication
{
    public static function initialize(): void
    {
        // Load secure environment configuration
        SecureEnvManager::loadSecureConfig();

        // Initialize secure error handling
        SecureErrorHandler::initialize();

        // Set secure HTTP headers
        SecureHeaders::setSecurityHeaders();

        // Hide server information
        ServerSecurity::hideServerInfo();

        // Set secure PHP configuration
        ServerSecurity::setSecurePHPConfig();

        // Generate security report
        $report = ServerSecurity::generateSecurityReport();
        echo "<pre>{$report}</pre>";
    }
}

/*
// USAGE EXAMPLES

// Initialize secure application
SecureApplication::initialize();

// Generate secure .env template
$template = SecureEnvManager::generateSecureEnvTemplate();
file_put_contents('.env.example', $template);

// Validate configuration
$issues = ServerSecurity::validateSecurityConfig();
if (!empty($issues)) {
    foreach ($issues as $issue) {
        error_log("SECURITY ISSUE: {$issue}");
    }
}

// Laravel usage in bootstrap/app.php:
// $app->middleware(SecurityHeadersMiddleware::class);
// $app->register(SecurityServiceProvider::class);
*/
?>
