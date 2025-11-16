# Error Handling & Logging

## Why Error Handling Matters

Proper error handling and logging are critical for both security and application stability. Poor error handling can expose sensitive information to attackers, while inadequate logging makes it difficult to detect and respond to security incidents.

### Security Risks of Poor Error Handling

- **Information Disclosure**: Error messages revealing database structure, file paths, or sensitive configuration
- **System Fingerprinting**: Error types helping attackers identify vulnerable software versions
- **Debug Information Leakage**: Stack traces exposing internal application logic
- **Denial of Service**: Unhandled errors crashing applications
- **Security Monitoring Gaps**: Lack of logging making attacks undetectable

## Production Error Display

### The Problem with Development Error Display

```php
<?php
// DEVELOPMENT - Useful for debugging
ini_set('display_errors', '1');
error_reporting(E_ALL);

// PRODUCTION - Dangerous!
ini_set('display_errors', '1'); // DON'T DO THIS IN PRODUCTION
```

### Secure Production Error Configuration

```php
<?php
// Production error handling - secure approach
ini_set('display_errors', '0');          // Hide errors from users
ini_set('display_startup_errors', '0');  // Hide startup errors
error_reporting(E_ALL & ~E_DEPRECATED); // Log all but deprecated
ini_set('log_errors', '1');             // Enable error logging
ini_set('error_log', '/var/log/php_errors.log'); // Secure log location
```

### Laravel Error Configuration

```php
<?php
// config/app.php
return [
    'debug' => env('APP_DEBUG', false), // NEVER true in production
    'env' => env('APP_ENV', 'production'),
];

// .env.production
APP_ENV=production
APP_DEBUG=false
LOG_LEVEL=error
```

## Secure Error Logging

### What to Log (and What Not to Log)

#### Log Security Events ✅
```php
<?php
class SecurityLogger
{
    public static function logSecurityEvent(string $event, array $data = []): void
    {
        $logEntry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'event' => $event,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'user_id' => $_SESSION['user_id'] ?? 'anonymous',
            'data' => $data
        ];

        error_log("SECURITY: " . json_encode($logEntry));
    }

    // Log authentication events
    public static function logLoginAttempt(string $username, bool $success): void
    {
        self::logSecurityEvent('LOGIN_ATTEMPT', [
            'username' => $username,
            'success' => $success
        ]);
    }

    // Log suspicious activities
    public static function logSuspiciousActivity(string $activity, array $details): void
    {
        self::logSecurityEvent('SUSPICIOUS_ACTIVITY', [
            'activity' => $activity,
            'details' => $details
        ]);
    }
}
```

#### Never Log Sensitive Data ❌
```php
<?php
// WRONG: Logging sensitive information
error_log("User login failed: password='{$password}'");
error_log("Credit card: " . $ccNumber);
error_log("API key: " . $apiKey);

// RIGHT: Log without sensitive data
error_log("User login failed for username: {$username}");
error_log("Payment processing failed for user: {$userId}");
error_log("API call failed for service: {$serviceName}");
```

### Structured Logging

```php
<?php
class StructuredLogger
{
    private static string $logFile = '/var/log/app/security.log';

    public static function log(array $data): void
    {
        $entry = [
            'timestamp' => date('c'), // ISO 8601 format
            'level' => $data['level'] ?? 'INFO',
            'message' => $data['message'] ?? '',
            'context' => $data['context'] ?? [],
            'user' => [
                'id' => $_SESSION['user_id'] ?? null,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                'agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
            ]
        ];

        $jsonEntry = json_encode($entry, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        // Ensure log directory exists
        $logDir = dirname(self::$logFile);
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }

        // Secure log file permissions
        if (!file_exists(self::$logFile)) {
            touch(self::$logFile);
            chmod(self::$logFile, 0600);
        }

        file_put_contents(self::$logFile, $jsonEntry . "\n", FILE_APPEND | LOCK_EX);
    }

    public static function error(string $message, array $context = []): void
    {
        self::log([
            'level' => 'ERROR',
            'message' => $message,
            'context' => $context
        ]);
    }

    public static function security(string $message, array $context = []): void
    {
        self::log([
            'level' => 'SECURITY',
            'message' => $message,
            'context' => $context
        ]);
    }
}
```

## Custom Error Handlers

### PHP Error Handler

```php
<?php
class SecureErrorHandler
{
    private static bool $debugMode = false;

    public static function initialize(bool $debugMode = false): void
    {
        self::$debugMode = $debugMode;

        // Set error reporting
        if ($debugMode) {
            error_reporting(E_ALL);
            ini_set('display_errors', '1');
        } else {
            error_reporting(E_ALL & ~E_DEPRECATED);
            ini_set('display_errors', '0');
            ini_set('log_errors', '1');
        }

        // Register handlers
        set_error_handler([self::class, 'handleError']);
        set_exception_handler([self::class, 'handleException']);
        register_shutdown_function([self::class, 'handleShutdown']);
    }

    public static function handleError(int $errno, string $errstr, string $errfile, int $errline): bool
    {
        // Sanitize error message
        $safeMessage = self::sanitizeErrorMessage($errstr);
        $safeFile = basename($errfile); // Hide full paths

        // Log error securely
        StructuredLogger::error('PHP Error', [
            'errno' => $errno,
            'message' => $safeMessage,
            'file' => $safeFile,
            'line' => $errline,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ]);

        // Don't display errors in production
        return !self::$debugMode;
    }

    public static function handleException(Throwable $exception): void
    {
        $safeMessage = self::sanitizeErrorMessage($exception->getMessage());
        $safeFile = basename($exception->getFile());

        StructuredLogger::error('Uncaught Exception', [
            'message' => $safeMessage,
            'file' => $safeFile,
            'line' => $exception->getLine(),
            'trace' => self::$debugMode ? $exception->getTraceAsString() : null,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ]);

        if (!self::$debugMode) {
            self::showErrorPage();
        } else {
            // Re-throw in development
            throw $exception;
        }
    }

    public static function handleShutdown(): void
    {
        $error = error_get_last();

        if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
            $safeMessage = self::sanitizeErrorMessage($error['message']);
            $safeFile = basename($error['file']);

            StructuredLogger::error('Fatal Error', [
                'message' => $safeMessage,
                'file' => $safeFile,
                'line' => $error['line'],
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);

            if (!self::$debugMode) {
                self::showErrorPage();
            }
        }
    }

    private static function sanitizeErrorMessage(string $message): string
    {
        // Remove sensitive information from error messages
        $patterns = [
            '/password[\'"]?\s*[:=]\s*[\'"][^\'"]*[\'"]/i',
            '/key[\'"]?\s*[:=]\s*[\'"][^\'"]*[\'"]/i',
            '/secret[\'"]?\s*[:=]\s*[\'"][^\'"]*[\'"]/i',
            '/token[\'"]?\s*[:=]\s*[\'"][^\'"]*[\'"]/i',
            '/(mysql|pgsql).*?@/i',
            '/\/var\/www\/[^)]*\//', // Full paths
        ];

        foreach ($patterns as $pattern) {
            $message = preg_replace($pattern, '[REDACTED]', $message);
        }

        return $message;
    }

    private static function showErrorPage(): void
    {
        if (!headers_sent()) {
            http_response_code(500);
            header('Content-Type: text/html; charset=utf-8');
            header('X-Content-Type-Options: nosniff');
        }

        echo self::getErrorPageHtml();
        exit;
    }

    private static function getErrorPageHtml(): string
    {
        return <<<'HTML'
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
    }
}

// Initialize secure error handling
SecureErrorHandler::initialize(getenv('APP_ENV') === 'development');
```

## Laravel Error Handling

### Laravel Exception Handler

```php
<?php
namespace App\Exceptions;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Illuminate\Support\Facades\Log;
use Throwable;

class Handler extends ExceptionHandler
{
    protected $dontReport = [
        // Don't report these exceptions
    ];

    protected $dontFlash = [
        'current_password',
        'password',
        'password_confirmation',
    ];

    public function report(Throwable $exception): void
    {
        // Custom reporting logic
        if ($this->shouldReport($exception)) {
            // Sanitize exception data before logging
            $safeContext = $this->sanitizeExceptionContext([
                'message' => $exception->getMessage(),
                'file' => $exception->getFile(),
                'line' => $exception->getLine(),
                'trace' => $exception->getTraceAsString(),
                'url' => request()->fullUrl(),
                'ip' => request()->ip(),
                'user_agent' => request()->userAgent(),
                'user_id' => auth()->id(),
            ]);

            Log::error('Application Exception', $safeContext);
        }

        parent::report($exception);
    }

    public function render($request, Throwable $exception)
    {
        // Custom rendering logic
        if ($request->expectsJson()) {
            return response()->json([
                'error' => 'Internal Server Error',
                'message' => app()->environment('production')
                    ? 'An error occurred while processing your request.'
                    : $exception->getMessage()
            ], 500);
        }

        // Show custom error page in production
        if (app()->environment('production')) {
            return response()->view('errors.500', [], 500);
        }

        return parent::render($request, $exception);
    }

    private function sanitizeExceptionContext(array $context): array
    {
        // Remove sensitive data from context
        $sensitiveKeys = ['password', 'password_confirmation', 'credit_card', 'api_key'];

        foreach ($context as $key => $value) {
            if (in_array($key, $sensitiveKeys) || str_contains(strtolower($key), 'password')) {
                $context[$key] = '[REDACTED]';
            }

            // Sanitize file paths
            if ($key === 'file' && is_string($value)) {
                $context[$key] = basename($value);
            }

            // Sanitize stack traces
            if ($key === 'trace' && is_string($value)) {
                $context[$key] = $this->sanitizeStackTrace($value);
            }
        }

        return $context;
    }

    private function sanitizeStackTrace(string $trace): string
    {
        // Remove full paths and sensitive information
        $lines = explode("\n", $trace);
        $sanitized = [];

        foreach ($lines as $line) {
            // Replace full paths with relative paths
            $line = preg_replace('/\/var\/www\/[^)]*\//', '/app/', $line);
            $line = preg_replace('/\/home\/[^\/]*\//', '/home/user/', $line);

            // Remove sensitive function calls
            $line = preg_replace('/password.*?\)/i', 'password([REDACTED]))', $line);

            $sanitized[] = $line;
        }

        return implode("\n", $sanitized);
    }
}
```

### Laravel Logging Configuration

```php
<?php
// config/logging.php
return [
    'default' => env('LOG_CHANNEL', 'stack'),

    'channels' => [
        'stack' => [
            'driver' => 'stack',
            'channels' => ['single', 'daily'],
            'ignore_exceptions' => false,
        ],

        'single' => [
            'driver' => 'single',
            'path' => storage_path('logs/laravel.log'),
            'level' => env('LOG_LEVEL', 'debug'),
        ],

        'daily' => [
            'driver' => 'daily',
            'path' => storage_path('logs/laravel.log'),
            'level' => env('LOG_LEVEL', 'debug'),
            'days' => 14,
        ],

        'security' => [
            'driver' => 'daily',
            'path' => storage_path('logs/security.log'),
            'level' => 'debug',
            'days' => 90, // Keep security logs longer
        ],
    ],
];

// Usage
use Illuminate\Support\Facades\Log;

Log::channel('security')->info('User login', [
    'user_id' => auth()->id(),
    'ip' => request()->ip(),
    'user_agent' => request()->userAgent()
]);
```

## Log Analysis and Monitoring

### Log Parsing and Analysis

```php
<?php
class LogAnalyzer
{
    public static function analyzeSecurityLogs(string $logFile): array
    {
        $analysis = [
            'total_entries' => 0,
            'security_events' => 0,
            'failed_logins' => 0,
            'suspicious_ips' => [],
            'error_patterns' => []
        ];

        if (!file_exists($logFile)) {
            return $analysis;
        }

        $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        foreach ($lines as $line) {
            $analysis['total_entries']++;

            // Parse JSON log entries
            $entry = json_decode($line, true);
            if (!$entry) continue;

            // Analyze security events
            if (isset($entry['level']) && $entry['level'] === 'SECURITY') {
                $analysis['security_events']++;

                if (isset($entry['message']) && str_contains($entry['message'], 'LOGIN_ATTEMPT')) {
                    if (isset($entry['data']['success']) && !$entry['data']['success']) {
                        $analysis['failed_logins']++;

                        $ip = $entry['ip'] ?? 'unknown';
                        if (!isset($analysis['suspicious_ips'][$ip])) {
                            $analysis['suspicious_ips'][$ip] = 0;
                        }
                        $analysis['suspicious_ips'][$ip]++;
                    }
                }
            }

            // Analyze error patterns
            if (isset($entry['level']) && $entry['level'] === 'ERROR') {
                $message = $entry['message'] ?? '';
                $pattern = self::extractErrorPattern($message);

                if (!isset($analysis['error_patterns'][$pattern])) {
                    $analysis['error_patterns'][$pattern] = 0;
                }
                $analysis['error_patterns'][$pattern]++;
            }
        }

        // Filter suspicious IPs (more than 5 failed attempts)
        $analysis['suspicious_ips'] = array_filter(
            $analysis['suspicious_ips'],
            fn($count) => $count > 5
        );

        return $analysis;
    }

    private static function extractErrorPattern(string $message): string
    {
        // Extract common error patterns
        if (preg_match('/SQLSTATE\[\w+\]/', $message)) {
            return 'Database Error';
        }

        if (preg_match('/Undefined (variable|index)/', $message)) {
            return 'Undefined Variable/Index';
        }

        if (preg_match('/Call to undefined method/', $message)) {
            return 'Undefined Method';
        }

        return 'Other Error';
    }

    public static function generateSecurityReport(): string
    {
        $logFile = '/var/log/app/security.log';
        $analysis = self::analyzeSecurityLogs($logFile);

        $report = "🔍 Security Log Analysis Report\n";
        $report .= "Generated: " . date('Y-m-d H:i:s') . "\n\n";

        $report .= "📊 Summary:\n";
        $report .= "- Total Log Entries: {$analysis['total_entries']}\n";
        $report .= "- Security Events: {$analysis['security_events']}\n";
        $report .= "- Failed Login Attempts: {$analysis['failed_logins']}\n\n";

        if (!empty($analysis['suspicious_ips'])) {
            $report .= "🚨 Suspicious IPs:\n";
            foreach ($analysis['suspicious_ips'] as $ip => $count) {
                $report .= "- {$ip}: {$count} failed attempts\n";
            }
            $report .= "\n";
        }

        if (!empty($analysis['error_patterns'])) {
            $report .= "🐛 Error Patterns:\n";
            foreach ($analysis['error_patterns'] as $pattern => $count) {
                $report .= "- {$pattern}: {$count} occurrences\n";
            }
        }

        return $report;
    }
}
```

## Log Rotation and Retention

### Automated Log Rotation

```bash
#!/bin/bash
# log-rotate.sh - Secure log rotation script

LOG_DIR="/var/log/app"
BACKUP_DIR="/var/log/app/archive"
RETENTION_DAYS=90

# Ensure directories exist
mkdir -p "$BACKUP_DIR"

# Rotate current logs
for log_file in "$LOG_DIR"/*.log; do
    if [ -f "$log_file" ]; then
        base_name=$(basename "$log_file" .log)
        timestamp=$(date +%Y%m%d_%H%M%S)
        backup_file="$BACKUP_DIR/${base_name}_${timestamp}.log.gz"

        # Compress and backup
        gzip -c "$log_file" > "$backup_file"

        # Clear original log
        > "$log_file"

        # Set secure permissions on backup
        chmod 600 "$backup_file"
    fi
done

# Remove old backups
find "$BACKUP_DIR" -name "*.log.gz" -mtime +$RETENTION_DAYS -delete

echo "Log rotation completed at $(date)"
```

### Log Integrity Monitoring

```php
<?php
class LogIntegrityMonitor
{
    private static string $integrityFile = '/var/log/app/integrity.hash';

    public static function updateIntegrityHash(): void
    {
        $logFiles = glob('/var/log/app/*.log');
        $hashes = [];

        foreach ($logFiles as $file) {
            $hashes[$file] = hash_file('sha256', $file);
        }

        file_put_contents(self::$integrityFile, json_encode([
            'timestamp' => time(),
            'hashes' => $hashes
        ]));

        chmod(self::$integrityFile, 0600);
    }

    public static function verifyIntegrity(): array
    {
        $issues = [];

        if (!file_exists(self::$integrityFile)) {
            $issues[] = 'Integrity file missing';
            return $issues;
        }

        $integrity = json_decode(file_get_contents(self::$integrityFile), true);

        if (!$integrity || !isset($integrity['hashes'])) {
            $issues[] = 'Invalid integrity file';
            return $issues;
        }

        $currentHashes = [];
        foreach ($integrity['hashes'] as $file => $storedHash) {
            if (file_exists($file)) {
                $currentHash = hash_file('sha256', $file);
                if ($currentHash !== $storedHash) {
                    $issues[] = "Log file modified: {$file}";
                }
            } else {
                $issues[] = "Log file missing: {$file}";
            }
        }

        return $issues;
    }
}
```

## Error Handling Best Practices

### 1. Fail Safely
```php
<?php
function processPayment(array $data): bool
{
    try {
        // Validate input
        if (empty($data['amount']) || !is_numeric($data['amount'])) {
            StructuredLogger::error('Invalid payment amount', [
                'amount' => $data['amount'] ?? 'null',
                'user_id' => $data['user_id'] ?? 'unknown'
            ]);
            return false;
        }

        // Process payment
        $result = $this->paymentGateway->charge($data);

        if (!$result['success']) {
            StructuredLogger::error('Payment failed', [
                'error' => $result['error'],
                'user_id' => $data['user_id']
            ]);
            return false;
        }

        StructuredLogger::log('Payment successful', [
            'amount' => $data['amount'],
            'user_id' => $data['user_id']
        ]);

        return true;

    } catch (Exception $e) {
        StructuredLogger::error('Payment processing error', [
            'error' => $e->getMessage(),
            'user_id' => $data['user_id'] ?? 'unknown'
        ]);
        return false;
    }
}
```

### 2. Graceful Degradation
```php
<?php
class GracefulDegradationHandler
{
    public static function handleServiceFailure(string $service, Exception $e): mixed
    {
        StructuredLogger::error("Service failure: {$service}", [
            'error' => $e->getMessage(),
            'service' => $service
        ]);

        // Return cached data if available
        $cached = self::getCachedData($service);
        if ($cached) {
            return $cached;
        }

        // Return default/fallback data
        return self::getFallbackData($service);
    }

    public static function handleDatabaseFailure(PDOException $e): array
    {
        StructuredLogger::error('Database connection failed', [
            'error' => $e->getMessage()
        ]);

        // Try to reconnect
        try {
            // Attempt reconnection logic
            return ['status' => 'reconnected'];
        } catch (Exception $reconnectError) {
            // Use read-only mode or cached data
            return ['status' => 'readonly_mode'];
        }
    }
}
```

### 3. User-Friendly Error Messages
```php
<?php
class UserFriendlyErrors
{
    private static array $errorMessages = [
        'db_connection' => 'Service temporarily unavailable. Please try again later.',
        'payment_failed' => 'Payment could not be processed. Please check your payment information.',
        'file_upload' => 'File upload failed. Please try again or contact support.',
        'validation' => 'Please check your input and try again.',
        'permission' => 'You do not have permission to perform this action.',
        'not_found' => 'The requested resource was not found.',
        'rate_limit' => 'Too many requests. Please wait before trying again.',
    ];

    public static function getMessage(string $errorType, array $context = []): string
    {
        $message = self::$errorMessages[$errorType] ??
                  'An unexpected error occurred. Please try again later.';

        // Log detailed error internally
        StructuredLogger::error("User error: {$errorType}", $context);

        return $message;
    }

    public static function handleExceptionForUser(Throwable $exception): string
    {
        // Log full exception details
        StructuredLogger::error('Exception for user', [
            'message' => $exception->getMessage(),
            'file' => basename($exception->getFile()),
            'line' => $exception->getLine(),
            'trace' => app()->environment('production') ? null : $exception->getTraceAsString()
        ]);

        // Return user-friendly message
        return 'Something went wrong. Our team has been notified.';
    }
}
```

## Security Monitoring Integration

### Real-time Alerting

```php
<?php
class SecurityAlertSystem
{
    public static function checkForAnomalies(): void
    {
        $analysis = LogAnalyzer::analyzeSecurityLogs('/var/log/app/security.log');

        // Alert thresholds
        if ($analysis['failed_logins'] > 10) {
            self::sendAlert('High number of failed login attempts detected');
        }

        if (count($analysis['suspicious_ips']) > 5) {
            self::sendAlert('Multiple suspicious IP addresses detected');
        }

        // Check for error spikes
        $errorCount = array_sum($analysis['error_patterns']);
        if ($errorCount > 50) {
            self::sendAlert('High error rate detected');
        }
    }

    public static function sendAlert(string $message): void
    {
        // Log alert
        StructuredLogger::security('ALERT: ' . $message);

        // Send email alert
        $alertEmail = getenv('SECURITY_ALERT_EMAIL') ?: 'admin@example.com';
        $subject = 'Security Alert: ' . date('Y-m-d H:i:s');

        mail($alertEmail, $subject, $message);

        // Could also integrate with Slack, PagerDuty, etc.
    }
}
```

## Summary: Error Handling & Logging Rules

1. **Never display errors in production** - Hide sensitive information from users
2. **Log everything securely** - Use structured logging with sensitive data sanitization
3. **Implement custom error handlers** - Control error display and logging
4. **Sanitize error messages** - Remove passwords, keys, and file paths
5. **Use graceful error pages** - User-friendly error messages
6. **Monitor logs regularly** - Detect security incidents and anomalies
7. **Implement log rotation** - Manage log file sizes and retention
8. **Maintain log integrity** - Prevent log tampering
9. **Fail safely** - Graceful degradation when services fail
10. **Alert on anomalies** - Real-time security monitoring

## Next Steps

Now that you understand error handling and logging, explore:

- **[Dependency Security](DependencySecurity.md)** - Secure package management
- **[Access Control](AccessControl.md)** - User permissions and authorization
- **[Secure Configuration](SecureConfiguration.md)** - Production configuration security

Remember: Proper error handling and logging are essential for both security monitoring and preventing information disclosure. Implement comprehensive logging and never expose sensitive error details to users!
