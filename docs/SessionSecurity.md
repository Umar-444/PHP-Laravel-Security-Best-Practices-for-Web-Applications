# Session Security

## What are Sessions?

Sessions allow web applications to maintain state across multiple HTTP requests. They enable features like user authentication, shopping carts, and personalized experiences. However, poorly managed sessions are a common attack vector.

### Session Mechanics

1. **Session Creation**: Server generates a unique session ID
2. **Cookie Storage**: Session ID stored in browser cookie
3. **Data Storage**: Session data stored on server
4. **Data Retrieval**: Server uses session ID to retrieve user data

## Session Attack Vectors

### 1. Session Hijacking
Attackers steal session IDs to impersonate legitimate users.

#### Methods:
- **Network Sniffing**: Intercepting unencrypted traffic
- **XSS Attacks**: Stealing session cookies via JavaScript
- **Session Fixation**: Tricking users into using attacker-controlled session IDs

### 2. Session Fixation
Attacker sets victim's session ID before they authenticate.

```php
// VULNERABLE: Accepting user-provided session ID
if (isset($_GET['session_id'])) {
    session_id($_GET['session_id']); // DANGER!
    session_start();
}
```

### 3. Session Poisoning
Manipulating session data to escalate privileges or bypass security.

### 4. Session Riding (CSRF)
Using victim's active session to perform unwanted actions.

## Secure Session Configuration

### PHP Session Security Settings

```php
<?php
// Secure session configuration
ini_set('session.cookie_secure', '1');      // HTTPS only
ini_set('session.cookie_httponly', '1');    // Prevent XSS theft
ini_set('session.cookie_samesite', 'Strict'); // CSRF protection
ini_set('session.use_only_cookies', '1');   // No URL sessions
ini_set('session.cookie_lifetime', '0');    // Session cookies (expire on browser close)
ini_set('session.gc_maxlifetime', '1440');  // 24 minutes server-side timeout
ini_set('session.cookie_domain', 'example.com'); // Domain restriction
ini_set('session.cookie_path', '/');        // Path restriction

// Start session with custom name
session_name('SECURE_APP_SESSION');
session_start();
```

### Laravel Session Configuration

In `config/session.php`:

```php
<?php
return [
    'driver' => env('SESSION_DRIVER', 'file'),
    'lifetime' => env('SESSION_LIFETIME', 120), // 2 hours
    'expire_on_close' => true,
    'encrypt' => true, // Laravel encrypts session data
    'path' => '/',
    'domain' => env('SESSION_DOMAIN', null),
    'secure' => env('SESSION_SECURE_COOKIE', true), // HTTPS only
    'http_only' => true, // Prevent XSS
    'same_site' => 'strict', // CSRF protection
];
```

## Secure Cookies

### Cookie Security Attributes

#### Secure Flag
```php
// Only send cookie over HTTPS
setcookie('session_id', $sessionId, [
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);
```

#### HttpOnly Flag
```php
// Prevent JavaScript access to cookies
setcookie('session_id', $sessionId, [
    'secure' => true,
    'httponly' => true, // JavaScript cannot read this cookie
    'samesite' => 'Strict'
]);
```

#### SameSite Attribute
```php
// CSRF protection
setcookie('session_id', $sessionId, [
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict' // Lax or Strict
]);
```

### Cookie Scope Limitations

```php
// Limit cookie to specific domain and path
setcookie('session_id', $sessionId, [
    'expires' => time() + 3600,
    'path' => '/app/',     // Only for /app/ paths
    'domain' => 'app.example.com', // Only for this subdomain
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);
```

## Session ID Security

### Session ID Generation

#### Weak Session IDs ❌
```php
// PREDICTABLE - Don't do this!
session_id('session_' . time());
session_id('session_' . rand(1000, 9999));
```

#### Strong Session IDs ✅
```php
// PHP generates secure random session IDs automatically
session_start(); // Uses cryptographically secure random bytes

// Or generate custom secure IDs
$secureId = bin2hex(random_bytes(32)); // 64 character hex string
session_id($secureId);
```

### Session ID Regeneration

#### When to Regenerate Session IDs

1. **After Login** - Prevents session fixation
2. **After Logout** - Clears old session
3. **Periodically** - Reduces hijacking window
4. **After Privilege Changes** - Role escalation

```php
<?php
class SecureSessionManager
{
    public static function login($userId, $username)
    {
        // CRITICAL: Regenerate session ID after successful login
        session_regenerate_id(true);

        $_SESSION['user_id'] = $userId;
        $_SESSION['username'] = $username;
        $_SESSION['login_time'] = time();
        $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
    }

    public static function logout()
    {
        // Clear session data
        $_SESSION = [];

        // Delete session cookie
        if (isset($_COOKIE[session_name()])) {
            setcookie(session_name(), '', time() - 3600, '/', '', true, true);
        }

        // Destroy session
        session_destroy();

        // Start new session to prevent session fixation
        session_start();
        session_regenerate_id(true);
    }

    public static function validateSession()
    {
        // Check session timeout (30 minutes)
        if (isset($_SESSION['login_time']) &&
            (time() - $_SESSION['login_time']) > 1800) {
            self::logout();
            return false;
        }

        // Optional: Check IP address consistency
        if (isset($_SESSION['ip_address']) &&
            $_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
            error_log('IP address changed for session: ' . session_id());
            self::logout();
            return false;
        }

        // Optional: Check user agent consistency
        if (isset($_SESSION['user_agent']) &&
            $_SESSION['user_agent'] !== ($_SERVER['HTTP_USER_AGENT'] ?? '')) {
            error_log('User agent changed for session: ' . session_id());
            self::logout();
            return false;
        }

        return true;
    }
}
```

## Session Data Management

### What NOT to Store in Sessions

#### Sensitive Data ❌
```php
<?php
// DANGER: Never store sensitive data in sessions
$_SESSION['password'] = $userPassword;      // Passwords
$_SESSION['credit_card'] = $ccNumber;       // Payment info
$_SESSION['ssn'] = $socialSecurityNumber;   // PII
$_SESSION['api_key'] = $secretApiKey;       // Secrets
```

#### Large Data ❌
```php
<?php
// PROBLEMATIC: Large data in sessions
$_SESSION['user_profile'] = $largeUserObject;  // Memory issues
$_SESSION['file_contents'] = file_get_contents('large_file.txt'); // Performance
```

### What to Store in Sessions ✅

```php
<?php
// SAFE: Store only identifiers and flags
$_SESSION['user_id'] = $user->id;
$_SESSION['username'] = $user->username;
$_SESSION['role'] = $user->role;
$_SESSION['login_time'] = time();
$_SESSION['csrf_token'] = generateCSRFToken();
$_SESSION['permissions'] = ['read', 'write']; // Simple arrays OK
```

### Secure Session Data Handling

```php
<?php
class SessionDataHandler
{
    /**
     * Safely get session value with default
     */
    public static function get(string $key, $default = null)
    {
        return $_SESSION[$key] ?? $default;
    }

    /**
     * Safely set session value with type checking
     */
    public static function set(string $key, $value): void
    {
        // Basic type validation
        if (is_object($value) || is_resource($value)) {
            throw new InvalidArgumentException('Cannot store objects or resources in session');
        }

        $_SESSION[$key] = $value;
    }

    /**
     * Remove session value
     */
    public static function remove(string $key): void
    {
        unset($_SESSION[$key]);
    }

    /**
     * Check if session key exists
     */
    public static function has(string $key): bool
    {
        return isset($_SESSION[$key]);
    }

    /**
     * Get all session data (for debugging only)
     */
    public static function all(): array
    {
        return $_SESSION;
    }
}
```

## Session Storage Security

### File-Based Sessions (Default PHP)

```php
// Configure secure session file storage
ini_set('session.save_path', '/var/secure/sessions'); // Secure directory
chmod('/var/secure/sessions', 0730); // Restrictive permissions

// Only the web server should access session files
// chown www-data:www-data /var/secure/sessions
// chmod 600 /var/secure/sessions/sess_*
```

### Database Session Storage

```php
<?php
class DatabaseSessionHandler implements SessionHandlerInterface
{
    private $pdo;
    private $table = 'sessions';

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
        $this->createTable();
    }

    private function createTable(): void
    {
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS {$this->table} (
                id VARCHAR(128) PRIMARY KEY,
                data TEXT NOT NULL,
                last_access TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                ip_address VARCHAR(45),
                user_agent TEXT,
                INDEX idx_last_access (last_access)
            )
        ");
    }

    public function open($savePath, $sessionName): bool
    {
        return true;
    }

    public function close(): bool
    {
        return true;
    }

    public function read($sessionId): string
    {
        $stmt = $this->pdo->prepare("
            SELECT data FROM {$this->table}
            WHERE id = ? AND last_access > DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ");
        $stmt->execute([$sessionId]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        return $result ? $result['data'] : '';
    }

    public function write($sessionId, $data): bool
    {
        $stmt = $this->pdo->prepare("
            INSERT INTO {$this->table} (id, data, ip_address, user_agent, last_access)
            VALUES (?, ?, ?, ?, NOW())
            ON DUPLICATE KEY UPDATE
                data = VALUES(data),
                ip_address = VALUES(ip_address),
                user_agent = VALUES(user_agent),
                last_access = NOW()
        ");

        return $stmt->execute([
            $sessionId,
            $data,
            $_SERVER['REMOTE_ADDR'] ?? '',
            $_SERVER['HTTP_USER_AGENT'] ?? ''
        ]);
    }

    public function destroy($sessionId): bool
    {
        $stmt = $this->pdo->prepare("DELETE FROM {$this->table} WHERE id = ?");
        return $stmt->execute([$sessionId]);
    }

    public function gc($maxLifetime): int
    {
        $stmt = $this->pdo->prepare("
            DELETE FROM {$this->table}
            WHERE last_access < DATE_SUB(NOW(), INTERVAL ? SECOND)
        ");
        $stmt->execute([$maxLifetime]);
        return $stmt->rowCount();
    }
}

// Usage
$handler = new DatabaseSessionHandler($pdo);
session_set_save_handler($handler, true);
session_start();
```

### Redis Session Storage

```php
<?php
// Using Redis for session storage
ini_set('session.save_handler', 'redis');
ini_set('session.save_path', 'tcp://127.0.0.1:6379?auth=your_password');

// Or with phpredis extension
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
$redis->auth('your_password');

// Set key prefix for security
ini_set('session.save_path', 'tcp://127.0.0.1:6379/app_sessions');
```

## Laravel Session Security

### Laravel Session Configuration

```php
<?php
// config/session.php - Secure configuration
return [
    'driver' => 'database', // Or 'redis' for better performance
    'lifetime' => 120,      // 2 hours
    'expire_on_close' => true,
    'encrypt' => true,      // Laravel encrypts all session data
    'path' => '/',
    'domain' => '.example.com', // Subdomain support
    'secure' => true,       // HTTPS only
    'http_only' => true,    // XSS protection
    'same_site' => 'strict', // CSRF protection
];
```

### Laravel Session Usage

```php
<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Session;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        // Validate credentials...

        // Regenerate session ID (Laravel does this automatically on login)
        // But you can force it if needed
        $request->session()->regenerate();

        // Store user data
        Session::put('user_id', $user->id);
        Session::put('username', $user->username);
        Session::put('role', $user->role);

        return redirect('/dashboard');
    }

    public function logout(Request $request)
    {
        // Laravel's Auth::logout() handles session cleanup
        auth()->logout();

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect('/');
    }

    public function dashboard(Request $request)
    {
        // Check authentication
        if (!Session::has('user_id')) {
            return redirect('/login');
        }

        // Get session data
        $userId = Session::get('user_id');
        $username = Session::get('username');

        return view('dashboard', compact('username'));
    }
}
```

### Laravel Middleware for Session Security

```php
<?php
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Session;

class SessionSecurityMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        // Check session timeout
        if (Session::has('last_activity')) {
            $inactiveTime = time() - Session::get('last_activity');
            if ($inactiveTime > config('session.lifetime') * 60) {
                auth()->logout();
                Session::flush();
                return redirect('/login')->with('message', 'Session expired');
            }
        }

        // Update last activity
        Session::put('last_activity', time());

        // Check IP address consistency (optional)
        if (Session::has('ip_address')) {
            if (Session::get('ip_address') !== $request->ip()) {
                // Log suspicious activity
                \Log::warning('IP address changed', [
                    'session_id' => Session::getId(),
                    'old_ip' => Session::get('ip_address'),
                    'new_ip' => $request->ip(),
                    'user_agent' => $request->userAgent()
                ]);

                // Optional: Force re-authentication
                // auth()->logout();
                // Session::flush();
                // return redirect('/login')->with('message', 'Security alert');
            }
        } else {
            Session::put('ip_address', $request->ip());
        }

        return $next($request);
    }
}
```

## Session Security Monitoring

### Logging Session Events

```php
<?php
class SessionLogger
{
    public static function logSessionEvent(string $event, array $data = []): void
    {
        $logData = array_merge($data, [
            'session_id' => session_id(),
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'timestamp' => date('Y-m-d H:i:s'),
            'uri' => $_SERVER['REQUEST_URI'] ?? 'unknown',
        ]);

        error_log("SESSION {$event}: " . json_encode($logData));
    }

    public static function logLogin(string $username): void
    {
        self::logSessionEvent('LOGIN_SUCCESS', ['username' => $username]);
    }

    public static function logFailedLogin(string $username): void
    {
        self::logSessionEvent('LOGIN_FAILED', ['username' => $username]);
    }

    public static function logLogout(string $username = null): void
    {
        self::logSessionEvent('LOGOUT', ['username' => $username]);
    }

    public static function logSuspiciousActivity(string $reason): void
    {
        self::logSessionEvent('SUSPICIOUS', ['reason' => $reason]);
    }
}
```

### Session Analytics

```php
<?php
class SessionAnalytics
{
    private $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    public function trackSession(string $sessionId, string $userId = null): void
    {
        $stmt = $this->pdo->prepare("
            INSERT INTO session_tracking (session_id, user_id, ip_address, user_agent, created_at)
            VALUES (?, ?, ?, ?, NOW())
            ON DUPLICATE KEY UPDATE last_activity = NOW()
        ");

        $stmt->execute([
            $sessionId,
            $userId,
            $_SERVER['REMOTE_ADDR'] ?? '',
            $_SERVER['HTTP_USER_AGENT'] ?? ''
        ]);
    }

    public function getActiveSessions(): array
    {
        $stmt = $this->pdo->query("
            SELECT * FROM session_tracking
            WHERE last_activity > DATE_SUB(NOW(), INTERVAL 30 MINUTE)
            ORDER BY last_activity DESC
        ");

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function detectAnomalies(): array
    {
        // Detect multiple sessions from same IP with different user agents
        $stmt = $this->pdo->query("
            SELECT ip_address, COUNT(DISTINCT user_agent) as agent_count,
                   GROUP_CONCAT(DISTINCT user_id) as users
            FROM session_tracking
            WHERE last_activity > DATE_SUB(NOW(), INTERVAL 1 HOUR)
            GROUP BY ip_address
            HAVING agent_count > 2 AND COUNT(*) > 3
        ");

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}
```

## Security Best Practices Summary

1. **Use HTTPS** - Always encrypt session traffic
2. **Secure Cookies** - Set secure, httponly, samesite flags
3. **Regenerate Session IDs** - After login/logout and periodically
4. **Validate Sessions** - Check timeouts and consistency
5. **Avoid Sensitive Data** - Don't store passwords, keys, or large objects
6. **Monitor Sessions** - Log and analyze session activity
7. **Use Secure Storage** - Database or Redis over file-based sessions
8. **Implement Timeouts** - Both idle and absolute session timeouts
9. **Validate Requests** - Check IP/user agent consistency
10. **Clean Up** - Properly destroy sessions on logout

## Next Steps

Now that you understand session security, explore:

- **[CSRF Protection](CSRFProtection.md)** - Prevent cross-site request forgery
- **[XSS Protection](XSSProtection.md)** - Prevent cross-site scripting attacks
- **[Authentication & Password Handling](AuthenticationPasswordHandling.md)** - Complete user security

Remember: Sessions are a critical security component. Implement these practices to protect your users and prevent session-based attacks!
