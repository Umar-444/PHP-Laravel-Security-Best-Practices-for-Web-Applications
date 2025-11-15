<?php

/**
 * Session Security Examples: Secure vs Insecure Session Management
 *
 * Practical examples of session security vulnerabilities and their secure alternatives
 */

declare(strict_types=1);

// =============================================================================
// 1. SESSION CONFIGURATION EXAMPLES
// =============================================================================

class SessionConfiguration
{
    /**
     * ❌ INSECURE: Default PHP session configuration
     * Vulnerable to session hijacking, fixation, and eavesdropping
     */
    public static function insecureSessionSetup(): void
    {
        // No security settings - vulnerable by default
        session_start();
    }

    /**
     * ✅ SECURE: Properly configured sessions
     */
    public static function secureSessionSetup(): void
    {
        // Secure session configuration
        ini_set('session.cookie_secure', '1');      // HTTPS only
        ini_set('session.cookie_httponly', '1');    // Prevent XSS theft
        ini_set('session.cookie_samesite', 'Strict'); // CSRF protection
        ini_set('session.use_only_cookies', '1');   // No URL sessions
        ini_set('session.cookie_lifetime', '0');    // Session cookies
        ini_set('session.gc_maxlifetime', '1440');  // 24 minutes
        ini_set('session.cookie_domain', $_SERVER['HTTP_HOST'] ?? 'localhost');

        // Unique session name per application
        session_name('SECURE_APP_' . hash('sha256', __DIR__));

        session_start();
    }

    /**
     * ❌ INSECURE: Accepting user-provided session IDs
     * Vulnerable to session fixation attacks
     */
    public static function vulnerableSessionFixation(string $userSessionId): void
    {
        // DANGER: Accepting user-controlled session ID
        if (!empty($userSessionId)) {
            session_id($userSessionId); // Attacker can set victim's session ID
        }
        session_start();
    }

    /**
     * ✅ SECURE: Automatic session ID generation
     */
    public static function secureSessionStart(): void
    {
        // PHP generates cryptographically secure session IDs automatically
        self::secureSessionSetup();

        // Additional security measures
        if (!isset($_SESSION['created'])) {
            $_SESSION['created'] = time();
            $_SESSION['fingerprint'] = self::generateFingerprint();
        }

        // Regenerate session ID periodically (every 5 minutes)
        if (time() - ($_SESSION['created'] ?? 0) > 300) {
            session_regenerate_id(true);
            $_SESSION['created'] = time();
        }
    }

    /**
     * Generate session fingerprint for additional security
     */
    private static function generateFingerprint(): string
    {
        return hash('sha256', implode('|', [
            $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? 'unknown',
        ]));
    }
}

// =============================================================================
// 2. SESSION DATA MANAGEMENT EXAMPLES
// =============================================================================

class SessionDataManagement
{
    /**
     * ❌ INSECURE: Storing sensitive data in sessions
     * Never store passwords, credit cards, or other sensitive data
     */
    public static function insecureDataStorage(): void
    {
        session_start();

        // DANGER: Storing sensitive information
        $_SESSION['password'] = 'user_secret_password';    // NEVER DO THIS
        $_SESSION['credit_card'] = '4111111111111111';     // NEVER DO THIS
        $_SESSION['social_security'] = '123-45-6789';     // NEVER DO THIS
        $_SESSION['api_key'] = 'sk_live_secret_key';      // NEVER DO THIS

        // PROBLEM: Storing large objects
        $_SESSION['user_profile'] = [
            'name' => 'John Doe',
            'bio' => str_repeat('A', 10000), // Large data
            'preferences' => ['theme' => 'dark', 'lang' => 'en']
        ];
    }

    /**
     * ✅ SECURE: Safe session data storage
     * Only store identifiers and temporary flags
     */
    public static function secureDataStorage(): void
    {
        SessionConfiguration::secureSessionStart();

        // SAFE: Store only identifiers and flags
        $_SESSION['user_id'] = 12345;
        $_SESSION['username'] = 'johndoe';
        $_SESSION['role'] = 'user';
        $_SESSION['login_time'] = time();
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['permissions'] = ['read', 'write']; // Simple arrays OK
        $_SESSION['theme'] = 'dark'; // User preferences OK

        // Store sensitive data in database, not session
        // Retrieve when needed using the user_id
    }

    /**
     * ✅ SECURE: Type-safe session data handling
     */
    public static function safeSessionOperations(): void
    {
        SessionConfiguration::secureSessionStart();

        // Safe getter with type checking
        $userId = self::getSessionInt('user_id');
        $username = self::getSessionString('username');
        $isLoggedIn = self::getSessionBool('is_logged_in', false);

        // Safe setter with validation
        self::setSessionData('user_id', 12345, 'int');
        self::setSessionData('username', 'johndoe', 'string');
        self::setSessionData('login_time', time(), 'int');
    }

    private static function getSessionInt(string $key, int $default = 0): int
    {
        return isset($_SESSION[$key]) && is_numeric($_SESSION[$key])
            ? (int) $_SESSION[$key]
            : $default;
    }

    private static function getSessionString(string $key, string $default = ''): string
    {
        return isset($_SESSION[$key]) && is_string($_SESSION[$key])
            ? $_SESSION[$key]
            : $default;
    }

    private static function getSessionBool(string $key, bool $default = false): bool
    {
        return isset($_SESSION[$key]) ? (bool) $_SESSION[$key] : $default;
    }

    private static function setSessionData(string $key, $value, string $expectedType): void
    {
        // Type validation
        $isValidType = match($expectedType) {
            'int' => is_int($value),
            'string' => is_string($value),
            'bool' => is_bool($value),
            'array' => is_array($value) && count($value) < 100, // Reasonable limit
            default => false
        };

        if (!$isValidType) {
            throw new InvalidArgumentException("Invalid type for session key '{$key}'");
        }

        // Size limit (prevent memory exhaustion)
        if (is_string($value) && strlen($value) > 1000) {
            throw new InvalidArgumentException("Session value too large for key '{$key}'");
        }

        $_SESSION[$key] = $value;
    }
}

// =============================================================================
// 3. LOGIN/LOGOUT SESSION MANAGEMENT
// =============================================================================

class AuthenticationSessionManager
{
    /**
     * ❌ INSECURE: Vulnerable login implementation
     * No session regeneration, stores sensitive data
     */
    public static function insecureLogin(array $user): void
    {
        session_start();

        // DANGER: No session regeneration (session fixation vulnerability)
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['password'] = $user['password']; // NEVER STORE PASSWORD!
        $_SESSION['email'] = $user['email'];
        $_SESSION['role'] = $user['role'];

        // No additional security measures
    }

    /**
     * ✅ SECURE: Proper login session management
     */
    public static function secureLogin(array $user): void
    {
        SessionConfiguration::secureSessionStart();

        // CRITICAL: Regenerate session ID to prevent session fixation
        session_regenerate_id(true);

        // Store only necessary, non-sensitive data
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['email'] = $user['email'];
        $_SESSION['role'] = $user['role'];
        $_SESSION['login_time'] = time();
        $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';

        // Generate CSRF token
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

        // Log successful login
        error_log("User {$user['username']} logged in from {$_SERVER['REMOTE_ADDR']}");
    }

    /**
     * ❌ INSECURE: Weak logout implementation
     */
    public static function insecureLogout(): void
    {
        // PROBLEM: Only clears session data, doesn't destroy session
        session_start();
        $_SESSION = []; // Data cleared, but session still exists

        // No cookie cleanup
    }

    /**
     * ✅ SECURE: Complete logout implementation
     */
    public static function secureLogout(): void
    {
        // Start session if not already started
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        // Log logout before destroying session
        $username = $_SESSION['username'] ?? 'unknown';
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        error_log("User {$username} logged out from {$ip}");

        // Clear all session data
        $_SESSION = [];

        // Get session parameters for cookie cleanup
        $sessionName = session_name();
        $sessionCookieParams = session_get_cookie_params();

        // Delete session cookie
        setcookie(
            $sessionName,
            '',
            time() - 3600,
            $sessionCookieParams['path'],
            $sessionCookieParams['domain'],
            $sessionCookieParams['secure'],
            $sessionCookieParams['httponly']
        );

        // Destroy session
        session_destroy();

        // Optional: Start new session to prevent session fixation
        session_start();
        session_regenerate_id(true);
    }

    /**
     * ✅ SECURE: Session validation on each request
     */
    public static function validateSession(): bool
    {
        if (session_status() === PHP_SESSION_NONE) {
            return false;
        }

        // Check if user is logged in
        if (!isset($_SESSION['user_id'])) {
            return false;
        }

        // Check session timeout (30 minutes)
        if (isset($_SESSION['login_time'])) {
            $inactiveTime = time() - $_SESSION['login_time'];
            if ($inactiveTime > 1800) { // 30 minutes
                self::secureLogout();
                return false;
            }
        }

        // Optional: Check IP address consistency
        if (isset($_SESSION['ip_address'])) {
            if ($_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
                error_log("IP address changed for user {$_SESSION['username']}: {$_SESSION['ip_address']} -> {$_SERVER['REMOTE_ADDR']}");
                // Could force re-authentication here
                // self::secureLogout();
                // return false;
            }
        }

        // Optional: Check user agent consistency
        if (isset($_SESSION['user_agent'])) {
            if ($_SESSION['user_agent'] !== ($_SERVER['HTTP_USER_AGENT'] ?? '')) {
                error_log("User agent changed for user {$_SESSION['username']}");
                // Could force re-authentication here
            }
        }

        // Update last activity
        $_SESSION['last_activity'] = time();

        return true;
    }
}

// =============================================================================
// 4. SESSION HIJACKING PREVENTION
// =============================================================================

class SessionHijackingPrevention
{
    /**
     * ❌ INSECURE: No protection against session hijacking
     */
    public static function vulnerableToHijacking(): void
    {
        session_start();

        // No validation of session integrity
        if (isset($_SESSION['user_id'])) {
            echo "Welcome, {$_SESSION['username']}!";
        }
    }

    /**
     * ✅ SECURE: Multiple layers of hijacking protection
     */
    public static function protectAgainstHijacking(): void
    {
        SessionConfiguration::secureSessionStart();

        // Layer 1: Session validation
        if (!AuthenticationSessionManager::validateSession()) {
            header('HTTP/1.1 401 Unauthorized');
            exit('Please log in');
        }

        // Layer 2: Request fingerprinting
        $currentFingerprint = self::generateRequestFingerprint();
        if (!isset($_SESSION['request_fingerprint'])) {
            $_SESSION['request_fingerprint'] = $currentFingerprint;
        } elseif ($_SESSION['request_fingerprint'] !== $currentFingerprint) {
            // Possible session hijacking
            error_log("Fingerprint mismatch for user {$_SESSION['username']}");
            AuthenticationSessionManager::secureLogout();
            exit('Session security violation');
        }

        // Layer 3: Behavioral analysis (basic)
        self::analyzeSessionBehavior();

        echo "Welcome, {$_SESSION['username']}!";
    }

    private static function generateRequestFingerprint(): string
    {
        return hash('sha256', implode('|', [
            $_SERVER['REMOTE_ADDR'] ?? '',
            $_SERVER['HTTP_USER_AGENT'] ?? '',
            $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
            $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '',
        ]));
    }

    private static function analyzeSessionBehavior(): void
    {
        // Track request patterns
        $now = time();
        $requests = $_SESSION['request_log'] ?? [];

        // Keep only recent requests (last 10 minutes)
        $requests = array_filter($requests, function($timestamp) use ($now) {
            return ($now - $timestamp) < 600;
        });

        $requests[] = $now;
        $_SESSION['request_log'] = array_slice($requests, -100); // Keep last 100

        // Check for suspicious patterns
        $recentRequests = count($requests);
        $timeSpan = end($requests) - reset($requests);

        if ($timeSpan > 0) {
            $requestsPerMinute = ($recentRequests / $timeSpan) * 60;

            // Flag if more than 30 requests per minute
            if ($requestsPerMinute > 30) {
                error_log("High request frequency detected for user {$_SESSION['username']}: {$requestsPerMinute} req/min");
            }
        }
    }
}

// =============================================================================
// 5. CUSTOM SESSION HANDLER (DATABASE STORAGE)
// =============================================================================

class DatabaseSessionHandler implements SessionHandlerInterface
{
    private PDO $pdo;
    private string $table = 'sessions';

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
                ip_address VARCHAR(45) NOT NULL,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_last_activity (last_activity),
                INDEX idx_ip_address (ip_address)
            )
        ");
    }

    public function open(string $savePath, string $sessionName): bool
    {
        return true;
    }

    public function close(): bool
    {
        return true;
    }

    public function read(string $sessionId): string
    {
        try {
            $stmt = $this->pdo->prepare("
                SELECT data FROM {$this->table}
                WHERE id = ? AND last_activity > DATE_SUB(NOW(), INTERVAL 24 HOUR)
            ");
            $stmt->execute([$sessionId]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            return $result ? $result['data'] : '';
        } catch (PDOException $e) {
            error_log("Session read error: " . $e->getMessage());
            return '';
        }
    }

    public function write(string $sessionId, string $data): bool
    {
        try {
            // Clean up old sessions periodically (1% chance)
            if (rand(1, 100) === 1) {
                $this->gc(86400); // 24 hours
            }

            $stmt = $this->pdo->prepare("
                INSERT INTO {$this->table} (id, data, ip_address, user_agent, created_at, last_activity)
                VALUES (?, ?, ?, ?, NOW(), NOW())
                ON DUPLICATE KEY UPDATE
                    data = VALUES(data),
                    ip_address = VALUES(ip_address),
                    user_agent = VALUES(user_agent),
                    last_activity = NOW()
            ");

            return $stmt->execute([
                $sessionId,
                $data,
                $_SERVER['REMOTE_ADDR'] ?? '',
                $_SERVER['HTTP_USER_AGENT'] ?? ''
            ]);
        } catch (PDOException $e) {
            error_log("Session write error: " . $e->getMessage());
            return false;
        }
    }

    public function destroy(string $sessionId): bool
    {
        try {
            $stmt = $this->pdo->prepare("DELETE FROM {$this->table} WHERE id = ?");
            return $stmt->execute([$sessionId]);
        } catch (PDOException $e) {
            error_log("Session destroy error: " . $e->getMessage());
            return false;
        }
    }

    public function gc(int $maxLifetime): int
    {
        try {
            $stmt = $this->pdo->prepare("
                DELETE FROM {$this->table}
                WHERE last_activity < DATE_SUB(NOW(), INTERVAL ? SECOND)
            ");
            $stmt->execute([$maxLifetime]);
            return $stmt->rowCount();
        } catch (PDOException $e) {
            error_log("Session GC error: " . $e->getMessage());
            return 0;
        }
    }

    /**
     * Get active sessions for monitoring
     */
    public function getActiveSessions(): array
    {
        try {
            $stmt = $this->pdo->query("
                SELECT id, ip_address, user_agent, created_at, last_activity
                FROM {$this->table}
                WHERE last_activity > DATE_SUB(NOW(), INTERVAL 30 MINUTE)
                ORDER BY last_activity DESC
            ");
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("Error getting active sessions: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Force logout all sessions for a user
     */
    public function destroyUserSessions(int $userId): int
    {
        try {
            // This assumes you store user_id in session data
            $stmt = $this->pdo->prepare("
                DELETE FROM {$this->table}
                WHERE data LIKE ?
            ");
            $stmt->execute(["%\"user_id\";i:{$userId}%"]);
            return $stmt->rowCount();
        } catch (PDOException $e) {
            error_log("Error destroying user sessions: " . $e->getMessage());
            return 0;
        }
    }
}

// =============================================================================
// 6. LARAVEL SESSION EXAMPLES
// =============================================================================

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\Auth;

class LaravelSessionController extends Controller
{
    /**
     * Laravel secure session management
     */
    public function secureLaravelSession(Request $request)
    {
        // Laravel automatically handles secure sessions
        // But you can add additional security layers

        // Check session timeout
        if (Session::has('last_activity')) {
            $inactiveTime = time() - Session::get('last_activity');
            if ($inactiveTime > config('session.lifetime') * 60) {
                Auth::logout();
                Session::flush();
                return redirect('/login')->with('message', 'Session expired');
            }
        }

        // Update activity
        Session::put('last_activity', time());

        // Store safe session data
        Session::put('user_id', Auth::id());
        Session::put('ip_address', $request->ip());
        Session::put('user_agent', $request->userAgent());

        // Laravel automatically encrypts session data
        Session::put('permissions', ['read', 'write']);

        return view('dashboard');
    }

    /**
     * Laravel session security middleware
     */
    public function withSecurityMiddleware(Request $request)
    {
        // This would be handled by middleware
        // See SessionSecurityMiddleware in documentation
        return response()->json(['secure' => true]);
    }
}

// =============================================================================
// USAGE EXAMPLES AND TESTING
// =============================================================================

class SessionSecurityTester
{
    public static function runSecurityTests(): array
    {
        $results = [];

        // Test 1: Session configuration
        SessionConfiguration::secureSessionSetup();
        $results['secure_config'] = session_status() === PHP_SESSION_ACTIVE;

        // Test 2: Secure data storage
        SessionDataManagement::secureDataStorage();
        $results['data_storage'] = !isset($_SESSION['password']); // Should not store password

        // Test 3: Login/logout security
        $testUser = ['id' => 1, 'username' => 'testuser', 'email' => 'test@example.com', 'role' => 'user'];
        AuthenticationSessionManager::secureLogin($testUser);
        $results['login_security'] = isset($_SESSION['user_id']) && isset($_SESSION['csrf_token']);

        // Test 4: Session validation
        $results['session_validation'] = AuthenticationSessionManager::validateSession();

        // Test 5: Secure logout
        AuthenticationSessionManager::secureLogout();
        $results['logout_security'] = !isset($_SESSION['user_id']);

        return $results;
    }

    public static function demonstrateVulnerabilities(): void
    {
        echo "⚠️  WARNING: The following examples demonstrate VULNERABILITIES\n";
        echo "🚫 NEVER use these in production code!\n\n";

        // This would be vulnerable - don't actually run it
        echo "❌ Vulnerable patterns shown in comments only for educational purposes\n";
        echo "✅ Always use the secure alternatives above\n";
    }
}

// =============================================================================
// SETUP AND INITIALIZATION
// =============================================================================

class SessionSecuritySetup
{
    public static function initializeSecureSessions(PDO $pdo = null): void
    {
        // Use database session storage if PDO provided
        if ($pdo) {
            $handler = new DatabaseSessionHandler($pdo);
            session_set_save_handler($handler, true);
        }

        // Configure secure sessions
        SessionConfiguration::secureSessionSetup();
    }

    public static function createSessionTables(PDO $pdo): void
    {
        // Database session handler will create its own tables
        $handler = new DatabaseSessionHandler($pdo);
        // Tables are created automatically in constructor
    }
}

/*
// SETUP EXAMPLE
try {
    $pdo = new PDO("mysql:host=localhost;dbname=secure_sessions", "user", "pass", [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
    ]);

    // Initialize secure session management
    SessionSecuritySetup::initializeSecureSessions($pdo);

    // Run security tests
    $testResults = SessionSecurityTester::runSecurityTests();
    print_r($testResults);

} catch (Exception $e) {
    echo "Setup error: " . $e->getMessage();
}
*/
?>
