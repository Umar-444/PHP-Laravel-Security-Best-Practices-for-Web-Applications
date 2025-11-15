<?php

/**
 * Authentication Examples: Password Hashing, Session Management, and Security
 *
 * Comprehensive examples of secure authentication practices in PHP
 */

declare(strict_types=1);

// =============================================================================
// PASSWORD HASHING EXAMPLES
// =============================================================================

class PasswordSecurity
{
    /**
     * Secure password hashing with Argon2
     */
    public static function hashPassword(string $password): string
    {
        return password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,  // 64MB
            'time_cost' => 4,        // 4 iterations
            'threads' => 3           // 3 parallel threads
        ]);
    }

    /**
     * Verify password with timing attack protection
     */
    public static function verifyPassword(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * Check if password hash needs rehashing (for algorithm upgrades)
     */
    public static function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost' => 4,
            'threads' => 3
        ]);
    }

    /**
     * Secure password generation
     */
    public static function generateSecurePassword(int $length = 12): string
    {
        $lowercase = 'abcdefghijklmnopqrstuvwxyz';
        $uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $numbers = '0123456789';
        $symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';

        // Ensure at least one of each type
        $password = '';
        $password .= $lowercase[random_int(0, strlen($lowercase) - 1)];
        $password .= $uppercase[random_int(0, strlen($uppercase) - 1)];
        $password .= $numbers[random_int(0, strlen($numbers) - 1)];
        $password .= $symbols[random_int(0, strlen($symbols) - 1)];

        // Fill the rest
        $allChars = $lowercase . $uppercase . $numbers . $symbols;
        for ($i = 4; $i < $length; $i++) {
            $password .= $allChars[random_int(0, strlen($allChars) - 1)];
        }

        return str_shuffle($password);
    }

    /**
     * Password strength validation
     */
    public static function validatePasswordStrength(string $password): array
    {
        $errors = [];
        $score = 0;

        // Length
        if (strlen($password) < 8) {
            $errors[] = 'At least 8 characters required';
        } else {
            $score += 25;
        }

        // Character types
        if (!preg_match('/[a-z]/', $password)) {
            $errors[] = 'Lowercase letter required';
        } else {
            $score += 25;
        }

        if (!preg_match('/[A-Z]/', $password)) {
            $errors[] = 'Uppercase letter required';
        } else {
            $score += 25;
        }

        if (!preg_match('/\d/', $password)) {
            $errors[] = 'Number required';
        } else {
            $score += 25;
        }

        // Common passwords check
        $commonPasswords = ['password', '123456', 'qwerty', 'admin'];
        if (in_array(strtolower($password), $commonPasswords)) {
            $errors[] = 'Password is too common';
            $score = 0;
        }

        return [
            'valid' => empty($errors),
            'errors' => $errors,
            'score' => $score,
            'strength' => self::getStrengthLevel($score)
        ];
    }

    private static function getStrengthLevel(int $score): string
    {
        if ($score >= 75) return 'Strong';
        if ($score >= 50) return 'Medium';
        return 'Weak';
    }
}

// =============================================================================
// SESSION MANAGEMENT EXAMPLES
// =============================================================================

class SecureSessionManager
{
    private const SESSION_TIMEOUT = 1800; // 30 minutes
    private const ABSOLUTE_TIMEOUT = 86400; // 24 hours

    public static function initialize(): void
    {
        // Secure session configuration
        ini_set('session.cookie_secure', '1');      // HTTPS only
        ini_set('session.cookie_httponly', '1');    // Prevent XSS
        ini_set('session.cookie_samesite', 'Strict'); // CSRF protection
        ini_set('session.use_only_cookies', '1');   // No URL sessions
        ini_set('session.cookie_lifetime', '0');    // Session cookies
        ini_set('session.gc_maxlifetime', '1440');  // 24 minutes

        // Unique session name per application
        session_name('secure_app_' . hash('sha256', __DIR__));

        session_start();

        // Initialize session if new
        if (!isset($_SESSION['created'])) {
            $_SESSION['created'] = time();
            $_SESSION['id'] = session_id();
        }

        // Check for session hijacking
        self::validateSession();
    }

    private static function validateSession(): void
    {
        // Regenerate session ID periodically
        if (time() - ($_SESSION['created'] ?? 0) > 300) { // 5 minutes
            session_regenerate_id(true);
            $_SESSION['created'] = time();
            $_SESSION['id'] = session_id();
        }

        // Check absolute timeout
        if (time() - ($_SESSION['created'] ?? 0) > self::ABSOLUTE_TIMEOUT) {
            self::destroy();
            return;
        }

        // Check IP consistency (optional - can be problematic with proxies)
        $currentIp = $_SERVER['REMOTE_ADDR'];
        if (isset($_SESSION['ip']) && $_SESSION['ip'] !== $currentIp) {
            // Log suspicious activity
            error_log("IP address changed for session {$_SESSION['id']}: {$_SESSION['ip']} -> {$currentIp}");
            self::destroy();
            return;
        }

        // Check user agent (helps prevent some session hijacking)
        $currentUa = $_SERVER['HTTP_USER_AGENT'] ?? '';
        if (isset($_SESSION['user_agent']) && $_SESSION['user_agent'] !== $currentUa) {
            error_log("User agent changed for session {$_SESSION['id']}");
            self::destroy();
            return;
        }
    }

    public static function setUser(int $userId, string $username, string $role): void
    {
        $_SESSION['user_id'] = $userId;
        $_SESSION['username'] = $username;
        $_SESSION['role'] = $role;
        $_SESSION['login_time'] = time();
        $_SESSION['ip'] = $_SERVER['REMOTE_ADDR'];
        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
    }

    public static function isAuthenticated(): bool
    {
        if (!isset($_SESSION['user_id'], $_SESSION['login_time'])) {
            return false;
        }

        // Check session timeout
        if (time() - $_SESSION['login_time'] > self::SESSION_TIMEOUT) {
            self::destroy();
            return false;
        }

        return true;
    }

    public static function getCurrentUser(): ?array
    {
        if (!self::isAuthenticated()) {
            return null;
        }

        return [
            'id' => $_SESSION['user_id'],
            'username' => $_SESSION['username'],
            'role' => $_SESSION['role'],
            'login_time' => $_SESSION['login_time']
        ];
    }

    public static function hasRole(string $role): bool
    {
        return isset($_SESSION['role']) && $_SESSION['role'] === $role;
    }

    public static function requireAuth(): void
    {
        if (!self::isAuthenticated()) {
            header('HTTP/1.1 401 Unauthorized');
            exit('Authentication required');
        }
    }

    public static function requireRole(string $role): void
    {
        self::requireAuth();

        if (!self::hasRole($role)) {
            header('HTTP/1.1 403 Forbidden');
            exit('Insufficient permissions');
        }
    }

    public static function logout(): void
    {
        self::destroy();
    }

    private static function destroy(): void
    {
        // Clear all session data
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
}

// =============================================================================
// ACCOUNT LOCKOUT AND RATE LIMITING
// =============================================================================

class AccountSecurity
{
    private PDO $pdo;
    private int $maxAttempts = 5;
    private int $lockoutMinutes = 15;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
        $this->createTables();
    }

    private function createTables(): void
    {
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INT PRIMARY KEY AUTO_INCREMENT,
                identifier VARCHAR(255) NOT NULL,
                ip_address VARCHAR(45) NOT NULL,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_identifier_time (identifier, attempt_time)
            )
        ");

        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS account_lockouts (
                id INT PRIMARY KEY AUTO_INCREMENT,
                identifier VARCHAR(255) NOT NULL UNIQUE,
                lockout_until TIMESTAMP NOT NULL,
                INDEX idx_identifier (identifier)
            )
        ");
    }

    public function recordFailedAttempt(string $identifier, string $ipAddress): void
    {
        $stmt = $this->pdo->prepare("
            INSERT INTO login_attempts (identifier, ip_address, attempt_time)
            VALUES (?, ?, NOW())
        ");
        $stmt->execute([$identifier, $ipAddress]);
    }

    public function isAccountLocked(string $identifier): bool
    {
        // Check if manually locked out
        $stmt = $this->pdo->prepare("
            SELECT lockout_until FROM account_lockouts
            WHERE identifier = ? AND lockout_until > NOW()
        ");
        $stmt->execute([$identifier]);
        if ($stmt->fetch()) {
            return true;
        }

        // Check recent failed attempts
        $stmt = $this->pdo->prepare("
            SELECT COUNT(*) as attempts FROM login_attempts
            WHERE identifier = ? AND attempt_time > DATE_SUB(NOW(), INTERVAL ? MINUTE)
        ");
        $stmt->execute([$identifier, $this->lockoutMinutes]);

        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return ($result['attempts'] ?? 0) >= $this->maxAttempts;
    }

    public function lockAccount(string $identifier): void
    {
        $lockoutTime = date('Y-m-d H:i:s', strtotime("+{$this->lockoutMinutes} minutes"));

        $stmt = $this->pdo->prepare("
            INSERT INTO account_lockouts (identifier, lockout_until)
            VALUES (?, ?)
            ON DUPLICATE KEY UPDATE lockout_until = VALUES(lockout_until)
        ");
        $stmt->execute([$identifier, $lockoutTime]);
    }

    public function clearFailedAttempts(string $identifier): void
    {
        $stmt = $this->pdo->prepare("DELETE FROM login_attempts WHERE identifier = ?");
        $stmt->execute([$identifier]);

        $stmt = $this->pdo->prepare("DELETE FROM account_lockouts WHERE identifier = ?");
        $stmt->execute([$identifier]);
    }

    public function getRemainingLockoutTime(string $identifier): ?int
    {
        $stmt = $this->pdo->prepare("
            SELECT TIMESTAMPDIFF(SECOND, NOW(), lockout_until) as seconds_remaining
            FROM account_lockouts
            WHERE identifier = ? AND lockout_until > NOW()
        ");
        $stmt->execute([$identifier]);

        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result ? (int)$result['seconds_remaining'] : null;
    }
}

// =============================================================================
// MULTI-FACTOR AUTHENTICATION (TOTP)
// =============================================================================

class TOTP
{
    /**
     * Generate a secret key for TOTP
     */
    public static function generateSecret(): string
    {
        return bin2hex(random_bytes(20)); // 40 character hex string
    }

    /**
     * Generate TOTP code from secret
     */
    public static function generateCode(string $secret, int $timeWindow = 30): string
    {
        $time = floor(time() / $timeWindow);
        $secret = self::base32Decode($secret);

        // HMAC-SHA1
        $hmac = hash_hmac('sha1', pack('N*', 0, $time), $secret, true);

        // Dynamic truncation
        $offset = ord($hmac[19]) & 0x0F;
        $code = (
            ((ord($hmac[$offset]) & 0x7F) << 24) |
            ((ord($hmac[$offset + 1]) & 0xFF) << 16) |
            ((ord($hmac[$offset + 2]) & 0xFF) << 8) |
            (ord($hmac[$offset + 3]) & 0xFF)
        ) % 1000000;

        return str_pad((string)$code, 6, '0', STR_PAD_LEFT);
    }

    /**
     * Verify TOTP code
     */
    public static function verifyCode(string $secret, string $code, int $window = 1): bool
    {
        $code = (int)$code;

        // Check current time window and adjacent windows
        for ($i = -$window; $i <= $window; $i++) {
            $expectedCode = (int)self::generateCode($secret, 30, time() + ($i * 30));
            if ($expectedCode === $code) {
                return true;
            }
        }

        return false;
    }

    /**
     * Generate QR code URL for Google Authenticator
     */
    public static function getQRCodeUrl(string $secret, string $accountName, string $issuer = 'MyApp'): string
    {
        $url = "otpauth://totp/{$issuer}:{$accountName}?secret={$secret}&issuer={$issuer}";
        return "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=" . urlencode($url);
    }

    private static function base32Decode(string $base32): string
    {
        $base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $output = '';

        $buffer = 0;
        $bitsLeft = 0;

        foreach (str_split($base32) as $char) {
            $value = strpos($base32Chars, $char);
            if ($value === false) continue;

            $buffer = ($buffer << 5) | $value;
            $bitsLeft += 5;

            if ($bitsLeft >= 8) {
                $output .= chr(($buffer >> ($bitsLeft - 8)) & 0xFF);
                $bitsLeft -= 8;
            }
        }

        return $output;
    }
}

// =============================================================================
// COMPLETE AUTHENTICATION SYSTEM
// =============================================================================

class CompleteAuthSystem
{
    private PDO $pdo;
    private AccountSecurity $accountSecurity;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
        $this->accountSecurity = new AccountSecurity($pdo);
    }

    public function register(string $username, string $email, string $password): array
    {
        // Validate input
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ['success' => false, 'message' => 'Invalid email format'];
        }

        if (!preg_match('/^[a-zA-Z0-9_-]{3,20}$/', $username)) {
            return ['success' => false, 'message' => 'Invalid username format'];
        }

        // Validate password strength
        $passwordCheck = PasswordSecurity::validatePasswordStrength($password);
        if (!$passwordCheck['valid']) {
            return ['success' => false, 'message' => implode(', ', $passwordCheck['errors'])];
        }

        try {
            // Check if user exists
            $stmt = $this->pdo->prepare("SELECT id FROM users WHERE email = ? OR username = ?");
            $stmt->execute([$email, $username]);
            if ($stmt->fetch()) {
                return ['success' => false, 'message' => 'User already exists'];
            }

            // Create user
            $hashedPassword = PasswordSecurity::hashPassword($password);
            $stmt = $this->pdo->prepare("
                INSERT INTO users (username, email, password_hash, created_at)
                VALUES (?, ?, ?, NOW())
            ");
            $stmt->execute([$username, $email, $hashedPassword]);

            $userId = $this->pdo->lastInsertId();

            return [
                'success' => true,
                'message' => 'Registration successful',
                'user_id' => $userId
            ];

        } catch (PDOException $e) {
            error_log("Registration error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Registration failed'];
        }
    }

    public function login(string $username, string $password, string $ipAddress): array
    {
        // Check account lockout
        if ($this->accountSecurity->isAccountLocked($username)) {
            $remainingTime = $this->accountSecurity->getRemainingLockoutTime($username);
            return [
                'success' => false,
                'message' => "Account locked. Try again in {$remainingTime} seconds."
            ];
        }

        try {
            // Get user
            $stmt = $this->pdo->prepare("
                SELECT id, username, email, password_hash, active, two_factor_secret
                FROM users WHERE (username = ? OR email = ?) AND active = 1
            ");
            $stmt->execute([$username, $username]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user) {
                $this->accountSecurity->recordFailedAttempt($username, $ipAddress);
                return ['success' => false, 'message' => 'Invalid credentials'];
            }

            // Verify password
            if (!PasswordSecurity::verifyPassword($password, $user['password_hash'])) {
                $this->accountSecurity->recordFailedAttempt($username, $ipAddress);
                return ['success' => false, 'message' => 'Invalid credentials'];
            }

            // Clear failed attempts
            $this->accountSecurity->clearFailedAttempts($username);

            // Check if 2FA is enabled
            if (!empty($user['two_factor_secret'])) {
                return [
                    'success' => true,
                    'requires_2fa' => true,
                    'user_id' => $user['id'],
                    'temp_token' => $this->generateTempToken($user['id'])
                ];
            }

            // Complete login
            $this->completeLogin($user, $ipAddress);

            return [
                'success' => true,
                'message' => 'Login successful',
                'user' => [
                    'id' => $user['id'],
                    'username' => $user['username'],
                    'email' => $user['email']
                ]
            ];

        } catch (PDOException $e) {
            error_log("Login error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Login failed'];
        }
    }

    public function verify2FA(string $tempToken, string $code): array
    {
        $userId = $this->validateTempToken($tempToken);
        if (!$userId) {
            return ['success' => false, 'message' => 'Invalid token'];
        }

        // Get user with 2FA secret
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user || empty($user['two_factor_secret'])) {
            return ['success' => false, 'message' => '2FA not enabled'];
        }

        if (!TOTP::verifyCode($user['two_factor_secret'], $code)) {
            return ['success' => false, 'message' => 'Invalid 2FA code'];
        }

        // Complete login
        $this->completeLogin($user, $_SERVER['REMOTE_ADDR']);

        return [
            'success' => true,
            'message' => 'Login successful',
            'user' => [
                'id' => $user['id'],
                'username' => $user['username'],
                'email' => $user['email']
            ]
        ];
    }

    private function completeLogin(array $user, string $ipAddress): void
    {
        // Regenerate session
        session_regenerate_id(true);

        // Set session data
        SecureSessionManager::setUser($user['id'], $user['username'], 'user');

        // Log successful login
        error_log("User {$user['username']} logged in from {$ipAddress}");
    }

    private function generateTempToken(int $userId): string
    {
        $token = bin2hex(random_bytes(32));
        $expires = date('Y-m-d H:i:s', strtotime('+5 minutes'));

        // Store in database or cache
        $stmt = $this->pdo->prepare("
            INSERT INTO temp_tokens (user_id, token, expires_at)
            VALUES (?, ?, ?)
        ");
        $stmt->execute([$userId, $token, $expires]);

        return $token;
    }

    private function validateTempToken(string $token): ?int
    {
        $stmt = $this->pdo->prepare("
            SELECT user_id FROM temp_tokens
            WHERE token = ? AND expires_at > NOW()
        ");
        $stmt->execute([$token]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($result) {
            // Delete used token
            $stmt = $this->pdo->prepare("DELETE FROM temp_tokens WHERE token = ?");
            $stmt->execute([$token]);

            return $result['user_id'];
        }

        return null;
    }
}

// =============================================================================
// USAGE EXAMPLES
// =============================================================================

/*
// Database setup
$pdo = new PDO("mysql:host=localhost;dbname=secure_auth", "user", "pass", [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
]);

// Initialize systems
SecureSessionManager::initialize();
$authSystem = new CompleteAuthSystem($pdo);

// Password examples
$password = "MySecurePass123!";
$hash = PasswordSecurity::hashPassword($password);
$valid = PasswordSecurity::verifyPassword($password, $hash);

// Registration
$result = $authSystem->register("johndoe", "john@example.com", "SecurePass123!");
if ($result['success']) {
    echo "Registration successful!";
}

// Login
$result = $authSystem->login("johndoe", "SecurePass123!", $_SERVER['REMOTE_ADDR']);
if ($result['success']) {
    if (isset($result['requires_2fa'])) {
        // Prompt for 2FA code
        echo "Enter 2FA code: ";
        $code = trim(fgets(STDIN));
        $result = $authSystem->verify2FA($result['temp_token'], $code);
    }

    if ($result['success']) {
        echo "Login successful!";
    }
}

// Session management
if (SecureSessionManager::isAuthenticated()) {
    $user = SecureSessionManager::getCurrentUser();
    echo "Welcome, {$user['username']}!";
}

// Logout
SecureSessionManager::logout();
*/
?>
