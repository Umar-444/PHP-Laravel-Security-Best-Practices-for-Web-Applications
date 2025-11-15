<?php

/**
 * Secure Login Implementation Example
 *
 * This example demonstrates secure authentication practices in PHP
 */

class SecureLogin
{
    private $pdo;
    private $sessionName = 'secure_session';

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;

        // Secure session configuration
        ini_set('session.cookie_secure', '1'); // HTTPS only
        ini_set('session.cookie_httponly', '1'); // Prevent XSS
        ini_set('session.cookie_samesite', 'Strict'); // CSRF protection
        ini_set('session.use_only_cookies', '1'); // No session IDs in URLs

        session_name($this->sessionName);
        session_start();
    }

    /**
     * Authenticate user with secure password verification
     */
    public function authenticate(string $email, string $password): bool
    {
        // Input validation
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return false;
        }

        if (strlen($password) < 8) {
            return false;
        }

        try {
            // Prepare statement to prevent SQL injection
            $stmt = $this->pdo->prepare("SELECT id, password_hash FROM users WHERE email = ? AND active = 1");
            $stmt->execute([$email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user) {
                // Always perform password verification to prevent timing attacks
                password_verify($password, '$2y$10$dummyhash');
                return false;
            }

            // Verify password using secure hash
            if (password_verify($password, $user['password_hash'])) {
                // Regenerate session ID to prevent session fixation
                session_regenerate_id(true);

                $_SESSION['user_id'] = $user['id'];
                $_SESSION['login_time'] = time();
                $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
                $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];

                return true;
            }

            return false;

        } catch (PDOException $e) {
            // Log error securely (don't expose to user)
            error_log("Authentication error: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Check if user is authenticated
     */
    public function isAuthenticated(): bool
    {
        if (!isset($_SESSION['user_id'])) {
            return false;
        }

        // Check session timeout (30 minutes)
        if (time() - $_SESSION['login_time'] > 1800) {
            $this->logout();
            return false;
        }

        // Check IP address consistency
        if ($_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
            $this->logout();
            return false;
        }

        // Check user agent consistency (optional, but adds security)
        if ($_SESSION['user_agent'] !== $_SERVER['HTTP_USER_AGENT']) {
            $this->logout();
            return false;
        }

        return true;
    }

    /**
     * Secure logout
     */
    public function logout(): void
    {
        // Clear session data
        $_SESSION = [];

        // Delete session cookie
        if (isset($_COOKIE[session_name()])) {
            setcookie(session_name(), '', time() - 3600, '/', '', true, true);
        }

        // Destroy session
        session_destroy();
    }

    /**
     * Get current user ID
     */
    public function getCurrentUserId(): ?int
    {
        return $_SESSION['user_id'] ?? null;
    }
}

// Usage example:
/*
try {
    $pdo = new PDO("mysql:host=localhost;dbname=secure_app", "user", "password", [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);

    $login = new SecureLogin($pdo);

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $email = $_POST['email'] ?? '';
        $password = $_POST['password'] ?? '';

        if ($login->authenticate($email, $password)) {
            header('Location: /dashboard');
            exit;
        } else {
            $error = "Invalid credentials";
        }
    }

} catch (PDOException $e) {
    die("Database connection failed");
}
*/
?>
