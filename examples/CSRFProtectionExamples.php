<?php

/**
 * CSRF Protection Examples: Vulnerable vs Secure Implementations
 *
 * Practical examples of CSRF vulnerabilities and their secure solutions
 */

declare(strict_types=1);

// =============================================================================
// 1. BASIC CSRF VULNERABILITIES
// =============================================================================

class CSRFVulnerabilities
{
    private PDO $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    /**
     * ❌ VULNERABLE: No CSRF protection
     * Attacker can create a form that submits to this endpoint
     */
    public function transferMoneyVulnerable(): void
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            return;
        }

        // NO CSRF CHECK - VULNERABLE!
        $fromAccount = $_SESSION['user_id'];
        $toAccount = (int) $_POST['to_account'];
        $amount = (float) $_POST['amount'];

        // Process transfer
        $this->transferFunds($fromAccount, $toAccount, $amount);

        echo "Transfer completed!";
    }

    /**
     * ❌ VULNERABLE: GET-based CSRF
     * Even worse - can be triggered by <img src="..."> tags
     */
    public function deleteAccountVulnerable(): void
    {
        $userId = (int) $_GET['user_id'];

        // NO CSRF CHECK - EXTREMELY VULNERABLE!
        $stmt = $this->pdo->prepare("DELETE FROM users WHERE id = ?");
        $stmt->execute([$userId]);

        echo "Account deleted!";
    }

    /**
     * ❌ VULNERABLE: Weak CSRF "protection"
     * Using Referer header (easily spoofed)
     */
    public function updateProfileVulnerable(): void
    {
        // WEAK PROTECTION: Referer can be spoofed or missing
        $referer = $_SERVER['HTTP_REFERER'] ?? '';

        if (strpos($referer, 'trusted-domain.com') === false) {
            die('CSRF detected');
        }

        // Process update
        $name = $_POST['name'];
        $email = $_POST['email'];

        $this->updateUserProfile($name, $email);
    }

    private function transferFunds(int $from, int $to, float $amount): void
    {
        // Implementation not shown
    }

    private function updateUserProfile(string $name, string $email): void
    {
        // Implementation not shown
    }
}

// =============================================================================
// 2. SYNCHRONIZER TOKEN PATTERN IMPLEMENTATION
// =============================================================================

class SynchronizerTokenCSRF
{
    private const TOKEN_NAME = '_csrf_token';
    private const TOKEN_LENGTH = 32;
    private const TOKEN_LIFETIME = 3600; // 1 hour

    public static function init(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }

    /**
     * Generate a new CSRF token
     */
    public static function generateToken(): string
    {
        self::init();

        $token = bin2hex(random_bytes(self::TOKEN_LENGTH));
        $_SESSION[self::TOKEN_NAME] = $token;
        $_SESSION[self::TOKEN_NAME . '_time'] = time();

        return $token;
    }

    /**
     * Get current token (generate if needed)
     */
    public static function getToken(): string
    {
        self::init();

        if (!isset($_SESSION[self::TOKEN_NAME]) ||
            self::isTokenExpired()) {
            return self::generateToken();
        }

        return $_SESSION[self::TOKEN_NAME];
    }

    /**
     * Validate CSRF token
     */
    public static function validateToken(?string $token = null): bool
    {
        self::init();

        // Get token from various sources
        $token = $token ??
                $_POST[self::TOKEN_NAME] ??
                $_GET[self::TOKEN_NAME] ??
                $_SERVER['HTTP_X_CSRF_TOKEN'] ??
                '';

        if (empty($token) || empty($_SESSION[self::TOKEN_NAME])) {
            return false;
        }

        // Use hash_equals for timing attack protection
        if (!hash_equals($_SESSION[self::TOKEN_NAME], $token)) {
            return false;
        }

        // Check expiration
        if (self::isTokenExpired()) {
            self::clearToken();
            return false;
        }

        // Optional: Clear token after use (one-time tokens)
        // self::clearToken();

        return true;
    }

    /**
     * Clear current token
     */
    private static function clearToken(): void
    {
        unset(
            $_SESSION[self::TOKEN_NAME],
            $_SESSION[self::TOKEN_NAME . '_time']
        );
    }

    /**
     * Check if token is expired
     */
    private static function isTokenExpired(): bool
    {
        $tokenTime = $_SESSION[self::TOKEN_NAME . '_time'] ?? 0;
        return (time() - $tokenTime) > self::TOKEN_LIFETIME;
    }

    /**
     * Middleware-style CSRF protection
     */
    public static function protectRequest(): void
    {
        // Skip CSRF check for safe methods
        $safeMethods = ['GET', 'HEAD', 'OPTIONS'];
        if (in_array($_SERVER['REQUEST_METHOD'], $safeMethods)) {
            return;
        }

        // Validate token for state-changing requests
        if (!self::validateToken()) {
            http_response_code(403);
            echo json_encode([
                'error' => 'CSRF token validation failed',
                'message' => 'Request rejected due to security policy'
            ]);
            exit;
        }
    }
}

// =============================================================================
// 3. SECURE CONTROLLER WITH CSRF PROTECTION
// =============================================================================

class SecureController
{
    public function __construct()
    {
        // Apply CSRF protection to all state-changing methods
        SynchronizerTokenCSRF::protectRequest();
    }

    /**
     * ✅ SECURE: Transfer money with CSRF protection
     */
    public function transferMoney(): void
    {
        // CSRF protection already validated in constructor

        $toAccount = filter_var($_POST['to_account'], FILTER_VALIDATE_INT);
        $amount = filter_var($_POST['amount'], FILTER_VALIDATE_FLOAT);

        if (!$toAccount || !$amount || $amount <= 0) {
            echo json_encode(['error' => 'Invalid transfer parameters']);
            return;
        }

        // Process secure transfer
        $this->processTransfer($_SESSION['user_id'], $toAccount, $amount);

        echo json_encode(['success' => true, 'message' => 'Transfer completed']);
    }

    /**
     * ✅ SECURE: Update profile with CSRF protection
     */
    public function updateProfile(): void
    {
        // CSRF protection already validated

        $name = trim($_POST['name'] ?? '');
        $email = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL);

        if (empty($name) || !$email) {
            echo json_encode(['error' => 'Invalid profile data']);
            return;
        }

        // Update profile securely
        $this->updateUserProfile($_SESSION['user_id'], $name, $email);

        echo json_encode(['success' => true, 'message' => 'Profile updated']);
    }

    private function processTransfer(int $from, int $to, float $amount): void
    {
        // Secure transfer implementation
    }

    private function updateUserProfile(int $userId, string $name, string $email): void
    {
        // Secure profile update implementation
    }
}

// =============================================================================
// 4. DOUBLE SUBMIT COOKIE PATTERN
// =============================================================================

class DoubleSubmitCookieCSRF
{
    private const COOKIE_NAME = 'csrf_token';

    /**
     * Generate and set CSRF token in both session and cookie
     */
    public static function generateToken(): string
    {
        $token = bin2hex(random_bytes(32));

        // Store in session
        $_SESSION[self::COOKIE_NAME] = $token;

        // Set httpOnly cookie
        setcookie(self::COOKIE_NAME, $token, [
            'expires' => time() + 3600, // 1 hour
            'path' => '/',
            'domain' => '', // Current domain only
            'secure' => isset($_SERVER['HTTPS']), // HTTPS only
            'httponly' => true, // JavaScript cannot access
            'samesite' => 'Strict'
        ]);

        return $token;
    }

    /**
     * Validate double-submit cookie token
     */
    public static function validateToken(string $token): bool
    {
        $sessionToken = $_SESSION[self::COOKIE_NAME] ?? null;
        $cookieToken = $_COOKIE[self::COOKIE_NAME] ?? null;

        // Both must exist and match the provided token
        return $sessionToken &&
               $cookieToken &&
               hash_equals($sessionToken, $token) &&
               hash_equals($cookieToken, $token);
    }

    /**
     * Get current token
     */
    public static function getToken(): string
    {
        return $_SESSION[self::COOKIE_NAME] ?? self::generateToken();
    }
}

// =============================================================================
// 5. ORIGIN HEADER VALIDATION
// =============================================================================

class OriginBasedCSRF
{
    /**
     * Validate request origin for CSRF protection
     */
    public static function validateOrigin(string $expectedOrigin = null): bool
    {
        $expectedOrigin = $expectedOrigin ?? self::getExpectedOrigin();

        // Check Origin header first (more reliable than Referer)
        $origin = $_SERVER['HTTP_ORIGIN'] ?? null;
        if ($origin) {
            return self::isSameOrigin($origin, $expectedOrigin);
        }

        // Fallback to Referer header
        $referer = $_SERVER['HTTP_REFERER'] ?? null;
        if ($referer) {
            return self::isSameOrigin($referer, $expectedOrigin);
        }

        // No origin headers - reject for state-changing requests
        return false;
    }

    /**
     * Get expected origin for current request
     */
    private static function getExpectedOrigin(): string
    {
        $scheme = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        return $scheme . '://' . $host;
    }

    /**
     * Check if two URLs have the same origin
     */
    private static function isSameOrigin(string $url1, string $url2): bool
    {
        $parsed1 = parse_url($url1);
        $parsed2 = parse_url($url2);

        if (!$parsed1 || !$parsed2) {
            return false;
        }

        // Compare scheme, host, and port
        return ($parsed1['scheme'] ?? '') === ($parsed2['scheme'] ?? '') &&
               strtolower($parsed1['host'] ?? '') === strtolower($parsed2['host'] ?? '') &&
               ($parsed1['port'] ?? self::getDefaultPort($parsed1['scheme'] ?? '')) ===
               ($parsed2['port'] ?? self::getDefaultPort($parsed2['scheme'] ?? ''));
    }

    /**
     * Get default port for scheme
     */
    private static function getDefaultPort(string $scheme): int
    {
        return match (strtolower($scheme)) {
            'https' => 443,
            'http' => 80,
            default => 80
        };
    }

    /**
     * Combined CSRF protection (token + origin)
     */
    public static function comprehensiveProtection(string $token): bool
    {
        // Check origin first
        if (!self::validateOrigin()) {
            return false;
        }

        // Then check token
        return SynchronizerTokenCSRF::validateToken($token);
    }
}

// =============================================================================
// 6. HTML FORMS WITH CSRF PROTECTION
// =============================================================================

class SecureFormGenerator
{
    /**
     * Generate secure HTML form with CSRF token
     */
    public static function createSecureForm(
        string $action,
        string $method = 'POST',
        array $fields = [],
        array $attributes = []
    ): string {
        $method = strtoupper($method);

        // Build form tag
        $formAttrs = array_merge([
            'action' => htmlspecialchars($action),
            'method' => $method
        ], $attributes);

        $formAttrString = self::buildAttributes($formAttrs);
        $html = "<form{$formAttrString}>";

        // Add CSRF token for non-GET forms
        if ($method !== 'GET') {
            $token = SynchronizerTokenCSRF::getToken();
            $html .= "\n    <input type=\"hidden\" name=\"_csrf_token\" value=\"{$token}\">";
        }

        // Add form fields
        foreach ($fields as $name => $config) {
            $type = $config['type'] ?? 'text';
            $value = $config['value'] ?? '';
            $label = $config['label'] ?? ucfirst($name);
            $required = $config['required'] ?? false;
            $placeholder = $config['placeholder'] ?? '';

            $html .= "\n    <div>";
            $html .= "\n        <label for=\"{$name}\">{$label}</label>";

            $fieldAttrs = [
                'type' => $type,
                'name' => $name,
                'id' => $name,
                'value' => htmlspecialchars($value)
            ];

            if ($required) $fieldAttrs['required'] = 'required';
            if ($placeholder) $fieldAttrs['placeholder'] = $placeholder;

            $fieldAttrString = self::buildAttributes($fieldAttrs);
            $html .= "\n        <input{$fieldAttrString}>";
            $html .= "\n    </div>";
        }

        // Add submit button
        $html .= "\n    <button type=\"submit\">Submit</button>";
        $html .= "\n</form>";

        return $html;
    }

    /**
     * Build HTML attributes string
     */
    private static function buildAttributes(array $attributes): string
    {
        $parts = [];
        foreach ($attributes as $name => $value) {
            if ($value === true) {
                $parts[] = htmlspecialchars($name);
            } elseif ($value !== false && $value !== null) {
                $parts[] = htmlspecialchars($name) . '="' . htmlspecialchars($value) . '"';
            }
        }
        return $parts ? ' ' . implode(' ', $parts) : '';
    }
}

// =============================================================================
// 7. LARAVEL CSRF PROTECTION EXAMPLES
// =============================================================================

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;

class LaravelSecureController extends Controller
{
    /**
     * Laravel automatically provides CSRF protection via middleware
     * The VerifyCsrfToken middleware validates tokens automatically
     */

    /**
     * ✅ SECURE: Transfer money (Laravel CSRF protection active)
     */
    public function transferMoney(Request $request)
    {
        // Laravel automatically validates CSRF token
        // No manual validation needed!

        $validated = $request->validate([
            'to_account' => 'required|integer|exists:users,id',
            'amount' => 'required|numeric|min:0.01|max:10000'
        ]);

        try {
            // Process transfer
            $this->processTransfer(
                Auth::id(),
                $validated['to_account'],
                $validated['amount']
            );

            return response()->json([
                'success' => true,
                'message' => 'Transfer completed successfully'
            ]);

        } catch (\Exception $e) {
            Log::error('Transfer failed', [
                'user_id' => Auth::id(),
                'error' => $e->getMessage()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Transfer failed'
            ], 500);
        }
    }

    /**
     * ✅ SECURE: Update profile with additional validation
     */
    public function updateProfile(Request $request)
    {
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users,email,' . Auth::id(),
            'bio' => 'nullable|string|max:1000'
        ]);

        Auth::user()->update($validated);

        return response()->json([
            'success' => true,
            'message' => 'Profile updated successfully'
        ]);
    }

    /**
     * AJAX endpoint with CSRF protection
     */
    public function ajaxAction(Request $request)
    {
        // CSRF token automatically validated by Laravel
        // For AJAX, token can be sent via header or form data

        $action = $request->input('action');

        return response()->json([
            'success' => true,
            'action' => $action,
            'timestamp' => now()
        ]);
    }

    private function processTransfer(int $fromUserId, int $toUserId, float $amount): void
    {
        // Secure transfer implementation
        // Use database transactions, etc.
    }
}

// =============================================================================
// 8. JAVASCRIPT CSRF PROTECTION
// =============================================================================

class JavaScriptCSRF
{
    /**
     * Generate JavaScript for CSRF-protected AJAX calls
     */
    public static function generateAjaxHelper(): string
    {
        $token = SynchronizerTokenCSRF::getToken();

        return "
        <script>
        // CSRF protection for AJAX requests
        function secureAjax(url, options = {}) {
            const csrfToken = '{$token}';

            // Set default headers
            options.headers = options.headers || {};
            options.headers['X-CSRF-TOKEN'] = csrfToken;

            // For POST/PUT/PATCH/DELETE, include token in data
            if (['POST', 'PUT', 'PATCH', 'DELETE'].includes((options.method || 'GET').toUpperCase())) {
                if (options.data) {
                    options.data._csrf_token = csrfToken;
                } else {
                    options.data = {_csrf_token: csrfToken};
                }
            }

            // Make request
            return fetch(url, options)
                .then(response => {
                    if (response.status === 419) { // CSRF token mismatch
                        alert('Security error: Please refresh the page and try again');
                        return Promise.reject(new Error('CSRF token expired'));
                    }
                    return response.json();
                });
        }

        // Example usage
        function updateProfile(data) {
            secureAjax('/profile/update', {
                method: 'POST',
                body: JSON.stringify(data),
                headers: {'Content-Type': 'application/json'}
            }).then(result => {
                console.log('Profile updated:', result);
            }).catch(error => {
                console.error('Update failed:', error);
            });
        }
        </script>
        ";
    }

    /**
     * Generate meta tag for JavaScript access to CSRF token
     */
    public static function generateMetaTag(): string
    {
        $token = SynchronizerTokenCSRF::getToken();
        return "<meta name=\"csrf-token\" content=\"{$token}\">";
    }
}

// =============================================================================
// 9. TESTING CSRF PROTECTION
// =============================================================================

class CSRFProtectionTester
{
    /**
     * Test CSRF token generation and validation
     */
    public static function testSynchronizerToken(): array
    {
        $results = [];

        // Test token generation
        SynchronizerTokenCSRF::init();
        $token = SynchronizerTokenCSRF::generateToken();
        $results['token_generated'] = !empty($token) && strlen($token) === 64;

        // Test token validation
        $results['token_valid'] = SynchronizerTokenCSRF::validateToken($token);

        // Test invalid token
        $results['invalid_token_rejected'] = !SynchronizerTokenCSRF::validateToken('invalid_token');

        return $results;
    }

    /**
     * Test double-submit cookie pattern
     */
    public static function testDoubleSubmitCookie(): array
    {
        $results = [];

        // Test token generation
        $token = DoubleSubmitCookieCSRF::generateToken();
        $results['cookie_token_generated'] = !empty($token);

        // Test validation
        $results['cookie_token_valid'] = DoubleSubmitCookieCSRF::validateToken($token);

        return $results;
    }

    /**
     * Test origin validation
     */
    public static function testOriginValidation(): array
    {
        $results = [];

        // Test same origin
        $_SERVER['HTTP_ORIGIN'] = 'http://localhost:8000';
        $results['same_origin_valid'] = OriginBasedCSRF::validateOrigin('http://localhost:8000');

        // Test different origin
        $_SERVER['HTTP_ORIGIN'] = 'http://evil.com';
        $results['different_origin_invalid'] = !OriginBasedCSRF::validateOrigin('http://localhost:8000');

        return $results;
    }

    /**
     * Simulate CSRF attack attempt
     */
    public static function simulateCSRFAttack(): string
    {
        // This would be the attacker's malicious page
        $token = 'simulated_stolen_token'; // Attacker doesn't have valid token

        // Try to make request without valid token
        $result = SynchronizerTokenCSRF::validateToken($token);

        return $result ? 'ATTACK SUCCESSFUL (Protection Failed)' : 'ATTACK BLOCKED (Protection Working)';
    }
}

// =============================================================================
// USAGE EXAMPLES AND DEMONSTRATIONS
// =============================================================================

/*
// INITIALIZATION
SynchronizerTokenCSRF::init();

// SECURE FORM GENERATION
$formHtml = SecureFormGenerator::createSecureForm('/transfer', 'POST', [
    'to_account' => ['type' => 'number', 'label' => 'To Account', 'required' => true],
    'amount' => ['type' => 'number', 'label' => 'Amount', 'required' => true, 'placeholder' => '0.00']
]);

echo $formHtml;

// JAVASCRIPT PROTECTION
echo JavaScriptCSRF::generateMetaTag();
echo JavaScriptCSRF::generateAjaxHelper();

// CONTROLLER USAGE
$controller = new SecureController();

// LARAVEL USAGE - CSRF protection is automatic with @csrf in forms
// <form action="/transfer" method="POST">
//     @csrf
//     <input name="to_account">
//     <input name="amount">
//     <button type="submit">Transfer</button>
// </form>

// TESTING
$testResults = CSRFProtectionTester::testSynchronizerToken();
print_r($testResults);

$attackResult = CSRFProtectionTester::simulateCSRFAttack();
echo "CSRF Attack Simulation: {$attackResult}";
*/
?>
