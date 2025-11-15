# CSRF Protection

## What is CSRF?

Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated. CSRF attacks specifically target state-changing requests, not theft of data, since the attacker has no way to see the response to the forged request.

### How CSRF Works

1. **User Authentication**: Victim logs into a trusted site (bank, email, social media)
2. **Malicious Site**: Victim visits attacker's malicious website
3. **Forged Request**: Malicious site sends request to trusted site using victim's credentials
4. **Unwanted Action**: Trusted site executes action thinking it's legitimate

### Real-World CSRF Examples

#### Bank Transfer Attack
```html
<!-- Malicious website -->
<img src="http://bank.com/transfer?to=attacker&amount=1000" style="display:none">
```
When victim visits the malicious site, their browser automatically loads the image, which sends a GET request to transfer $1000 to the attacker.

#### Social Media Attack
```html
<!-- Hidden form on malicious site -->
<form action="http://socialmedia.com/follow" method="POST" style="display:none">
    <input type="hidden" name="user_id" value="attacker_id">
</form>
<script>document.forms[0].submit();</script>
```

#### Email Unsubscribe Attack
```html
<!-- In malicious email or website -->
<img src="http://newsletter.com/unsubscribe?user_id=12345">
```

## CSRF Attack Vectors

### 1. GET-based CSRF
```html
<img src="http://example.com/delete?id=123">
<link rel="stylesheet" href="http://example.com/delete?id=123">
<script src="http://example.com/delete?id=123"></script>
```

### 2. POST-based CSRF
```html
<form action="http://example.com/transfer" method="POST" id="csrf-form">
    <input type="hidden" name="to" value="attacker">
    <input type="hidden" name="amount" value="500">
</form>
<script>document.getElementById('csrf-form').submit();</script>
```

### 3. JSON-based CSRF (Modern APIs)
```html
<script>
fetch('/api/user/update', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({name: 'Hacked'})
});
</script>
```

### 4. Login CSRF
```html
<form action="http://example.com/login" method="POST">
    <input name="username" value="victim_username">
    <input name="password" value="attacker_password">
</form>
```

## Why CSRF Protection Matters

### Impact of CSRF Attacks

- **Data Manipulation**: Unauthorized changes to user data
- **Financial Loss**: Unauthorized transactions or transfers
- **Account Takeover**: Changing passwords or email addresses
- **Privacy Violation**: Unauthorized posting or sharing
- **System Compromise**: Escalating privileges or deleting data

### CSRF vs XSS Comparison

| Aspect | CSRF | XSS |
|--------|------|-----|
| **Target** | Actions | Data theft |
| **Authentication** | Uses victim's session | Bypasses authentication |
| **User Interaction** | Victim visits malicious site | Victim clicks malicious link |
| **Prevention** | Anti-CSRF tokens | Input validation & output escaping |
| **Scope** | State-changing operations | Any user-controllable output |

## CSRF Protection Strategies

### 1. Synchronizer Token Pattern (Recommended)

#### How It Works
1. Server generates unique token for each user session/form
2. Token included in all state-changing requests
3. Server validates token before processing request
4. Tokens expire with session or have short lifetimes

#### Implementation
```php
<?php
class CSRFTokenManager
{
    private const TOKEN_LENGTH = 32;
    private const TOKEN_LIFETIME = 3600; // 1 hour

    public static function generateToken(): string
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $token = bin2hex(random_bytes(self::TOKEN_LENGTH));
        $_SESSION['csrf_token'] = $token;
        $_SESSION['csrf_token_time'] = time();

        return $token;
    }

    public static function validateToken(string $token): bool
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        // Check if token exists
        if (!isset($_SESSION['csrf_token'])) {
            return false;
        }

        // Check token value
        if (!hash_equals($_SESSION['csrf_token'], $token)) {
            return false;
        }

        // Check token lifetime
        if (isset($_SESSION['csrf_token_time'])) {
            $tokenAge = time() - $_SESSION['csrf_token_time'];
            if ($tokenAge > self::TOKEN_LIFETIME) {
                self::clearToken();
                return false;
            }
        }

        // Token is valid - clear it to prevent reuse
        self::clearToken();
        return true;
    }

    public static function getToken(): string
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        // Generate token if it doesn't exist or is expired
        if (!isset($_SESSION['csrf_token']) ||
            !isset($_SESSION['csrf_token_time']) ||
            (time() - $_SESSION['csrf_token_time']) > self::TOKEN_LIFETIME) {
            return self::generateToken();
        }

        return $_SESSION['csrf_token'];
    }

    private static function clearToken(): void
    {
        unset($_SESSION['csrf_token'], $_SESSION['csrf_token_time']);
    }
}
```

### 2. Double Submit Cookie Pattern

#### How It Works
1. Token stored in both session and cookie
2. Client sends token in both cookie and POST data
3. Server compares both values

#### Implementation
```php
<?php
class DoubleSubmitCookieCSRF
{
    private const COOKIE_NAME = 'csrf_token';
    private const TOKEN_LENGTH = 32;

    public static function generateToken(): string
    {
        $token = bin2hex(random_bytes(self::TOKEN_LENGTH));

        // Store in session
        $_SESSION[self::COOKIE_NAME] = $token;

        // Set httpOnly cookie
        setcookie(self::COOKIE_NAME, $token, [
            'httponly' => true,
            'secure' => true,
            'samesite' => 'Strict',
            'path' => '/',
        ]);

        return $token;
    }

    public static function validateToken(string $token): bool
    {
        // Get token from session and cookie
        $sessionToken = $_SESSION[self::COOKIE_NAME] ?? null;
        $cookieToken = $_COOKIE[self::COOKIE_NAME] ?? null;

        // Both must exist and match
        if (!$sessionToken || !$cookieToken) {
            return false;
        }

        // Use hash_equals for timing attack protection
        return hash_equals($sessionToken, $token) &&
               hash_equals($cookieToken, $token);
    }

    public static function getToken(): string
    {
        return $_SESSION[self::COOKIE_NAME] ?? self::generateToken();
    }
}
```

### 3. Origin Header Validation

#### How It Works
1. Check `Origin` or `Referer` headers
2. Ensure request comes from same origin
3. Reject requests from different origins

#### Implementation
```php
<?php
class OriginValidator
{
    public static function validateOrigin(string $allowedOrigin = null): bool
    {
        $allowedOrigin = $allowedOrigin ?? self::getCurrentOrigin();

        // Check Origin header first (more reliable)
        $origin = $_SERVER['HTTP_ORIGIN'] ?? null;
        if ($origin) {
            return self::isSameOrigin($origin, $allowedOrigin);
        }

        // Fallback to Referer header
        $referer = $_SERVER['HTTP_REFERER'] ?? null;
        if ($referer) {
            return self::isSameOrigin($referer, $allowedOrigin);
        }

        // No origin headers - could be legitimate (curl, etc.)
        // Consider rejecting or requiring additional validation
        return false;
    }

    private static function getCurrentOrigin(): string
    {
        $scheme = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        return $scheme . '://' . $host;
    }

    private static function isSameOrigin(string $url1, string $url2): bool
    {
        $parsed1 = parse_url($url1);
        $parsed2 = parse_url($url2);

        if (!$parsed1 || !$parsed2) {
            return false;
        }

        return ($parsed1['scheme'] ?? '') === ($parsed2['scheme'] ?? '') &&
               ($parsed1['host'] ?? '') === ($parsed2['host'] ?? '') &&
               ($parsed1['port'] ?? null) === ($parsed2['port'] ?? null);
    }
}
```

## Laravel CSRF Protection

### Built-in CSRF Protection

Laravel provides automatic CSRF protection through middleware.

#### Configuration
```php
// In app/Http/Kernel.php
protected $middlewareGroups = [
    'web' => [
        \App\Http\Middleware\EncryptCookies::class,
        \Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse::class,
        \Illuminate\Session\Middleware\StartSession::class,
        \Illuminate\View\Middleware\ShareErrorsFromSession::class,
        \App\Http\Middleware\VerifyCsrfToken::class, // CSRF Protection
        \Illuminate\Routing\Middleware\SubstituteBindings::class,
    ],
];
```

#### Using CSRF Tokens in Forms
```blade
{{-- Laravel Blade template --}}
<form action="/post" method="POST">
    @csrf  {{-- Laravel automatically generates and includes CSRF token --}}
    <input type="text" name="title">
    <button type="submit">Submit</button>
</form>
```

#### Manual CSRF Token Usage
```php
// In controller or view
$token = csrf_token(); // Laravel helper

// Or in Blade
{{ csrf_token() }}
```

#### API CSRF Protection
```php
// For API routes, use Sanctum or Passport
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens;
}

// In API routes
Route::middleware('auth:sanctum')->group(function () {
    Route::post('/user/profile', [UserController::class, 'update']);
});
```

### Custom CSRF Middleware

```php
<?php
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class CustomCsrfMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        // Skip CSRF check for certain routes
        if ($this->shouldSkipCsrfCheck($request)) {
            return $next($request);
        }

        // Check CSRF token for state-changing methods
        if ($this->isStateChangingMethod($request->method())) {
            if (!$request->hasHeader('X-CSRF-TOKEN') &&
                !$request->has('_token')) {
                Log::warning('CSRF token missing', [
                    'url' => $request->fullUrl(),
                    'method' => $request->method(),
                    'ip' => $request->ip(),
                ]);
                return response('CSRF token missing', 419);
            }

            $token = $request->header('X-CSRF-TOKEN') ??
                    $request->input('_token');

            if (!hash_equals($request->session()->token(), $token)) {
                Log::warning('CSRF token mismatch', [
                    'url' => $request->fullUrl(),
                    'method' => $request->method(),
                    'ip' => $request->ip(),
                ]);
                return response('CSRF token mismatch', 419);
            }
        }

        return $next($request);
    }

    private function shouldSkipCsrfCheck(Request $request): bool
    {
        // Skip for API routes
        if ($request->is('api/*')) {
            return true;
        }

        // Skip for webhook endpoints
        if ($request->is('webhooks/*')) {
            return true;
        }

        return false;
    }

    private function isStateChangingMethod(string $method): bool
    {
        return in_array(strtoupper($method), ['POST', 'PUT', 'PATCH', 'DELETE']);
    }
}
```

## PHP Manual CSRF Protection

### Basic CSRF Protection Class

```php
<?php
class CSRFProtection
{
    private const TOKEN_NAME = '_csrf_token';
    private const TOKEN_LENGTH = 32;
    private const TOKEN_LIFETIME = 3600; // 1 hour

    public static function init(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        // Generate token if needed
        if (!isset($_SESSION[self::TOKEN_NAME]) ||
            self::isTokenExpired()) {
            self::generateToken();
        }
    }

    public static function generateToken(): string
    {
        $token = bin2hex(random_bytes(self::TOKEN_LENGTH));
        $_SESSION[self::TOKEN_NAME] = $token;
        $_SESSION[self::TOKEN_NAME . '_time'] = time();
        return $token;
    }

    public static function getToken(): string
    {
        self::init();
        return $_SESSION[self::TOKEN_NAME];
    }

    public static function validateToken(string $token = null): bool
    {
        self::init();

        // Get token from various sources
        $token = $token ??
                $_POST[self::TOKEN_NAME] ??
                $_GET[self::TOKEN_NAME] ??
                $_SERVER['HTTP_X_CSRF_TOKEN'] ??
                '';

        if (empty($token)) {
            return false;
        }

        // Validate token
        if (!isset($_SESSION[self::TOKEN_NAME]) ||
            !hash_equals($_SESSION[self::TOKEN_NAME], $token)) {
            return false;
        }

        // Check expiration
        if (self::isTokenExpired()) {
            self::clearToken();
            return false;
        }

        // Token is valid - optionally clear it to prevent reuse
        // self::clearToken();

        return true;
    }

    private static function isTokenExpired(): bool
    {
        if (!isset($_SESSION[self::TOKEN_NAME . '_time'])) {
            return true;
        }

        return (time() - $_SESSION[self::TOKEN_NAME . '_time']) > self::TOKEN_LIFETIME;
    }

    private static function clearToken(): void
    {
        unset(
            $_SESSION[self::TOKEN_NAME],
            $_SESSION[self::TOKEN_NAME . '_time']
        );
    }
}
```

### Using CSRF Protection in Forms

```php
<?php
// Initialize CSRF protection
CSRFProtection::init();
?>

<!-- HTML Form with CSRF Protection -->
<form action="/transfer" method="POST">
    <input type="hidden" name="_csrf_token" value="<?php echo CSRFProtection::getToken(); ?>">
    <input type="text" name="to_account" placeholder="Recipient Account">
    <input type="number" name="amount" placeholder="Amount">
    <button type="submit">Transfer Money</button>
</form>
```

### Protecting API Endpoints

```php
<?php
class SecureAPIController
{
    public function handleRequest(): void
    {
        // Validate CSRF token for state-changing operations
        if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
            if (!CSRFProtection::validateToken()) {
                http_response_code(403);
                echo json_encode(['error' => 'CSRF token validation failed']);
                exit;
            }
        }

        // Process request...
    }
}
```

### AJAX CSRF Protection

```javascript
// JavaScript for AJAX requests
function makeSecureRequest(url, data) {
    // Add CSRF token to request
    data._csrf_token = '<?php echo CSRFProtection::getToken(); ?>';

    return fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': '<?php echo CSRFProtection::getToken(); ?>'
        },
        body: JSON.stringify(data)
    });
}
```

## Advanced CSRF Protection Techniques

### 1. Encrypted Tokens

```php
<?php
class EncryptedCSRFToken
{
    private static $key;

    public static function setEncryptionKey(string $key): void
    {
        self::$key = $key;
    }

    public static function generateEncryptedToken(): string
    {
        $data = json_encode([
            'token' => bin2hex(random_bytes(16)),
            'timestamp' => time(),
            'user_id' => $_SESSION['user_id'] ?? null,
        ]);

        return self::encrypt($data);
    }

    public static function validateEncryptedToken(string $encryptedToken): bool
    {
        $data = self::decrypt($encryptedToken);
        if (!$data) return false;

        $payload = json_decode($data, true);
        if (!$payload) return false;

        // Check timestamp (5 minute window)
        if ((time() - $payload['timestamp']) > 300) {
            return false;
        }

        // Check user ID
        if (isset($payload['user_id']) &&
            $payload['user_id'] !== ($_SESSION['user_id'] ?? null)) {
            return false;
        }

        return true;
    }

    private static function encrypt(string $data): string
    {
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', self::$key, 0, $iv);
        return base64_encode($iv . $encrypted);
    }

    private static function decrypt(string $data): ?string
    {
        $data = base64_decode($data);
        if (strlen($data) < 16) return null;

        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);

        return openssl_decrypt($encrypted, 'AES-256-CBC', self::$key, 0, $iv);
    }
}
```

### 2. HMAC-Based Tokens

```php
<?php
class HMACCsrfToken
{
    private static $secret;

    public static function setSecret(string $secret): void
    {
        self::$secret = $secret;
    }

    public static function generateHMACToken(): string
    {
        $data = [
            'timestamp' => time(),
            'user_id' => $_SESSION['user_id'] ?? 0,
            'nonce' => bin2hex(random_bytes(8)),
        ];

        $message = json_encode($data);
        $hmac = hash_hmac('sha256', $message, self::$secret);

        return base64_encode(json_encode([
            'data' => $data,
            'hmac' => $hmac
        ]));
    }

    public static function validateHMACToken(string $token): bool
    {
        $payload = json_decode(base64_decode($token), true);
        if (!$payload || !isset($payload['data'], $payload['hmac'])) {
            return false;
        }

        $message = json_encode($payload['data']);
        $expectedHmac = hash_hmac('sha256', $message, self::$secret);

        if (!hash_equals($expectedHmac, $payload['hmac'])) {
            return false;
        }

        // Check timestamp (5 minute window)
        if ((time() - $payload['data']['timestamp']) > 300) {
            return false;
        }

        return true;
    }
}
```

## CSRF Protection for Different Frameworks

### CodeIgniter CSRF Protection

```php
// In config.php
$config['csrf_protection'] = TRUE;
$config['csrf_token_name'] = 'csrf_token_name';
$config['csrf_cookie_name'] = 'csrf_cookie_name';
$config['csrf_expire'] = 7200; // 2 hours
```

### Symfony CSRF Protection

```php
// In controller
use Symfony\Component\Security\Csrf\CsrfTokenManager;

class MyController extends AbstractController
{
    public function submitForm(Request $request, CsrfTokenManager $csrfTokenManager)
    {
        $token = new CsrfToken('form_token', $request->request->get('_token'));

        if (!$csrfTokenManager->isTokenValid($token)) {
            throw new Exception('CSRF token is invalid');
        }

        // Process form...
    }
}
```

## Testing CSRF Protection

### Manual Testing

```html
<!-- Test form without CSRF token -->
<form action="/transfer" method="POST">
    <input type="hidden" name="to" value="attacker">
    <input type="hidden" name="amount" value="100">
    <input type="submit" value="Test CSRF">
</form>
```

### Automated Testing

```php
<?php
class CSRFProtectionTest
{
    public function testCSRFProtection(): void
    {
        // Start session
        CSRFProtection::init();

        // Test token generation
        $token = CSRFProtection::getToken();
        $this->assertNotEmpty($token);
        $this->assertEquals(64, strlen($token)); // 32 bytes hex encoded

        // Test token validation
        $this->assertTrue(CSRFProtection::validateToken($token));

        // Test invalid token
        $this->assertFalse(CSRFProtection::validateToken('invalid_token'));

        // Test token reuse (if one-time tokens)
        // $this->assertFalse(CSRFProtection::validateToken($token));
    }

    public function testLaravelCSRF(): void
    {
        // Test Laravel CSRF token
        $token = csrf_token();
        $this->assertNotEmpty($token);

        // Test form with CSRF token
        $response = $this->post('/protected-endpoint', [
            '_token' => $token,
            'data' => 'test'
        ]);

        $response->assertStatus(200);
    }
}
```

## Common CSRF Vulnerabilities

### 1. Missing CSRF Protection

```php
<?php
// VULNERABLE: No CSRF protection
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $userId = $_SESSION['user_id'];
    $newEmail = $_POST['email'];

    // Update email without CSRF check
    updateUserEmail($userId, $newEmail);
}
```

### 2. Weak Token Generation

```php
<?php
// VULNERABLE: Predictable tokens
$token = md5($_SESSION['user_id'] . time()); // Predictable

// BETTER but still vulnerable to timing attacks
$token = md5(uniqid(mt_rand(), true));
```

### 3. Token in URL Parameters

```php
<?php
// PROBLEMATIC: Token in URL (logged in access logs)
$form = "<form action='/action?_csrf_token={$token}' method='POST'>";
```

### 4. Missing Origin Validation

```php
<?php
// WEAK: Only checking Referer (can be spoofed)
$referer = $_SERVER['HTTP_REFERER'];
if (strpos($referer, 'trusted-domain.com') === false) {
    die('CSRF detected');
}
```

## CSRF Protection Best Practices

1. **Use Synchronizer Tokens**: Generate unique tokens per request/session
2. **Validate Origin Headers**: Check Origin and Referer headers
3. **Use Secure Tokens**: Cryptographically secure random tokens
4. **Implement Token Expiration**: Tokens should expire
5. **Use HTTPS**: Prevents token interception
6. **Validate on Server**: Client-side validation can be bypassed
7. **Log CSRF Attempts**: Monitor and alert on suspicious activity
8. **Use Framework Features**: Leverage built-in CSRF protection
9. **Test Thoroughly**: Include CSRF testing in security audits
10. **Keep Updated**: Stay current with security best practices

## Summary

CSRF attacks exploit the trust between users and web applications. The most effective protection combines:

- **Anti-CSRF tokens** in all state-changing forms
- **Origin header validation** for additional security
- **Proper session management** to prevent fixation
- **Framework-provided protections** (Laravel's built-in CSRF)

Remember: CSRF protection is essential for any application that maintains user sessions and processes state-changing requests.

## Next Steps

Now that you understand CSRF protection, explore:

- **[XSS Protection](XSSProtection.md)** - Prevent cross-site scripting attacks
- **[Session Security](SessionSecurity.md)** - Secure session management
- **[Input Handling](InputHandling.md)** - Validate and sanitize user input

CSRF protection is a critical component of web application security. Implement it consistently across all user-facing forms and API endpoints!
