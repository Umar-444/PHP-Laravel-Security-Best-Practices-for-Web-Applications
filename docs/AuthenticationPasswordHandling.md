# Authentication & Password Handling

## Why Authentication Security Matters

Authentication is the gatekeeper of your application. Weak authentication allows attackers to impersonate legitimate users, leading to data breaches, financial loss, and reputation damage.

### Common Authentication Attacks

- **Brute Force**: Automated password guessing
- **Credential Stuffing**: Using leaked credentials from other breaches
- **Password Spraying**: Trying common passwords across many accounts
- **Session Hijacking**: Stealing session tokens
- **Man-in-the-Middle**: Intercepting authentication traffic

## Password Hashing Fundamentals

### What is Password Hashing?

Password hashing converts plain text passwords into irreversible strings. Unlike encryption, hashing cannot be reversed, making stolen hashes useless to attackers.

### Cryptographic Hash Functions

#### MD5 ❌ (Broken)
```php
// NEVER USE - Cryptographically broken
$hash = md5('password'); // Always same result, fast to crack
```

#### SHA-256 ❌ (Inadequate for passwords)
```php
// PROBLEMATIC - Designed for data integrity, not passwords
$hash = hash('sha256', 'password'); // No salt, fast to crack with rainbow tables
```

#### bcrypt ✅ (Recommended)
```php
// SECURE - Designed specifically for passwords
$hash = password_hash('password', PASSWORD_BCRYPT, [
    'cost' => 12 // Work factor (higher = slower = more secure)
]);
```

#### Argon2 ✅ (Modern alternative)
```php
// MOST SECURE - Winner of Password Hashing Competition
$hash = password_hash('password', PASSWORD_ARGON2ID, [
    'memory_cost' => 65536,  // 64MB
    'time_cost' => 4,        // 4 iterations
    'threads' => 3           // 3 parallel threads
]);
```

### Password Hashing Best Practices

#### 1. Use Built-in Functions
```php
<?php
// Always use password_hash() - it handles salt automatically
$password = 'user-input-password';

$options = [
    'cost' => 12,  // Increase for better security (slower)
];

// Default is bcrypt, but you can specify Argon2
$hash = password_hash($password, PASSWORD_DEFAULT, $options);

// Verify password
if (password_verify($password, $hash)) {
    // Password is correct
}
```

#### 2. Never Hash Twice
```php
<?php
// WRONG - Double hashing doesn't add security
$hash = md5(sha1('password')); // Still vulnerable

// RIGHT - Single proper hash
$hash = password_hash('password', PASSWORD_ARGON2ID);
```

#### 3. Use Appropriate Cost Factors
```php
<?php
// Balance security vs performance
$options = [
    // bcrypt cost: 10-14 (doubles time for each increase)
    'cost' => 12,

    // Argon2 parameters
    'memory_cost' => PASSWORD_ARGON2_DEFAULT_MEMORY_COST,  // 64MB
    'time_cost' => PASSWORD_ARGON2_DEFAULT_TIME_COST,      // 4
    'threads' => PASSWORD_ARGON2_DEFAULT_THREADS,          // 3
];

// Hash should take 0.1-0.5 seconds
$start = microtime(true);
$hash = password_hash($password, PASSWORD_ARGON2ID, $options);
$time = microtime(true) - $start;

if ($time > 0.5) {
    // Too slow - reduce cost
} elseif ($time < 0.1) {
    // Too fast - increase cost
}
```

## Session Management

### Session Security Basics

Sessions track authenticated users across requests. Poor session management leads to hijacking and fixation attacks.

#### Secure Session Configuration
```php
<?php
// Configure sessions securely
ini_set('session.cookie_secure', '1');     // HTTPS only
ini_set('session.cookie_httponly', '1');   // Prevent XSS theft
ini_set('session.cookie_samesite', 'Strict'); // CSRF protection
ini_set('session.use_only_cookies', '1');  // No session IDs in URLs
ini_set('session.cookie_lifetime', '0');   // Session cookies (expire on browser close)

// Set session name
session_name('SECURE_APP_SESSION');

// Start session
session_start();
```

#### Session Regeneration
```php
<?php
class SecureSession
{
    public static function startSecureSession(): void
    {
        // Secure configuration
        ini_set('session.cookie_secure', '1');
        ini_set('session.cookie_httponly', '1');
        ini_set('session.cookie_samesite', 'Strict');
        ini_set('session.use_only_cookies', '1');

        session_name('secure_app_' . md5(__FILE__));
        session_start();

        // Regenerate session ID periodically
        if (!isset($_SESSION['created'])) {
            $_SESSION['created'] = time();
        } elseif (time() - $_SESSION['created'] > 300) { // 5 minutes
            session_regenerate_id(true);
            $_SESSION['created'] = time();
        }
    }

    public static function storeUser(int $userId, string $username, string $role): void
    {
        $_SESSION['user_id'] = $userId;
        $_SESSION['username'] = $username;
        $_SESSION['role'] = $role;
        $_SESSION['login_time'] = time();
        $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
    }

    public static function isValid(): bool
    {
        // Check if session exists
        if (!isset($_SESSION['user_id'])) {
            return false;
        }

        // Check session timeout (30 minutes)
        if (time() - ($_SESSION['login_time'] ?? 0) > 1800) {
            self::destroy();
            return false;
        }

        // Check IP address consistency (optional)
        if (($_SESSION['ip_address'] ?? '') !== $_SERVER['REMOTE_ADDR']) {
            self::destroy();
            return false;
        }

        // Check user agent consistency (helps prevent some attacks)
        if (($_SESSION['user_agent'] ?? '') !== $_SERVER['HTTP_USER_AGENT']) {
            self::destroy();
            return false;
        }

        return true;
    }

    public static function destroy(): void
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
}
```

### Preventing Session Fixation

Session fixation occurs when an attacker sets a victim's session ID.

```php
<?php
class SecureLogin
{
    public function authenticate(string $username, string $password): bool
    {
        // Validate credentials (implementation not shown)
        if ($this->validateCredentials($username, $password)) {
            // CRITICAL: Regenerate session ID after successful login
            session_regenerate_id(true);

            // Store user data in new session
            $_SESSION['user_id'] = $this->getUserId($username);
            $_SESSION['login_time'] = time();

            return true;
        }

        return false;
    }
}
```

## Secure Login Flow

### Complete Authentication Process

```php
<?php
class AuthenticationManager
{
    private PDO $pdo;
    private int $maxLoginAttempts = 5;
    private int $lockoutTime = 900; // 15 minutes

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    public function login(string $username, string $password, string $ipAddress): array
    {
        // Check if account is locked
        if ($this->isAccountLocked($username)) {
            return [
                'success' => false,
                'message' => 'Account is temporarily locked due to too many failed attempts'
            ];
        }

        // Get user from database
        $user = $this->getUserByUsername($username);
        if (!$user) {
            $this->recordFailedAttempt($username, $ipAddress);
            return [
                'success' => false,
                'message' => 'Invalid username or password'
            ];
        }

        // Verify password
        if (!password_verify($password, $user['password_hash'])) {
            $this->recordFailedAttempt($username, $ipAddress);
            return [
                'success' => false,
                'message' => 'Invalid username or password'
            ];
        }

        // Check if account is active
        if (!$user['active']) {
            return [
                'success' => false,
                'message' => 'Account is deactivated'
            ];
        }

        // Successful login
        $this->clearFailedAttempts($username);

        // Regenerate session ID
        session_regenerate_id(true);

        // Store user session
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        $_SESSION['login_time'] = time();
        $_SESSION['ip_address'] = $ipAddress;

        return [
            'success' => true,
            'message' => 'Login successful',
            'user' => [
                'id' => $user['id'],
                'username' => $user['username'],
                'role' => $user['role']
            ]
        ];
    }

    private function getUserByUsername(string $username): ?array
    {
        $stmt = $this->pdo->prepare("
            SELECT id, username, password_hash, role, active
            FROM users
            WHERE username = ? AND active = 1
        ");
        $stmt->execute([$username]);

        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    private function isAccountLocked(string $username): bool
    {
        $stmt = $this->pdo->prepare("
            SELECT COUNT(*) as attempts, MAX(attempt_time) as last_attempt
            FROM login_attempts
            WHERE username = ? AND attempt_time > DATE_SUB(NOW(), INTERVAL 15 MINUTE)
        ");
        $stmt->execute([$username]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        return $result['attempts'] >= $this->maxLoginAttempts;
    }

    private function recordFailedAttempt(string $username, string $ipAddress): void
    {
        $stmt = $this->pdo->prepare("
            INSERT INTO login_attempts (username, ip_address, attempt_time)
            VALUES (?, ?, NOW())
        ");
        $stmt->execute([$username, $ipAddress]);
    }

    private function clearFailedAttempts(string $username): void
    {
        $stmt = $this->pdo->prepare("
            DELETE FROM login_attempts
            WHERE username = ?
        ");
        $stmt->execute([$username]);
    }
}
```

## Password Policies

### Strong Password Requirements

```php
<?php
class PasswordPolicy
{
    public static function validatePassword(string $password): array
    {
        $errors = [];
        $score = 0;

        // Length check
        if (strlen($password) < 8) {
            $errors[] = 'Password must be at least 8 characters';
        } else {
            $score += 20;
        }

        // Character variety
        if (!preg_match('/[A-Z]/', $password)) {
            $errors[] = 'Password must contain uppercase letter';
        } else {
            $score += 20;
        }

        if (!preg_match('/[a-z]/', $password)) {
            $errors[] = 'Password must contain lowercase letter';
        } else {
            $score += 20;
        }

        if (!preg_match('/\d/', $password)) {
            $errors[] = 'Password must contain number';
        } else {
            $score += 20;
        }

        if (!preg_match('/[@$!%*?&]/', $password)) {
            $errors[] = 'Password must contain special character';
        } else {
            $score += 20;
        }

        // Check against common passwords
        $commonPasswords = [
            'password', '123456', 'qwerty', 'admin', 'letmein',
            'welcome', 'monkey', '123456789', 'iloveyou', 'princess'
        ];

        if (in_array(strtolower($password), $commonPasswords)) {
            $errors[] = 'Password is too common';
            $score = 0;
        }

        // Check for repeated characters
        if (preg_match('/(.)\1{2,}/', $password)) {
            $errors[] = 'Password cannot contain repeated characters';
        }

        // Check for sequential characters
        if (preg_match('/123|234|345|456|567|678|789|abc|bcd|cde|def/', $password)) {
            $errors[] = 'Password cannot contain sequential characters';
        }

        return [
            'valid' => empty($errors),
            'errors' => $errors,
            'strength' => $score,
            'level' => self::getStrengthLevel($score)
        ];
    }

    private static function getStrengthLevel(int $score): string
    {
        if ($score >= 80) return 'Very Strong';
        if ($score >= 60) return 'Strong';
        if ($score >= 40) return 'Medium';
        if ($score >= 20) return 'Weak';
        return 'Very Weak';
    }

    public static function generateSecurePassword(int $length = 12): string
    {
        $lowercase = 'abcdefghijklmnopqrstuvwxyz';
        $uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $numbers = '0123456789';
        $symbols = '@$!%*?&';

        $allChars = $lowercase . $uppercase . $numbers . $symbols;

        // Ensure at least one of each type
        $password = '';
        $password .= $lowercase[rand(0, strlen($lowercase) - 1)];
        $password .= $uppercase[rand(0, strlen($uppercase) - 1)];
        $password .= $numbers[rand(0, strlen($numbers) - 1)];
        $password .= $symbols[rand(0, strlen($symbols) - 1)];

        // Fill the rest randomly
        for ($i = 4; $i < $length; $i++) {
            $password .= $allChars[rand(0, strlen($allChars) - 1)];
        }

        // Shuffle to avoid predictable patterns
        return str_shuffle($password);
    }
}
```

## Laravel Authentication

### Using Laravel Sanctum for API Authentication

```php
<?php
// config/auth.php
'guards' => [
    'web' => [
        'driver' => 'session',
        'provider' => 'users',
    ],
    'api' => [
        'driver' => 'sanctum',
        'provider' => null,
    ],
],
```

### User Model with Secure Authentication

```php
<?php
namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens, Notifiable;

    protected $fillable = [
        'name',
        'email',
        'password',
        'email_verified_at',
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];

    protected $casts = [
        'email_verified_at' => 'datetime',
        'password' => 'hashed', // Laravel 10+ automatically hashes
    ];

    // Secure password hashing
    public function setPasswordAttribute(string $password): void
    {
        $this->attributes['password'] = password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost' => 4,
            'threads' => 3,
        ]);
    }

    // Custom password verification
    public function verifyPassword(string $password): bool
    {
        return password_verify($password, $this->password);
    }
}
```

### Secure Registration Controller

```php
<?php
namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class RegisterController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => [
                'required',
                'string',
                'min:8',
                'confirmed',
                'regex:/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/'
            ],
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'errors' => $validator->errors()
            ], 422);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password), // Or use setPasswordAttribute
        ]);

        // Generate API token if using Sanctum
        $token = $user->createToken('API Token')->plainTextToken;

        return response()->json([
            'success' => true,
            'message' => 'User registered successfully',
            'user' => $user,
            'token' => $token
        ], 201);
    }
}
```

### Secure Login Controller

```php
<?php
namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\ValidationException;

class LoginController extends Controller
{
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
        ]);

        // Rate limiting
        if (RateLimiter::tooManyAttempts($this->throttleKey($request), 5)) {
            $seconds = RateLimiter::availableIn($this->throttleKey($request));

            throw ValidationException::withMessages([
                'email' => "Too many login attempts. Please try again in {$seconds} seconds."
            ]);
        }

        if (!Auth::attempt($request->only('email', 'password'), $request->boolean('remember'))) {
            RateLimiter::hit($this->throttleKey($request), 300); // 5 minutes

            throw ValidationException::withMessages([
                'email' => 'Invalid credentials.'
            ]);
        }

        RateLimiter::clear($this->throttleKey($request));

        $request->session()->regenerate();

        return response()->json([
            'success' => true,
            'message' => 'Login successful',
            'user' => Auth::user()
        ]);
    }

    public function logout(Request $request)
    {
        Auth::logout();

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return response()->json([
            'success' => true,
            'message' => 'Logged out successfully'
        ]);
    }

    private function throttleKey(Request $request): string
    {
        return 'login:' . $request->ip() . ':' . $request->input('email');
    }
}
```

## Multi-Factor Authentication (MFA)

### TOTP Implementation

```php
<?php
// composer require pragmarx/google2fa

use PragmaRX\Google2FA\Google2FA;

class TwoFactorAuth
{
    private Google2FA $google2fa;

    public function __construct()
    {
        $this->google2fa = new Google2FA();
    }

    public function generateSecret(): string
    {
        return $this->google2fa->generateSecretKey();
    }

    public function getQRCodeUrl(string $secret, string $email, string $issuer = 'MyApp'): string
    {
        return $this->google2fa->getQRCodeUrl($issuer, $email, $secret);
    }

    public function verifyCode(string $secret, string $code): bool
    {
        return $this->google2fa->verifyKey($secret, $code);
    }
}

// Usage in User model
class User extends Authenticatable
{
    protected $fillable = ['name', 'email', 'password', 'two_factor_secret', 'two_factor_enabled'];

    public function enableTwoFactor(): void
    {
        $this->two_factor_secret = app(TwoFactorAuth::class)->generateSecret();
        $this->two_factor_enabled = false; // Set to true after verification
        $this->save();
    }

    public function verifyTwoFactorCode(string $code): bool
    {
        return app(TwoFactorAuth::class)->verifyCode($this->two_factor_secret, $code);
    }
}
```

## Security Monitoring and Logging

### Authentication Event Logging

```php
<?php
class AuthLogger
{
    public static function logSuccessfulLogin(int $userId, string $ip, string $userAgent): void
    {
        error_log(sprintf(
            "[AUTH SUCCESS] User ID: %d, IP: %s, User-Agent: %s, Time: %s",
            $userId,
            $ip,
            $userAgent,
            date('Y-m-d H:i:s')
        ));
    }

    public static function logFailedLogin(string $username, string $ip, string $reason): void
    {
        error_log(sprintf(
            "[AUTH FAILED] Username: %s, IP: %s, Reason: %s, Time: %s",
            $username,
            $ip,
            $reason,
            date('Y-m-d H:i:s')
        ));
    }

    public static function logSuspiciousActivity(string $type, array $data): void
    {
        error_log(sprintf(
            "[SECURITY %s] %s",
            $type,
            json_encode($data)
        ));
    }
}
```

## Summary: Authentication Security Checklist

### Password Security
- [ ] Use password_hash() with Argon2 or bcrypt
- [ ] Never store plain text passwords
- [ ] Implement strong password policies
- [ ] Use password_verify() for verification

### Session Management
- [ ] Configure sessions securely (HTTPS, HttpOnly, SameSite)
- [ ] Regenerate session IDs after login
- [ ] Implement session timeouts
- [ ] Validate session data on each request

### Login Security
- [ ] Implement rate limiting
- [ ] Use account lockout for failed attempts
- [ ] Log authentication events
- [ ] Implement secure logout

### Advanced Security
- [ ] Consider multi-factor authentication
- [ ] Monitor for suspicious activity
- [ ] Implement password breach checking
- [ ] Regular security audits

## Next Steps

Now that you understand authentication and password security, explore:

- **[Secure Coding Basics](SecureCodingBasics.md)** - Overall security principles
- **[Input Handling](InputHandling.md)** - Input validation and sanitization
- **[SQL Injection Prevention](SQLInjectionPrevention.md)** - Database security

Remember: Authentication is your application's first line of defense. Implement it properly to protect your users and data!
