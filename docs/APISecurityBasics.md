# API Security Basics

## Why API Security Matters

APIs are the backbone of modern web applications, enabling communication between different systems, mobile apps, and third-party services. However, APIs are prime targets for attackers due to their:

- **Direct data access** - APIs often provide direct access to sensitive data
- **High-value targets** - APIs typically contain business logic and data
- **Public exposure** - APIs are designed to be accessible from external sources
- **Complex attack surface** - APIs handle various input formats and authentication methods

### API Security Statistics

- **95%** of organizations experienced API security incidents in the past year
- **83%** of web traffic is API-based
- **34%** of attacks target APIs specifically
- **Average cost** of API data breach: $4.35 million

## API Authentication Methods

### API Tokens

API tokens are the most common authentication method for APIs. They provide a way to identify and authorize API clients.

#### Types of API Tokens

#### 1. **Bearer Tokens**
- Included in `Authorization: Bearer <token>` header
- Stateless - server doesn't maintain session state
- Most common for REST APIs

#### 2. **API Keys**
- Simple string identifiers passed in headers or query parameters
- Often used for public APIs with rate limiting
- Less secure than bearer tokens

#### 3. **JWT Tokens**
- JSON Web Tokens containing user information and claims
- Can be signed and encrypted
- Self-contained - no server-side storage needed

### Secure Token Implementation

```php
<?php
class APITokenManager
{
    private PDO $pdo;
    private string $table = 'api_tokens';

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
        $this->createTable();
    }

    private function createTable(): void
    {
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS {$this->table} (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NOT NULL,
                token VARCHAR(255) UNIQUE NOT NULL,
                name VARCHAR(100) NOT NULL,
                abilities JSON NULL,
                last_used_at TIMESTAMP NULL,
                expires_at TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user (user_id),
                INDEX idx_token (token),
                INDEX idx_expires (expires_at)
            )
        ");
    }

    /**
     * Generate a secure API token
     */
    public function generateToken(int $userId, string $name, array $abilities = [], ?DateTime $expiresAt = null): string
    {
        $token = bin2hex(random_bytes(32)); // 64 character hex token

        $stmt = $this->pdo->prepare("
            INSERT INTO {$this->table} (user_id, token, name, abilities, expires_at)
            VALUES (?, ?, ?, ?, ?)
        ");

        $abilitiesJson = json_encode($abilities);
        $expiresAtStr = $expiresAt ? $expiresAt->format('Y-m-d H:i:s') : null;

        $stmt->execute([$userId, $token, $name, $abilitiesJson, $expiresAtStr]);

        return $token;
    }

    /**
     * Validate API token
     */
    public function validateToken(string $token): ?array
    {
        $stmt = $this->pdo->prepare("
            SELECT t.*, u.email, u.role
            FROM {$this->table} t
            JOIN users u ON t.user_id = u.id
            WHERE t.token = ? AND (t.expires_at IS NULL OR t.expires_at > NOW())
        ");

        $stmt->execute([$token]);
        $tokenData = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$tokenData) {
            return null;
        }

        // Update last used timestamp
        $this->updateLastUsed($tokenData['id']);

        return [
            'id' => $tokenData['id'],
            'user_id' => $tokenData['user_id'],
            'email' => $tokenData['email'],
            'role' => $tokenData['role'],
            'abilities' => json_decode($tokenData['abilities'] ?? '[]', true),
            'name' => $tokenData['name'],
        ];
    }

    /**
     * Check if token has specific ability
     */
    public function tokenHasAbility(array $tokenData, string $ability): bool
    {
        // Check if token has wildcard ability (*)
        if (in_array('*', $tokenData['abilities'])) {
            return true;
        }

        // Check specific ability
        return in_array($ability, $tokenData['abilities']);
    }

    /**
     * Revoke API token
     */
    public function revokeToken(int $tokenId, int $userId): bool
    {
        $stmt = $this->pdo->prepare("
            DELETE FROM {$this->table}
            WHERE id = ? AND user_id = ?
        ");

        return $stmt->execute([$tokenId, $userId]);
    }

    /**
     * Update last used timestamp
     */
    private function updateLastUsed(int $tokenId): void
    {
        $stmt = $this->pdo->prepare("
            UPDATE {$this->table}
            SET last_used_at = NOW()
            WHERE id = ?
        ");
        $stmt->execute([$tokenId]);
    }
}
```

### Laravel Sanctum API Tokens

Laravel Sanctum provides a simple API token authentication system.

```php
<?php
// User model with API tokens
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens;

    // Create API token
    public function createAPIToken(string $name, array $abilities = ['*']): string
    {
        return $this->createToken($name, $abilities)->plainTextToken;
    }

    // Check token abilities
    public function tokenCan(string $ability): bool
    {
        return $this->currentAccessToken()->can($ability);
    }
}

// API Routes with Sanctum
Route::middleware('auth:sanctum')->group(function () {
    Route::get('/user', function (Request $request) {
        return $request->user();
    });

    Route::middleware('ability:server:update')->group(function () {
        Route::post('/server/{server}/update', [ServerController::class, 'update']);
    });
});

// Controller usage
class APIController extends Controller
{
    public function getUser(Request $request)
    {
        // Get authenticated user
        $user = $request->user();

        // Check token abilities
        if (!$user->tokenCan('user:read')) {
            return response()->json(['error' => 'Insufficient permissions'], 403);
        }

        return response()->json(['user' => $user]);
    }
}
```

## Rate Limiting

Rate limiting prevents API abuse by limiting the number of requests a client can make in a given time period.

### Why Rate Limiting Matters

- **Prevents DoS attacks** - Limits resource consumption
- **Reduces scraping** - Makes it harder to extract large amounts of data
- **Improves performance** - Prevents server overload
- **Fair resource allocation** - Ensures fair access for all users

### Rate Limiting Strategies

#### 1. **Fixed Window**
```php
<?php
class FixedWindowRateLimiter
{
    private PDO $pdo;
    private string $table = 'rate_limits';
    private int $maxRequests;
    private int $windowSeconds;

    public function __construct(PDO $pdo, int $maxRequests = 60, int $windowSeconds = 60)
    {
        $this->pdo = $pdo;
        $this->maxRequests = $maxRequests;
        $this->windowSeconds = $windowSeconds;
        $this->createTable();
    }

    private function createTable(): void
    {
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS {$this->table} (
                id VARCHAR(255) PRIMARY KEY,
                requests INT DEFAULT 0,
                window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_window (window_start)
            )
        ");
    }

    public function isAllowed(string $identifier): bool
    {
        $now = time();
        $windowStart = $now - ($now % $this->windowSeconds);

        // Clean old entries
        $this->cleanOldEntries($windowStart);

        // Get or create record for this identifier
        $stmt = $this->pdo->prepare("
            INSERT INTO {$this->table} (id, requests, window_start)
            VALUES (?, 1, FROM_UNIXTIME(?))
            ON DUPLICATE KEY UPDATE
                requests = IF(window_start = FROM_UNIXTIME(?), requests + 1, 1),
                window_start = FROM_UNIXTIME(?)
        ");

        $stmt->execute([$identifier, $windowStart, $windowStart, $windowStart]);

        // Check if limit exceeded
        $stmt = $this->pdo->prepare("
            SELECT requests FROM {$this->table}
            WHERE id = ? AND window_start = FROM_UNIXTIME(?)
        ");

        $stmt->execute([$identifier, $windowStart]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        return ($result['requests'] ?? 0) <= $this->maxRequests;
    }

    private function cleanOldEntries(int $currentWindow): void
    {
        $cutoff = $currentWindow - $this->windowSeconds;
        $stmt = $this->pdo->prepare("DELETE FROM {$this->table} WHERE window_start < FROM_UNIXTIME(?)");
        $stmt->execute([$cutoff]);
    }
}
```

#### 2. **Sliding Window**
```php
<?php
class SlidingWindowRateLimiter
{
    private PDO $pdo;
    private string $table = 'rate_limit_requests';
    private int $maxRequests;
    private int $windowSeconds;

    public function __construct(PDO $pdo, int $maxRequests = 100, int $windowSeconds = 60)
    {
        $this->pdo = $pdo;
        $this->maxRequests = $maxRequests;
        $this->windowSeconds = $windowSeconds;
        $this->createTable();
    }

    private function createTable(): void
    {
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS {$this->table} (
                id INT PRIMARY KEY AUTO_INCREMENT,
                identifier VARCHAR(255) NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_identifier_time (identifier, timestamp)
            )
        ");
    }

    public function isAllowed(string $identifier): bool
    {
        $now = date('Y-m-d H:i:s');
        $windowStart = date('Y-m-d H:i:s', strtotime("-{$this->windowSeconds} seconds"));

        // Count requests in sliding window
        $stmt = $this->pdo->prepare("
            SELECT COUNT(*) as count FROM {$this->table}
            WHERE identifier = ? AND timestamp >= ?
        ");

        $stmt->execute([$identifier, $windowStart]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        $requestCount = $result['count'];

        // Record this request
        $stmt = $this->pdo->prepare("INSERT INTO {$this->table} (identifier) VALUES (?)");
        $stmt->execute([$identifier]);

        // Clean old entries
        $stmt = $this->pdo->prepare("DELETE FROM {$this->table} WHERE timestamp < ?");
        $stmt->execute([$windowStart]);

        return $requestCount < $this->maxRequests;
    }
}
```

### Laravel Rate Limiting

Laravel provides built-in rate limiting through middleware.

```php
<?php
// In routes/api.php
use Illuminate\Support\Facades\Route;
use Illuminate\Http\Request;

Route::middleware('throttle:60,1')->group(function () {
    // 60 requests per minute
    Route::get('/user', function (Request $request) {
        return $request->user();
    });
});

// Custom rate limits
Route::middleware('throttle:uploads:10,1')->group(function () {
    // 10 uploads per minute
    Route::post('/upload', [UploadController::class, 'store']);
});

// Different limits for authenticated users
Route::middleware('auth:sanctum')->middleware(function ($request, $next) {
    // Higher limits for authenticated users
    return app(\Illuminate\Routing\Middleware\ThrottleRequests::class)
        ->handle($request, $next, 'api_authenticated:100,1');
})->group(function () {
    Route::apiResource('posts', PostController::class);
});
```

#### Custom Rate Limiting Middleware

```php
<?php
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Symfony\Component\HttpFoundation\Response;

class CustomRateLimiter
{
    public function handle(Request $request, Closure $next, string $limit = '60', string $decayMinutes = '1'): Response
    {
        $key = $this->resolveRequestSignature($request);
        $maxAttempts = (int) $limit;
        $decaySeconds = (int) $decayMinutes * 60;

        // Check if limit exceeded
        if ($this->tooManyAttempts($key, $maxAttempts)) {
            return $this->buildLimitExceededResponse($request, $key, $maxAttempts, $decaySeconds);
        }

        // Increment attempts
        $this->hit($key, $decaySeconds);

        $response = $next($request);

        // Add rate limit headers
        $response->headers->set('X-RateLimit-Limit', $maxAttempts);
        $response->headers->set('X-RateLimit-Remaining', $this->remainingAttempts($key, $maxAttempts));
        $response->headers->set('X-RateLimit-Reset', $this->availableIn($key));

        return $response;
    }

    protected function resolveRequestSignature(Request $request): string
    {
        // Use IP + route for rate limiting
        return sha1($request->ip() . '|' . $request->route()->getName());
    }

    protected function tooManyAttempts(string $key, int $maxAttempts): bool
    {
        return Cache::get($key, 0) >= $maxAttempts;
    }

    protected function hit(string $key, int $decaySeconds): void
    {
        Cache::add($key, 1, $decaySeconds);
        Cache::increment($key);
    }

    protected function remainingAttempts(string $key, int $maxAttempts): int
    {
        return max(0, $maxAttempts - Cache::get($key, 0));
    }

    protected function availableIn(string $key): int
    {
        return Cache::getStore()->getTTL($key);
    }

    protected function buildLimitExceededResponse(Request $request, string $key, int $maxAttempts, int $decaySeconds): Response
    {
        $retryAfter = $this->availableIn($key);

        $response = response()->json([
            'error' => 'Too Many Requests',
            'message' => 'API rate limit exceeded',
            'retry_after' => $retryAfter
        ], 429);

        $response->headers->set('X-RateLimit-Limit', $maxAttempts);
        $response->headers->set('Retry-After', $retryAfter);
        $response->headers->set('X-RateLimit-Reset', time() + $retryAfter);

        return $response;
    }
}
```

## JSON Input Handling

### JSON Parsing Security

JSON input can contain malicious content or malformed data. Proper validation is crucial.

#### Safe JSON Decoding

```php
<?php
class SecureJSONHandler
{
    /**
     * Safely decode JSON with comprehensive validation
     */
    public static function safeDecode(string $json, bool $associative = true, int $maxDepth = 512): mixed
    {
        if (empty(trim($json))) {
            throw new InvalidArgumentException('JSON input is empty');
        }

        // Check JSON length limits
        if (strlen($json) > 1048576) { // 1MB limit
            throw new InvalidArgumentException('JSON input too large');
        }

        // Basic JSON structure validation
        $json = trim($json);
        if (!self::isValidJSONStructure($json)) {
            throw new InvalidArgumentException('Invalid JSON structure');
        }

        // Decode with error handling
        $data = json_decode($json, $associative, $maxDepth, JSON_THROW_ON_ERROR);

        // Additional security checks
        if ($associative && is_array($data)) {
            $data = self::sanitizeArray($data);
        }

        return $data;
    }

    /**
     * Validate basic JSON structure
     */
    private static function isValidJSONStructure(string $json): bool
    {
        $json = trim($json);

        // Must start with valid JSON characters
        if (!str_starts_with($json, '{') &&
            !str_starts_with($json, '[') &&
            !str_starts_with($json, '"')) {
            return false;
        }

        // Must end with valid JSON characters
        if (!str_ends_with($json, '}') &&
            !str_ends_with($json, ']') &&
            !str_ends_with($json, '"')) {
            return false;
        }

        return true;
    }

    /**
     * Sanitize decoded array data
     */
    private static function sanitizeArray(array $data, int $depth = 0): array
    {
        // Prevent deep recursion attacks
        if ($depth > 10) {
            throw new InvalidArgumentException('JSON structure too deep');
        }

        $sanitized = [];

        foreach ($data as $key => $value) {
            // Validate key
            if (!is_string($key) && !is_int($key)) {
                throw new InvalidArgumentException('Invalid array key type');
            }

            // Sanitize key
            if (is_string($key)) {
                $key = self::sanitizeString($key);
            }

            // Sanitize value based on type
            if (is_string($value)) {
                $value = self::sanitizeString($value);
            } elseif (is_array($value)) {
                $value = self::sanitizeArray($value, $depth + 1);
            } elseif (is_object($value)) {
                // Convert objects to arrays for consistency
                $value = self::sanitizeArray((array) $value, $depth + 1);
            }
            // Numbers and booleans are safe as-is

            $sanitized[$key] = $value;
        }

        return $sanitized;
    }

    /**
     * Sanitize string values
     */
    private static function sanitizeString(string $string): string
    {
        // Remove null bytes and other control characters
        $string = preg_replace('/\x00/', '', $string);

        // Limit string length
        if (strlen($string) > 65535) { // 64KB limit per string
            throw new InvalidArgumentException('String value too long');
        }

        // Basic XSS prevention (additional to JSON validation)
        $string = filter_var($string, FILTER_SANITIZE_STRING, FILTER_FLAG_NO_ENCODE_QUOTES);

        return $string;
    }

    /**
     * Validate JSON against schema
     */
    public static function validateAgainstSchema(mixed $data, array $schema): bool
    {
        foreach ($schema as $field => $rules) {
            if (!isset($data[$field])) {
                if (($rules['required'] ?? false)) {
                    return false;
                }
                continue;
            }

            $value = $data[$field];
            $type = $rules['type'] ?? null;

            // Type validation
            if ($type && !$self::validateType($value, $type)) {
                return false;
            }

            // Length validation
            if (isset($rules['max_length']) && is_string($value)) {
                if (strlen($value) > $rules['max_length']) {
                    return false;
                }
            }

            // Range validation
            if (isset($rules['min']) && is_numeric($value)) {
                if ($value < $rules['min']) {
                    return false;
                }
            }

            if (isset($rules['max']) && is_numeric($value)) {
                if ($value > $rules['max']) {
                    return false;
                }
            }

            // Pattern validation
            if (isset($rules['pattern']) && is_string($value)) {
                if (!preg_match($rules['pattern'], $value)) {
                    return false;
                }
            }
        }

        return true;
    }

    private static function validateType($value, string $type): bool
    {
        return match ($type) {
            'string' => is_string($value),
            'int' => is_int($value),
            'float' => is_float($value),
            'bool' => is_bool($value),
            'array' => is_array($value),
            'email' => is_string($value) && filter_var($value, FILTER_VALIDATE_EMAIL),
            'url' => is_string($value) && filter_var($value, FILTER_VALIDATE_URL),
            default => false
        };
    }
}
```

### Laravel JSON Request Validation

```php
<?php
namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class APIStoreUserRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'name' => 'required|string|max:255|regex:/^[a-zA-Z\s\-\.\']+$/',
            'email' => 'required|email:rfc,dns|max:254|unique:users,email',
            'password' => 'required|string|min:8|confirmed',
            'age' => 'nullable|integer|min:13|max:120',
            'preferences' => 'nullable|array',
            'preferences.theme' => 'nullable|string|in:light,dark',
            'preferences.language' => 'nullable|string|size:2',
        ];
    }

    public function messages(): array
    {
        return [
            'name.regex' => 'Name can only contain letters, spaces, hyphens, periods, and apostrophes.',
            'email.email' => 'Please provide a valid email address.',
            'password.min' => 'Password must be at least 8 characters.',
            'age.min' => 'You must be at least 13 years old.',
            'preferences.theme.in' => 'Theme must be either light or dark.',
            'preferences.language.size' => 'Language code must be exactly 2 characters.',
        ];
    }

    public function prepareForValidation(): void
    {
        // Sanitize input before validation
        if ($this->has('name')) {
            $this->merge([
                'name' => trim($this->name)
            ]);
        }

        if ($this->has('email')) {
            $this->merge([
                'email' => strtolower(trim($this->email))
            ]);
        }
    }

    protected function passedValidation(): void
    {
        // Additional processing after validation
        $this->merge([
            'email_verified_at' => null,
            'password' => bcrypt($this->password),
        ]);
    }
}
```

## API Security Middleware

### Comprehensive API Security Middleware

```php
<?php
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

class APISecurityMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        // Only apply to API routes
        if (!$this->isAPIRoute($request)) {
            return $next($request);
        }

        // 1. Validate Content-Type for POST/PUT/PATCH
        if ($this->requiresJSONContent($request)) {
            if (!$this->hasValidContentType($request)) {
                return $this->errorResponse('Content-Type must be application/json', 415);
            }
        }

        // 2. Validate JSON structure if present
        if ($request->isJson()) {
            try {
                $jsonData = $request->json()->all();
                $this->validateJSONStructure($jsonData);
                $this->sanitizeJSONData($jsonData);
            } catch (\Exception $e) {
                Log::warning('Invalid JSON in API request', [
                    'ip' => $request->ip(),
                    'user_agent' => $request->userAgent(),
                    'error' => $e->getMessage()
                ]);
                return $this->errorResponse('Invalid JSON format', 400);
            }
        }

        // 3. Check for suspicious patterns
        if ($this->containsSuspiciousPatterns($request)) {
            Log::warning('Suspicious API request detected', [
                'ip' => $request->ip(),
                'url' => $request->fullUrl(),
                'data' => $this->sanitizeForLogging($request->all())
            ]);
            return $this->errorResponse('Request contains invalid data', 400);
        }

        // 4. Validate API token if required
        if ($this->requiresAuthentication($request)) {
            if (!$this->validateAPIToken($request)) {
                return $this->errorResponse('Invalid or missing API token', 401);
            }
        }

        // 5. Apply rate limiting
        if (!$this->checkRateLimit($request)) {
            return $this->errorResponse('Rate limit exceeded', 429);
        }

        $response = $next($request);

        // 6. Add security headers
        $this->addSecurityHeaders($response);

        // 7. Log successful API calls
        if ($response->getStatusCode() < 400) {
            Log::info('API call successful', [
                'method' => $request->method(),
                'url' => $request->fullUrl(),
                'status' => $response->getStatusCode(),
                'user_id' => $request->user() ? $request->user()->id : null,
                'ip' => $request->ip()
            ]);
        }

        return $response;
    }

    private function isAPIRoute(Request $request): bool
    {
        return str_starts_with($request->path(), 'api/') ||
               $request->expectsJson();
    }

    private function requiresJSONContent(Request $request): bool
    {
        return in_array($request->method(), ['POST', 'PUT', 'PATCH']);
    }

    private function hasValidContentType(Request $request): bool
    {
        $contentType = $request->header('Content-Type');
        return str_contains($contentType, 'application/json');
    }

    private function validateJSONStructure(array $data, int $depth = 0): void
    {
        if ($depth > 10) {
            throw new \Exception('JSON structure too deep');
        }

        foreach ($data as $key => $value) {
            if (!is_string($key) && !is_int($key)) {
                throw new \Exception('Invalid JSON key type');
            }

            if (is_array($value)) {
                $this->validateJSONStructure($value, $depth + 1);
            } elseif (is_string($value) && strlen($value) > 65535) {
                throw new \Exception('JSON string value too long');
            }
        }
    }

    private function sanitizeJSONData(array &$data): void
    {
        foreach ($data as $key => &$value) {
            if (is_string($value)) {
                // Remove null bytes and control characters
                $value = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $value);
            } elseif (is_array($value)) {
                $this->sanitizeJSONData($value);
            }
        }
    }

    private function containsSuspiciousPatterns(Request $request): bool
    {
        $data = json_encode($request->all());

        $suspiciousPatterns = [
            '/<script/i',
            '/javascript:/i',
            '/vbscript:/i',
            '/data:/i',
            '/\x00/', // Null bytes
            '/\.\./', // Directory traversal
        ];

        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $data)) {
                return true;
            }
        }

        return false;
    }

    private function validateAPIToken(Request $request): bool
    {
        $token = $request->bearerToken() ?? $request->header('X-API-Token');

        if (!$token) {
            return false;
        }

        // Validate token format (basic check)
        if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
            return false;
        }

        // Here you would check the token against your database/cache
        // For now, just check if it exists in a simple array
        $validTokens = ['your_api_token_here'];

        return in_array($token, $validTokens);
    }

    private function checkRateLimit(Request $request): bool
    {
        $key = 'api_rate_limit:' . $request->ip();
        $maxRequests = 100; // 100 requests per minute
        $decayMinutes = 1;

        // Use Laravel's built-in rate limiter
        return !app(\Illuminate\Cache\RateLimiter::class)->tooManyAttempts($key, $maxRequests);
    }

    private function addSecurityHeaders($response): void
    {
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('X-API-Version', '1.0');
        $response->headers->set('Content-Security-Policy', "default-src 'none'");
    }

    private function sanitizeForLogging(array $data): array
    {
        $sanitized = [];

        foreach ($data as $key => $value) {
            if (is_string($value)) {
                // Mask sensitive fields
                if (str_contains(strtolower($key), 'password') ||
                    str_contains(strtolower($key), 'token') ||
                    str_contains(strtolower($key), 'secret')) {
                    $sanitized[$key] = '[REDACTED]';
                } else {
                    $sanitized[$key] = strlen($value) > 100 ? substr($value, 0, 100) . '...' : $value;
                }
            } elseif (is_array($value)) {
                $sanitized[$key] = $this->sanitizeForLogging($value);
            } else {
                $sanitized[$key] = $value;
            }
        }

        return $sanitized;
    }

    private function errorResponse(string $message, int $statusCode): Response
    {
        return response()->json([
            'error' => true,
            'message' => $message,
            'timestamp' => now()->timestamp
        ], $statusCode);
    }
}
```

## API Security Best Practices

### 1. **Use HTTPS Only**
- Always require HTTPS for API endpoints
- Redirect HTTP requests to HTTPS
- Use HSTS headers

### 2. **Implement Proper Authentication**
- Use secure token-based authentication
- Implement token expiration and rotation
- Validate token permissions

### 3. **Apply Rate Limiting**
- Prevent abuse with appropriate limits
- Use different limits for different endpoints
- Implement gradual backoff

### 4. **Validate All Input**
- Validate JSON structure and content
- Sanitize input data
- Use schema validation

### 5. **Implement Proper Error Handling**
- Don't expose internal errors
- Use consistent error response format
- Log errors securely

### 6. **Monitor API Usage**
- Log all API requests and responses
- Implement anomaly detection
- Set up alerts for suspicious activity

## Next Steps

Now that you understand API security basics, explore:

- **[Secure Deployment](SecureDeployment.md)** - Production deployment security
- **[Authentication & Password Handling](AuthenticationPasswordHandling.md)** - User authentication
- **[Rate Limiting](RateLimiting.md)** - Advanced rate limiting techniques

Remember: APIs are high-value targets. Implement multiple layers of security to protect your API endpoints and data!
