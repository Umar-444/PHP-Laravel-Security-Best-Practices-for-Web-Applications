<?php

/**
 * API Security Examples: Token Authentication, Rate Limiting, and JSON Handling
 *
 * Practical examples of API security implementations in PHP and Laravel
 */

declare(strict_types=1);

// =============================================================================
// 1. API TOKEN AUTHENTICATION EXAMPLES
// =============================================================================

class APITokenAuthentication
{
    private PDO $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
        $this->createTables();
    }

    private function createTables(): void
    {
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role ENUM('user', 'admin') DEFAULT 'user',
                active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ");

        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS api_tokens (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NOT NULL,
                token VARCHAR(255) UNIQUE NOT NULL,
                name VARCHAR(100) NOT NULL,
                abilities JSON NULL,
                last_used_at TIMESTAMP NULL,
                expires_at TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user (user_id),
                INDEX idx_token (token),
                INDEX idx_expires (expires_at)
            )
        ");
    }

    /**
     * Register a new user
     */
    public function register(string $email, string $password): int
    {
        $hash = password_hash($password, PASSWORD_ARGON2ID);

        $stmt = $this->pdo->prepare("
            INSERT INTO users (email, password_hash) VALUES (?, ?)
        ");
        $stmt->execute([$email, $hash]);

        return $this->pdo->lastInsertId();
    }

    /**
     * Generate API token for user
     */
    public function generateToken(int $userId, string $name, array $abilities = ['*'], int $daysValid = 30): string
    {
        // Generate cryptographically secure token
        $token = bin2hex(random_bytes(32));

        // Calculate expiration
        $expiresAt = date('Y-m-d H:i:s', strtotime("+{$daysValid} days"));

        $stmt = $this->pdo->prepare("
            INSERT INTO api_tokens (user_id, token, name, abilities, expires_at)
            VALUES (?, ?, ?, ?, ?)
        ");

        $stmt->execute([
            $userId,
            $token,
            $name,
            json_encode($abilities),
            $expiresAt
        ]);

        return $token;
    }

    /**
     * Validate API token and return user data
     */
    public function validateToken(string $token): ?array
    {
        $stmt = $this->pdo->prepare("
            SELECT
                t.id as token_id,
                t.user_id,
                t.name as token_name,
                t.abilities,
                u.email,
                u.role,
                u.active
            FROM api_tokens t
            JOIN users u ON t.user_id = u.id
            WHERE t.token = ?
            AND (t.expires_at IS NULL OR t.expires_at > NOW())
            AND u.active = TRUE
        ");

        $stmt->execute([$token]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$result) {
            return null;
        }

        // Update last used timestamp
        $stmt = $this->pdo->prepare("
            UPDATE api_tokens SET last_used_at = NOW() WHERE id = ?
        ");
        $stmt->execute([$result['token_id']]);

        return [
            'user_id' => $result['user_id'],
            'email' => $result['email'],
            'role' => $result['role'],
            'token_name' => $result['token_name'],
            'abilities' => json_decode($result['abilities'], true),
            'token_id' => $result['token_id']
        ];
    }

    /**
     * Check if token has specific ability
     */
    public function tokenHasAbility(array $tokenData, string $ability): bool
    {
        return in_array('*', $tokenData['abilities']) ||
               in_array($ability, $tokenData['abilities']);
    }

    /**
     * Revoke API token
     */
    public function revokeToken(int $tokenId, int $userId): bool
    {
        $stmt = $this->pdo->prepare("
            DELETE FROM api_tokens WHERE id = ? AND user_id = ?
        ");
        return $stmt->execute([$tokenId, $userId]);
    }

    /**
     * List user's API tokens
     */
    public function listUserTokens(int $userId): array
    {
        $stmt = $this->pdo->prepare("
            SELECT id, name, abilities, last_used_at, expires_at, created_at
            FROM api_tokens
            WHERE user_id = ?
            ORDER BY created_at DESC
        ");
        $stmt->execute([$userId]);

        $tokens = [];
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $tokens[] = [
                'id' => $row['id'],
                'name' => $row['name'],
                'abilities' => json_decode($row['abilities'], true),
                'last_used' => $row['last_used_at'],
                'expires_at' => $row['expires_at'],
                'created_at' => $row['created_at']
            ];
        }

        return $tokens;
    }
}

// =============================================================================
// 2. RATE LIMITING EXAMPLES
// =============================================================================

class APIRateLimiter
{
    private PDO $pdo;
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
            CREATE TABLE IF NOT EXISTS api_rate_limits (
                id VARCHAR(255) PRIMARY KEY,
                requests INT DEFAULT 0,
                window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_window (window_start)
            )
        ");
    }

    /**
     * Check if request is allowed under rate limit
     */
    public function isAllowed(string $identifier): bool
    {
        $this->cleanupOldEntries();

        $currentRequests = $this->getCurrentRequests($identifier);

        if ($currentRequests >= $this->maxRequests) {
            return false;
        }

        $this->incrementRequests($identifier);
        return true;
    }

    /**
     * Get remaining requests for identifier
     */
    public function getRemainingRequests(string $identifier): int
    {
        $currentRequests = $this->getCurrentRequests($identifier);
        return max(0, $this->maxRequests - $currentRequests);
    }

    /**
     * Get reset time for rate limit
     */
    public function getResetTime(string $identifier): int
    {
        $stmt = $this->pdo->prepare("
            SELECT UNIX_TIMESTAMP(window_start) + ? as reset_time
            FROM api_rate_limits
            WHERE id = ?
        ");
        $stmt->execute([$this->windowSeconds, $identifier]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        return $result ? (int) $result['reset_time'] : time() + $this->windowSeconds;
    }

    private function getCurrentRequests(string $identifier): int
    {
        $stmt = $this->pdo->prepare("
            SELECT requests FROM api_rate_limits WHERE id = ?
        ");
        $stmt->execute([$identifier]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        return $result ? (int) $result['requests'] : 0;
    }

    private function incrementRequests(string $identifier): void
    {
        $stmt = $this->pdo->prepare("
            INSERT INTO api_rate_limits (id, requests, window_start)
            VALUES (?, 1, NOW())
            ON DUPLICATE KEY UPDATE requests = requests + 1
        ");
        $stmt->execute([$identifier]);
    }

    private function cleanupOldEntries(): void
    {
        $stmt = $this->pdo->prepare("
            DELETE FROM api_rate_limits
            WHERE window_start < DATE_SUB(NOW(), INTERVAL ? SECOND)
        ");
        $stmt->execute([$this->windowSeconds]);
    }
}

class APIRateLimitMiddleware
{
    private APIRateLimiter $limiter;

    public function __construct(APIRateLimiter $limiter)
    {
        $this->limiter = $limiter;
    }

    /**
     * Apply rate limiting to API request
     */
    public function handle(array $request): ?array
    {
        // Create identifier (IP + route)
        $identifier = ($request['ip'] ?? 'unknown') . ':' . ($request['route'] ?? 'unknown');

        if (!$this->limiter->isAllowed($identifier)) {
            return [
                'status' => 429,
                'headers' => [
                    'X-RateLimit-Limit' => '100',
                    'X-RateLimit-Remaining' => '0',
                    'X-RateLimit-Reset' => $this->limiter->getResetTime($identifier),
                    'Retry-After' => $this->limiter->getResetTime($identifier) - time()
                ],
                'body' => json_encode([
                    'error' => 'Too Many Requests',
                    'message' => 'API rate limit exceeded',
                    'retry_after' => $this->limiter->getResetTime($identifier) - time()
                ])
            ];
        }

        // Add rate limit headers to successful response
        return [
            'status' => 200,
            'headers' => [
                'X-RateLimit-Limit' => '100',
                'X-RateLimit-Remaining' => $this->limiter->getRemainingRequests($identifier),
                'X-RateLimit-Reset' => $this->limiter->getResetTime($identifier)
            ]
        ];
    }
}

// =============================================================================
// 3. SECURE JSON HANDLING EXAMPLES
// =============================================================================

class SecureJSONHandler
{
    private const MAX_JSON_SIZE = 1048576; // 1MB
    private const MAX_DEPTH = 10;
    private const MAX_STRING_LENGTH = 65535; // 64KB

    /**
     * Safely decode JSON with comprehensive validation
     */
    public static function safeDecode(string $json, bool $associative = true): mixed
    {
        // Validate input
        if (empty(trim($json))) {
            throw new InvalidArgumentException('JSON input is empty');
        }

        $json = trim($json);

        // Check size limits
        if (strlen($json) > self::MAX_JSON_SIZE) {
            throw new InvalidArgumentException('JSON input exceeds size limit');
        }

        // Basic structure validation
        if (!self::isValidJSONStructure($json)) {
            throw new InvalidArgumentException('Invalid JSON structure');
        }

        // Decode with error handling
        try {
            $data = json_decode($json, $associative, self::MAX_DEPTH, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new InvalidArgumentException('JSON decode error: ' . $e->getMessage());
        }

        // Additional security validation
        if ($associative && is_array($data)) {
            self::validateAndSanitizeArray($data);
        }

        return $data;
    }

    /**
     * Validate basic JSON structure
     */
    private static function isValidJSONStructure(string $json): bool
    {
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
     * Validate and sanitize array data
     */
    private static function validateAndSanitizeArray(array &$data, int $depth = 0): void
    {
        if ($depth > self::MAX_DEPTH) {
            throw new InvalidArgumentException('JSON structure too deep');
        }

        foreach ($data as $key => &$value) {
            // Validate key type
            if (!is_string($key) && !is_int($key)) {
                throw new InvalidArgumentException('Invalid array key type');
            }

            // Sanitize key
            if (is_string($key)) {
                $key = self::sanitizeString($key);
            }

            // Process value based on type
            if (is_string($value)) {
                $value = self::sanitizeString($value);
            } elseif (is_array($value)) {
                self::validateAndSanitizeArray($value, $depth + 1);
            } elseif (is_object($value)) {
                // Convert objects to arrays for consistency
                $value = (array) $value;
                self::validateAndSanitizeArray($value, $depth + 1);
            }
            // Numbers, booleans, and null are safe

            $data[$key] = $value;
        }
    }

    /**
     * Sanitize string values
     */
    private static function sanitizeString(string $string): string
    {
        // Check length
        if (strlen($string) > self::MAX_STRING_LENGTH) {
            throw new InvalidArgumentException('String value exceeds maximum length');
        }

        // Remove null bytes and dangerous control characters
        $string = preg_replace('/\x00/', '', $string);
        $string = preg_replace('/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $string);

        // Basic XSS prevention
        $string = htmlspecialchars($string, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8', false);

        return $string;
    }

    /**
     * Validate JSON against schema
     */
    public static function validateSchema(mixed $data, array $schema): bool
    {
        if (!is_array($data)) {
            return false;
        }

        foreach ($schema as $field => $rules) {
            // Check required fields
            if (($rules['required'] ?? false) && !isset($data[$field])) {
                return false;
            }

            if (!isset($data[$field])) {
                continue;
            }

            $value = $data[$field];

            // Type validation
            if (isset($rules['type'])) {
                if (!self::validateType($value, $rules['type'])) {
                    return false;
                }
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

            // Enum validation
            if (isset($rules['enum']) && is_array($rules['enum'])) {
                if (!in_array($value, $rules['enum'])) {
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
            'date' => is_string($value) && strtotime($value) !== false,
            default => false
        };
    }
}

// =============================================================================
// 4. COMPLETE API CONTROLLER EXAMPLE
// =============================================================================

class SecureAPIController
{
    private APITokenAuthentication $auth;
    private APIRateLimitMiddleware $rateLimiter;
    private SecureJSONHandler $jsonHandler;

    public function __construct(PDO $pdo)
    {
        $this->auth = new APITokenAuthentication($pdo);
        $limiter = new APIRateLimiter($pdo);
        $this->rateLimiter = new APIRateLimitMiddleware($limiter);
        $this->jsonHandler = new SecureJSONHandler();
    }

    /**
     * Handle API request with full security
     */
    public function handleRequest(array $request): array
    {
        try {
            // 1. Rate limiting check
            $rateLimitResult = $this->rateLimiter->handle($request);
            if (isset($rateLimitResult['status']) && $rateLimitResult['status'] === 429) {
                return $rateLimitResult;
            }

            // 2. Authentication check (if required)
            if ($this->requiresAuth($request)) {
                $user = $this->authenticateRequest($request);
                if (!$user) {
                    return [
                        'status' => 401,
                        'headers' => ['WWW-Authenticate' => 'Bearer'],
                        'body' => json_encode([
                            'error' => 'Unauthorized',
                            'message' => 'Invalid or missing API token'
                        ])
                    ];
                }
                $request['user'] = $user;
            }

            // 3. Parse and validate JSON input
            if ($this->hasJSONBody($request)) {
                $jsonData = $this->parseJSONBody($request['body'] ?? '');
                $request['json'] = $jsonData;
            }

            // 4. Route to appropriate handler
            $response = $this->routeRequest($request);

            // 5. Add security headers
            if (!isset($response['headers'])) {
                $response['headers'] = [];
            }
            $response['headers'] = array_merge($response['headers'], [
                'X-Content-Type-Options' => 'nosniff',
                'X-Frame-Options' => 'DENY',
                'X-API-Version' => '1.0'
            ]);

            return $response;

        } catch (Throwable $e) {
            error_log("API Error: " . $e->getMessage());

            return [
                'status' => 500,
                'body' => json_encode([
                    'error' => 'Internal Server Error',
                    'message' => 'An unexpected error occurred'
                ])
            ];
        }
    }

    private function requiresAuth(array $request): bool
    {
        // Define which routes require authentication
        $protectedRoutes = ['POST /users', 'PUT /users', 'DELETE /users'];

        $route = ($request['method'] ?? 'GET') . ' ' . ($request['route'] ?? '');
        return in_array($route, $protectedRoutes);
    }

    private function authenticateRequest(array $request): ?array
    {
        $authHeader = $request['headers']['authorization'] ?? '';
        $apiKeyHeader = $request['headers']['x-api-key'] ?? '';

        // Try Bearer token first
        if (preg_match('/Bearer\s+(.+)/i', $authHeader, $matches)) {
            return $this->auth->validateToken($matches[1]);
        }

        // Try API key header
        if (!empty($apiKeyHeader)) {
            return $this->auth->validateToken($apiKeyHeader);
        }

        return null;
    }

    private function hasJSONBody(array $request): bool
    {
        $contentType = $request['headers']['content-type'] ?? '';
        return str_contains(strtolower($contentType), 'application/json');
    }

    private function parseJSONBody(string $body): mixed
    {
        if (empty($body)) {
            throw new InvalidArgumentException('Empty request body');
        }

        return SecureJSONHandler::safeDecode($body);
    }

    private function routeRequest(array $request): array
    {
        $method = $request['method'] ?? 'GET';
        $route = $request['route'] ?? '';

        return match ("$method $route") {
            'GET /users' => $this->getUsers($request),
            'POST /users' => $this->createUser($request),
            'GET /users/profile' => $this->getUserProfile($request),
            'PUT /users/profile' => $this->updateUserProfile($request),
            default => [
                'status' => 404,
                'body' => json_encode(['error' => 'Not Found'])
            ]
        };
    }

    private function getUsers(array $request): array
    {
        // Mock data - in real app, fetch from database
        $users = [
            ['id' => 1, 'name' => 'John Doe', 'email' => 'john@example.com'],
            ['id' => 2, 'name' => 'Jane Smith', 'email' => 'jane@example.com']
        ];

        return [
            'status' => 200,
            'headers' => ['Content-Type' => 'application/json'],
            'body' => json_encode(['users' => $users])
        ];
    }

    private function createUser(array $request): array
    {
        // Validate JSON schema
        $schema = [
            'name' => ['required' => true, 'type' => 'string', 'max_length' => 255],
            'email' => ['required' => true, 'type' => 'email', 'max_length' => 254],
            'password' => ['required' => true, 'type' => 'string', 'min' => 8, 'max_length' => 255]
        ];

        if (!SecureJSONHandler::validateSchema($request['json'], $schema)) {
            return [
                'status' => 400,
                'body' => json_encode(['error' => 'Invalid input data'])
            ];
        }

        // Check user authorization
        if (!$this->auth->tokenHasAbility($request['user'], 'users:create')) {
            return [
                'status' => 403,
                'body' => json_encode(['error' => 'Insufficient permissions'])
            ];
        }

        // Create user (mock implementation)
        $userId = rand(1000, 9999);

        return [
            'status' => 201,
            'headers' => ['Content-Type' => 'application/json'],
            'body' => json_encode([
                'message' => 'User created successfully',
                'user_id' => $userId
            ])
        ];
    }

    private function getUserProfile(array $request): array
    {
        $user = $request['user'];

        return [
            'status' => 200,
            'headers' => ['Content-Type' => 'application/json'],
            'body' => json_encode([
                'id' => $user['user_id'],
                'email' => $user['email'],
                'role' => $user['role']
            ])
        ];
    }

    private function updateUserProfile(array $request): array
    {
        // Validate input
        $schema = [
            'name' => ['type' => 'string', 'max_length' => 255],
            'email' => ['type' => 'email', 'max_length' => 254]
        ];

        if (!SecureJSONHandler::validateSchema($request['json'], $schema)) {
            return [
                'status' => 400,
                'body' => json_encode(['error' => 'Invalid input data'])
            ];
        }

        // Update profile (mock implementation)
        return [
            'status' => 200,
            'body' => json_encode(['message' => 'Profile updated successfully'])
        ];
    }
}

// =============================================================================
// 5. LARAVEL API SECURITY EXAMPLES
// =============================================================================

// Note: These examples show Laravel implementations
// In a real Laravel application, these would be in:
// - app/Http/Controllers/Api/SecureAPIController.php
// - app/Http/Requests/StoreUserRequest.php

// Simulating Laravel classes for demonstration
if (!class_exists('Controller')) {
    class Controller {}
}
if (!class_exists('User')) {
    class User {
        public static function create(array $data) { return (object)$data; }
        public function createToken($name, $abilities = []) {
            return (object)['plainTextToken' => 'simulated_token_' . rand(1000, 9999)];
        }
        public function only($fields) { return $this; }
        public function tokens() { return collect([]); }
    }
}
if (!class_exists('Auth')) {
    class Auth {
        public static function attempt($credentials) { return rand(0, 1); }
        public static function user() { return new User(); }
    }
}
if (!class_exists('Hash')) {
    class Hash {
        public static function make($password) { return password_hash($password, PASSWORD_DEFAULT); }
    }
}
if (!class_exists('PersonalAccessToken')) {
    class PersonalAccessToken {
        public function delete() {}
    }
}

// Mock Laravel Request and Response classes
if (!class_exists('Request')) {
    class Request {
        public function validated() { return []; }
        public function only($fields) { return []; }
        public function user() { return new User(); }
        public function validate(array $rules) { return []; }
    }
}
if (!class_exists('JsonResponse')) {
    class JsonResponse {
        public function __construct($data, $status = 200) {}
    }
}

class SecureAPIController extends Controller
{
    /**
     * Register new user with API token
     */
    public function register(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users',
            'password' => 'required|string|min:8'
        ]);

        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => Hash::make($validated['password']),
        ]);

        // Create API token
        $token = $user->createToken('API Access')->plainTextToken;

        return new JsonResponse([
            'message' => 'User registered successfully',
            'user' => $user->only(['id', 'name', 'email']),
            'token' => $token
        ], 201);
    }

    /**
     * Login and get API token
     */
    public function login(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
        ]);

        if (!Auth::attempt($validated)) {
            return new JsonResponse([
                'error' => 'Unauthorized',
                'message' => 'Invalid credentials'
            ], 401);
        }

        $user = Auth::user();
        $token = $user->createToken('API Access')->plainTextToken;

        return new JsonResponse([
            'message' => 'Login successful',
            'user' => $user->only(['id', 'name', 'email']),
            'token' => $token
        ]);
    }

    /**
     * Get authenticated user profile
     */
    public function profile(Request $request): JsonResponse
    {
        return new JsonResponse([
            'user' => $request->user()->only(['id', 'name', 'email'])
        ]);
    }

    /**
     * Update user profile (with ability check)
     */
    public function updateProfile(Request $request): JsonResponse
    {
        $user = $request->user();

        // Check if token has update ability
        if (!$user->tokenCan('profile:update')) {
            return new JsonResponse([
                'error' => 'Forbidden',
                'message' => 'Token does not have update permission'
            ], 403);
        }

        $validated = $request->validate([
            'name' => 'sometimes|string|max:255',
            'email' => 'sometimes|email|unique:users,email,' . $user->id,
        ]);

        $user->update($validated);

        return new JsonResponse([
            'message' => 'Profile updated successfully',
            'user' => $user->only(['id', 'name', 'email'])
        ]);
    }

    /**
     * List user's API tokens
     */
    public function tokens(Request $request): JsonResponse
    {
        $user = $request->user();

        $tokens = $user->tokens()->select('id', 'name', 'abilities', 'last_used_at', 'created_at')->get();

        return new JsonResponse(['tokens' => $tokens]);
    }

    /**
     * Revoke API token
     */
    public function revokeToken(Request $request, PersonalAccessToken $token): JsonResponse
    {
        // Ensure user owns the token
        if ($token->tokenable_id !== $request->user()->id) {
            return new JsonResponse(['error' => 'Unauthorized'], 403);
        }

        $token->delete();

        return new JsonResponse(['message' => 'Token revoked successfully']);
    }
}

// =============================================================================
// USAGE EXAMPLES AND TESTING
// =============================================================================

/*
// SETUP
$pdo = new PDO("mysql:host=localhost;dbname=api_security", "user", "pass", [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
]);

// API AUTHENTICATION
$auth = new APITokenAuthentication($pdo);

// Register user
$userId = $auth->register('user@example.com', 'SecurePass123!');

// Generate API token
$token = $auth->generateToken($userId, 'My API Token', ['read', 'write']);

// Validate token
$userData = $auth->validateToken($token);
if ($userData && $auth->tokenHasAbility($userData, 'read')) {
    echo "Token is valid and has read ability\n";
}

// RATE LIMITING
$rateLimiter = new APIRateLimiter($pdo, 10, 60); // 10 requests per minute
$middleware = new APIRateLimitMiddleware($rateLimiter);

// Test rate limiting
for ($i = 0; $i < 12; $i++) {
    $result = $middleware->handle(['ip' => '192.168.1.1', 'route' => '/api/test']);
    if (isset($result['status']) && $result['status'] === 429) {
        echo "Rate limit exceeded after {$i} requests\n";
        break;
    }
}

// JSON HANDLING
try {
    $jsonData = SecureJSONHandler::safeDecode('{"name": "John", "email": "john@example.com"}');

    $schema = [
        'name' => ['required' => true, 'type' => 'string', 'max_length' => 255],
        'email' => ['required' => true, 'type' => 'email']
    ];

    if (SecureJSONHandler::validateSchema($jsonData, $schema)) {
        echo "JSON data is valid\n";
    }
} catch (Exception $e) {
    echo "JSON validation failed: " . $e->getMessage() . "\n";
}

// COMPLETE API CONTROLLER
$apiController = new SecureAPIController($pdo);

// Test API request
$request = [
    'method' => 'GET',
    'route' => '/users',
    'ip' => '192.168.1.1',
    'headers' => [
        'authorization' => 'Bearer ' . $token,
        'content-type' => 'application/json'
    ]
];

$response = $apiController->handleRequest($request);
echo "API Response Status: " . ($response['status'] ?? 'unknown') . "\n";
*/
?>
