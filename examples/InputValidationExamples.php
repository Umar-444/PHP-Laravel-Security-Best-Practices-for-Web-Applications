<?php

/**
 * Input Validation and Sanitization Examples
 *
 * Practical examples of secure input handling in PHP and Laravel
 */

declare(strict_types=1);

// =============================================================================
// PHP INPUT VALIDATION EXAMPLES
// =============================================================================

class PHPInputValidator
{
    /**
     * Validate email with multiple security checks
     */
    public static function validateEmail(string $email): bool
    {
        // Basic format validation
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return false;
        }

        // Length check (prevent extremely long emails)
        if (strlen($email) > 254) {
            return false;
        }

        // Extract domain and check DNS (optional but recommended)
        $domain = substr(strrchr($email, "@"), 1);
        if (!checkdnsrr($domain, 'MX') && !checkdnsrr($domain, 'A')) {
            return false; // Domain doesn't exist
        }

        return true;
    }

    /**
     * Validate username with allow-list approach
     */
    public static function validateUsername(string $username): bool
    {
        // Allow-list: only alphanumeric, underscore, hyphen
        if (!preg_match('/^[a-zA-Z0-9_-]{3,20}$/', $username)) {
            return false;
        }

        // Check for reserved words
        $reserved = ['admin', 'root', 'system', 'null', 'undefined'];
        if (in_array(strtolower($username), $reserved)) {
            return false;
        }

        return true;
    }

    /**
     * Validate strong password
     */
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

        // Character variety checks
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
        $commonPasswords = ['password', '123456', 'qwerty', 'admin'];
        if (in_array(strtolower($password), $commonPasswords)) {
            $errors[] = 'Password is too common';
            $score = 0;
        }

        return [
            'valid' => empty($errors),
            'errors' => $errors,
            'strength' => $score
        ];
    }

    /**
     * Validate and sanitize URL
     */
    public static function validateUrl(string $url): ?string
    {
        // Basic URL validation
        $url = filter_var($url, FILTER_VALIDATE_URL, [
            FILTER_FLAG_SCHEME_REQUIRED,
            FILTER_FLAG_HOST_REQUIRED
        ]);

        if (!$url) {
            return null;
        }

        // Parse URL components
        $parsed = parse_url($url);
        if (!$parsed || !isset($parsed['scheme'], $parsed['host'])) {
            return null;
        }

        // Only allow HTTP/HTTPS
        if (!in_array(strtolower($parsed['scheme']), ['http', 'https'])) {
            return null;
        }

        // Validate host (prevent IP spoofing)
        if (!filter_var($parsed['host'], FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            // Allow IP addresses
            if (!filter_var($parsed['host'], FILTER_VALIDATE_IP)) {
                return null;
            }
        }

        return $url;
    }

    /**
     * Validate positive integer with range
     */
    public static function validatePositiveInteger($value, int $min = 1, int $max = PHP_INT_MAX): ?int
    {
        $int = filter_var($value, FILTER_VALIDATE_INT, [
            'options' => [
                'min_range' => $min,
                'max_range' => $max
            ]
        ]);

        return $int !== false ? $int : null;
    }

    /**
     * Validate decimal number
     */
    public static function validateDecimal(string $value, int $decimals = 2): ?float
    {
        if (!is_numeric($value)) {
            return null;
        }

        $float = (float) $value;

        // Check decimal places
        if ($decimals > 0) {
            $parts = explode('.', $value);
            if (count($parts) === 2 && strlen($parts[1]) > $decimals) {
                return null;
            }
        }

        return $float;
    }

    /**
     * Validate date string
     */
    public static function validateDate(string $date, string $format = 'Y-m-d'): ?string
    {
        $d = DateTime::createFromFormat($format, $date);
        if (!$d || $d->format($format) !== $date) {
            return null;
        }

        // Additional validation: reasonable date range
        $year = (int) $d->format('Y');
        if ($year < 1900 || $year > (date('Y') + 10)) {
            return null;
        }

        return $date;
    }
}

// =============================================================================
// OUTPUT SANITIZATION EXAMPLES
// =============================================================================

class OutputSanitizer
{
    /**
     * Sanitize for HTML context
     */
    public static function forHtml(string $data): string
    {
        return htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    /**
     * Sanitize for HTML attributes
     */
    public static function forAttribute(string $data): string
    {
        return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    }

    /**
     * Sanitize for JavaScript context
     */
    public static function forJavaScript($data): string
    {
        return json_encode($data, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
    }

    /**
     * Sanitize for URL context
     */
    public static function forUrl(string $data): string
    {
        return urlencode($data);
    }

    /**
     * Sanitize for SQL LIKE queries
     */
    public static function forSqlLike(string $data, PDO $pdo): string
    {
        // Escape wildcards and use prepared statements
        $data = str_replace(['%', '_'], ['\%', '\_'], $data);
        return $pdo->quote($data);
    }

    /**
     * Remove all HTML tags and encode entities
     */
    public static function stripAndEncode(string $data): string
    {
        // Remove HTML tags
        $data = strip_tags($data);

        // Convert special characters to HTML entities
        return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    }
}

// =============================================================================
// LARAVEL FORM REQUEST EXAMPLES
// =============================================================================

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class CreateUserRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true; // Implement authorization if needed
    }

    public function rules(): array
    {
        return [
            'name' => 'required|string|min:2|max:50|regex:/^[a-zA-Z\s\-\.\']+$/',
            'email' => [
                'required',
                'email:rfc,dns',
                'max:254',
                Rule::unique('users')->ignore($this->user())
            ],
            'password' => 'required|string|min:8|confirmed|regex:/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/',
            'phone' => 'nullable|string|regex:/^(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})$/',
            'date_of_birth' => 'nullable|date|before:today|after:1900-01-01',
            'website' => 'nullable|url|max:255',
            'bio' => 'nullable|string|max:500',
            'avatar' => 'nullable|image|mimes:jpeg,png,jpg,gif|max:2048|dimensions:min_width=100,min_height=100,max_width=2000,max_height=2000',
        ];
    }

    public function messages(): array
    {
        return [
            'name.regex' => 'Name can only contain letters, spaces, hyphens, periods, and apostrophes.',
            'password.regex' => 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.',
            'phone.regex' => 'Please provide a valid phone number.',
            'avatar.dimensions' => 'Avatar must be between 100x100 and 2000x2000 pixels.',
        ];
    }

    public function prepareForValidation(): void
    {
        // Normalize input before validation
        $this->merge([
            'name' => trim($this->name),
            'email' => strtolower(trim($this->email)),
        ]);
    }

    public function passedValidation(): void
    {
        // Additional processing after validation passes
        if ($this->hasFile('avatar')) {
            // Could add image processing here
            $this->merge([
                'avatar_path' => $this->file('avatar')->store('avatars', 'public')
            ]);
        }
    }
}

// =============================================================================
// LARAVEL CONTROLLER WITH VALIDATION
// =============================================================================

namespace App\Http\Controllers;

use App\Http\Requests\CreateUserRequest;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;

class UserController extends Controller
{
    public function store(CreateUserRequest $request): JsonResponse
    {
        try {
            $validated = $request->validated();

            // Additional security checks
            if (!$this->isValidPassword($validated['password'])) {
                return response()->json([
                    'success' => false,
                    'message' => 'Password does not meet security requirements'
                ], 422);
            }

            // Create user
            $user = User::create([
                'name' => $validated['name'],
                'email' => $validated['email'],
                'password' => Hash::make($validated['password']),
                'phone' => $validated['phone'] ?? null,
                'date_of_birth' => $validated['date_of_birth'] ?? null,
                'website' => $validated['website'] ?? null,
                'bio' => $validated['bio'] ?? null,
                'avatar' => $validated['avatar_path'] ?? null,
            ]);

            Log::info('User created successfully', [
                'user_id' => $user->id,
                'email' => $user->email,
                'ip' => $request->ip()
            ]);

            return response()->json([
                'success' => true,
                'message' => 'User created successfully',
                'user' => $user->only(['id', 'name', 'email'])
            ], 201);

        } catch (\Exception $e) {
            Log::error('User creation failed', [
                'error' => $e->getMessage(),
                'email' => $request->email,
                'ip' => $request->ip()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to create user. Please try again.'
            ], 500);
        }
    }

    /**
     * Additional password validation
     */
    private function isValidPassword(string $password): bool
    {
        // Check against breached password databases (concept)
        // In real implementation, you might use HaveIBeenPwned API

        $breachedPasswords = [
            'password123',
            '123456789',
            'qwerty123',
            // Add more or implement API call
        ];

        if (in_array(strtolower($password), $breachedPasswords)) {
            return false;
        }

        return true;
    }

    /**
     * Update user with validation
     */
    public function update(CreateUserRequest $request, User $user): JsonResponse
    {
        // Authorization check
        if ($request->user()->id !== $user->id && !$request->user()->hasRole('admin')) {
            return response()->json(['message' => 'Unauthorized'], 403);
        }

        $validated = $request->validated();

        // Remove password if not provided (don't require password change on update)
        if (empty($validated['password'])) {
            unset($validated['password']);
        } else {
            $validated['password'] = Hash::make($validated['password']);
        }

        $user->update($validated);

        return response()->json([
            'success' => true,
            'message' => 'User updated successfully'
        ]);
    }
}

// =============================================================================
// CUSTOM VALIDATION RULES
// =============================================================================

namespace App\Rules;

use Illuminate\Contracts\Validation\Rule;
use Illuminate\Support\Facades\Http;

class StrongPassword implements Rule
{
    public function passes($attribute, $value): bool
    {
        // Basic checks
        if (strlen($value) < 8) return false;
        if (!preg_match('/[A-Z]/', $value)) return false;
        if (!preg_match('/[a-z]/', $value)) return false;
        if (!preg_match('/\d/', $value)) return false;
        if (!preg_match('/[@$!%*?&]/', $value)) return false;

        // Check against common passwords
        $common = ['password', '123456', 'qwerty', 'admin', 'letmein'];
        if (in_array(strtolower($value), $common)) return false;

        // Optional: Check against HaveIBeenPwned
        // This is a concept - implement carefully to avoid rate limits
        // $hashedPassword = strtoupper(sha1($value));
        // $prefix = substr($hashedPassword, 0, 5);
        // $response = Http::get("https://api.pwnedpasswords.com/range/{$prefix}");
        // if (str_contains($response->body(), substr($hashedPassword, 5))) {
        //     return false;
        // }

        return true;
    }

    public function message(): string
    {
        return 'Password must be strong: at least 8 characters with uppercase, lowercase, number, and special character.';
    }
}

// =============================================================================
// FILE UPLOAD VALIDATION EXAMPLE
// =============================================================================

class SecureFileUpload
{
    private array $allowedTypes = [
        'image/jpeg' => ['jpg', 'jpeg'],
        'image/png' => ['png'],
        'image/gif' => ['gif'],
        'image/webp' => ['webp'],
        'application/pdf' => ['pdf'],
    ];

    private int $maxSize = 5242880; // 5MB

    public function validateAndProcessUpload(array $file): array
    {
        $result = [
            'success' => false,
            'path' => null,
            'error' => null
        ];

        // Check upload errors
        if ($file['error'] !== UPLOAD_ERR_OK) {
            $result['error'] = $this->getUploadErrorMessage($file['error']);
            return $result;
        }

        // Validate file size
        if ($file['size'] > $this->maxSize) {
            $result['error'] = 'File size exceeds 5MB limit';
            return $result;
        }

        // Get MIME type using multiple methods
        $mimeType = $this->getSecureMimeType($file['tmp_name']);
        if (!$mimeType || !isset($this->allowedTypes[$mimeType])) {
            $result['error'] = 'File type not allowed';
            return $result;
        }

        // Validate file extension matches MIME type
        $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($extension, $this->allowedTypes[$mimeType])) {
            $result['error'] = 'File extension does not match content type';
            return $result;
        }

        // Additional security checks
        if (!$this->isSafeFileContent($file['tmp_name'])) {
            $result['error'] = 'Potentially unsafe file detected';
            return $result;
        }

        // Generate secure filename
        $secureFilename = $this->generateSecureFilename($file['name']);

        // Move file to secure location
        $uploadDir = __DIR__ . '/../storage/uploads/';
        $destination = $uploadDir . $secureFilename;

        if (move_uploaded_file($file['tmp_name'], $destination)) {
            chmod($destination, 0644); // Secure permissions
            $result['success'] = true;
            $result['path'] = $secureFilename;
        } else {
            $result['error'] = 'Failed to save file';
        }

        return $result;
    }

    private function getSecureMimeType(string $filePath): ?string
    {
        // Method 1: finfo (most reliable)
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        if ($finfo) {
            $mime = finfo_file($finfo, $filePath);
            finfo_close($finfo);
            if ($mime) return $mime;
        }

        // Method 2: getimagesize for images
        $imageInfo = getimagesize($filePath);
        if ($imageInfo && isset($imageInfo['mime'])) {
            return $imageInfo['mime'];
        }

        return null;
    }

    private function isSafeFileContent(string $filePath): bool
    {
        $content = file_get_contents($filePath);

        // Check for PHP code or script tags
        if (preg_match('/<\?php|<script|<%/i', $content)) {
            return false;
        }

        // Check for null bytes (common in file upload attacks)
        if (str_contains($content, "\0")) {
            return false;
        }

        return true;
    }

    private function generateSecureFilename(string $originalName): string
    {
        $extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
        return bin2hex(random_bytes(16)) . '_' . time() . '.' . $extension;
    }

    private function getUploadErrorMessage(int $errorCode): string
    {
        return match($errorCode) {
            UPLOAD_ERR_INI_SIZE => 'File exceeds server size limit',
            UPLOAD_ERR_FORM_SIZE => 'File exceeds form size limit',
            UPLOAD_ERR_PARTIAL => 'File was only partially uploaded',
            UPLOAD_ERR_NO_FILE => 'No file was uploaded',
            UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder',
            UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk',
            UPLOAD_ERR_EXTENSION => 'File upload stopped by extension',
            default => 'Unknown upload error'
        };
    }
}

// =============================================================================
// USAGE EXAMPLES
// =============================================================================

/*
// PHP Validation Usage
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $errors = [];

    // Validate email
    if (!PHPInputValidator::validateEmail($_POST['email'] ?? '')) {
        $errors[] = 'Invalid email address';
    }

    // Validate username
    if (!PHPInputValidator::validateUsername($_POST['username'] ?? '')) {
        $errors[] = 'Invalid username';
    }

    // Validate password
    $passwordValidation = PHPInputValidator::validatePassword($_POST['password'] ?? '');
    if (!$passwordValidation['valid']) {
        $errors = array_merge($errors, $passwordValidation['errors']);
    }

    if (empty($errors)) {
        // Process form data securely
        $name = OutputSanitizer::forHtml($_POST['name']);
        // ... rest of processing
    }
}

// Laravel Usage in routes/web.php:
// Route::post('/users', [UserController::class, 'store']);

// With custom validation rule:
// 'password' => ['required', 'min:8', new StrongPassword],
*/
?>
