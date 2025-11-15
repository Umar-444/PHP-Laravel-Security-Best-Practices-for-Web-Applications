# Input Handling: Validation & Sanitization

## Why Input Handling Matters

Input handling is the foundation of web application security. All user input should be considered potentially malicious until proven otherwise. Proper input validation and sanitization prevents the majority of common web vulnerabilities including SQL injection, XSS, and command injection.

### The Core Principle

**"Never trust user input"** - This is the fundamental rule of secure web development.

## Input Validation vs Sanitization

### Input Validation
- **Purpose**: Ensures data meets expected criteria
- **Approach**: Checks if input is what we expect
- **Result**: Accepts or rejects data
- **When**: Always performed first

### Input Sanitization
- **Purpose**: Cleans or transforms data to make it safe
- **Approach**: Removes or encodes dangerous characters
- **Result**: Modified safe data
- **When**: Performed after validation

## Validation Strategies

### Allow-List vs Block-List Approach

#### Block-List (Deny-List) Approach ❌
```php
// PROBLEMATIC: Block-list approach
function validateUsername($username) {
    // Remove potentially dangerous characters
    $username = str_replace(['<', '>', '"', "'"], '', $username);

    // Check length
    if (strlen($username) < 3 || strlen($username) > 20) {
        return false;
    }

    return true;
}
```
**Problems with Block-List:**
- Easy to miss dangerous characters
- New attack vectors can bypass filters
- Character encoding issues
- Context-dependent dangerous characters

#### Allow-List (Permit-List) Approach ✅
```php
function validateUsername($username) {
    // Only allow specific characters
    if (!preg_match('/^[a-zA-Z0-9_-]{3,20}$/', $username)) {
        return false;
    }

    return true;
}
```
**Advantages of Allow-List:**
- Explicit about what is allowed
- Much harder to bypass
- Clear and maintainable
- Reduces attack surface

## PHP Validation Functions

### Built-in Filter Functions

#### Email Validation
```php
// Basic email validation
$email = $_POST['email'];
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    die("Invalid email format");
}

// Advanced email validation with options
$email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL, [
    'options' => [
        'default' => false // Return false instead of null
    ]
]);
```

#### URL Validation
```php
$url = $_POST['website'];
if (!filter_var($url, FILTER_VALIDATE_URL)) {
    die("Invalid URL format");
}

// Validate URL with specific schemes
$url = filter_var($_POST['website'], FILTER_VALIDATE_URL, [
    'options' => [
        'default' => false,
        'flags' => FILTER_FLAG_SCHEME_REQUIRED | FILTER_FLAG_HOST_REQUIRED
    ],
    'flags' => FILTER_FLAG_SCHEME_REQUIRED
]);
```

#### Integer Validation
```php
$id = $_POST['user_id'];

// Basic integer validation
if (!filter_var($id, FILTER_VALIDATE_INT)) {
    die("Invalid user ID");
}

// Integer within range
$id = filter_var($id, FILTER_VALIDATE_INT, [
    'options' => [
        'min_range' => 1,
        'max_range' => 1000
    ]
]);
```

#### Float Validation
```php
$price = $_POST['price'];
$price = filter_var($price, FILTER_VALIDATE_FLOAT, [
    'options' => [
        'min_range' => 0.01,
        'max_range' => 999.99
    ]
]);
```

### Regular Expression Validation

#### Common Patterns
```php
class InputValidator
{
    public static function validateUsername($username) {
        // Alphanumeric, underscore, hyphen (3-20 chars)
        return preg_match('/^[a-zA-Z0-9_-]{3,20}$/', $username);
    }

    public static function validatePassword($password) {
        // At least 8 chars, one uppercase, one lowercase, one digit
        return preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/', $password);
    }

    public static function validatePhone($phone) {
        // US phone format: (123) 456-7890 or 123-456-7890
        return preg_match('/^(\(\d{3}\)\s?|\d{3}-?)\d{3}-?\d{4}$/', $phone);
    }

    public static function validatePostalCode($zip) {
        // US ZIP code: 12345 or 12345-6789
        return preg_match('/^\d{5}(-\d{4})?$/', $zip);
    }
}
```

## Laravel Validation

### Form Request Validation
```php
<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class CreateUserRequest extends FormRequest
{
    public function authorize()
    {
        return true; // Or implement authorization logic
    }

    public function rules()
    {
        return [
            'name' => 'required|string|min:2|max:50',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|string|min:8|confirmed',
            'age' => 'nullable|integer|min:18|max:120',
            'website' => 'nullable|url',
            'phone' => 'nullable|regex:/^(\(\d{3}\)\s?|\d{3}-?)\d{3}-?\d{4}$/',
        ];
    }

    public function messages()
    {
        return [
            'name.required' => 'Name is required',
            'email.email' => 'Please provide a valid email address',
            'password.min' => 'Password must be at least 8 characters',
        ];
    }
}
```

### Controller Validation
```php
public function store(CreateUserRequest $request)
{
    // Validation is automatically handled by CreateUserRequest

    $validated = $request->validated();

    // Create user with validated data
    User::create($validated);

    return response()->json(['message' => 'User created successfully']);
}
```

### Manual Validation
```php
public function updateProfile(Request $request)
{
    $request->validate([
        'name' => 'required|string|min:2|max:50',
        'email' => 'required|email|unique:users,email,' . auth()->id(),
        'bio' => 'nullable|string|max:500',
    ]);

    // Update profile...
}
```

## Output Sanitization

### HTML Context Sanitization
```php
class OutputSanitizer
{
    public static function sanitizeForHtml($data) {
        return htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    public static function sanitizeForAttribute($data) {
        return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    }

    public static function sanitizeForJavaScript($data) {
        return json_encode($data, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
    }

    public static function sanitizeForUrl($data) {
        return urlencode($data);
    }
}

// Usage
$name = $_GET['name'];
echo "<h1>Welcome, " . OutputSanitizer::sanitizeForHtml($name) . "!</h1>";
```

### Laravel Blade Sanitization
```blade
{{-- Automatic escaping --}}
<h1>Welcome, {{ $name }}</h1>

{{-- Explicit unescaping (use only for trusted content) --}}
<h1>Welcome, {!! $trustedHtml !!}</h1>

{{-- Attribute escaping --}}
<input type="text" value="{{ $value }}" />

{{-- JavaScript escaping --}}
<script>
    var userData = {!! json_encode($userData) !!};
</script>
```

## Preventing Broken Data Entry

### Type Juggling Prevention
```php
// PROBLEMATIC: PHP type juggling
$userId = $_GET['id']; // "123abc" becomes 123

// SECURE: Strict type checking
$userId = filter_var($_GET['id'], FILTER_VALIDATE_INT);
if ($userId === false) {
    throw new InvalidArgumentException('Invalid user ID');
}

// Even better: Use strict types
declare(strict_types=1);

function getUserById(int $userId): ?User
{
    return User::find($userId);
}

// Call with type checking
$userId = (int) $_GET['id'];
if ($userId <= 0) {
    throw new InvalidArgumentException('User ID must be positive integer');
}
```

### Numeric Validation
```php
class NumericValidator
{
    public static function validatePositiveInteger($value, $max = null) {
        $int = filter_var($value, FILTER_VALIDATE_INT, [
            'options' => [
                'min_range' => 1,
                'max_range' => $max
            ]
        ]);

        return $int !== false;
    }

    public static function validateDecimal($value, $decimals = 2) {
        if (!is_numeric($value)) {
            return false;
        }

        $parts = explode('.', $value);
        if (count($parts) > 2) {
            return false;
        }

        if (isset($parts[1]) && strlen($parts[1]) > $decimals) {
            return false;
        }

        return true;
    }
}
```

## Input Filtering Techniques

### Trim and Normalize
```php
function normalizeInput($input) {
    // Trim whitespace
    $input = trim($input);

    // Normalize Unicode (prevent homograph attacks)
    $input = normalizer_normalize($input, Normalizer::FORM_C);

    // Convert to lowercase for case-insensitive fields
    // $input = mb_strtolower($input);

    return $input;
}
```

### Length Validation
```php
class LengthValidator
{
    public static function validateLength($input, $min = null, $max = null) {
        $length = mb_strlen($input); // Multi-byte safe

        if ($min !== null && $length < $min) {
            return false;
        }

        if ($max !== null && $length > $max) {
            return false;
        }

        return true;
    }

    public static function truncate($input, $maxLength) {
        return mb_substr($input, 0, $maxLength);
    }
}
```

## File Upload Validation

### Basic File Validation
```php
class FileValidator
{
    private static $allowedMimeTypes = [
        'image/jpeg' => ['jpg', 'jpeg'],
        'image/png' => ['png'],
        'image/gif' => ['gif'],
        'application/pdf' => ['pdf'],
    ];

    public static function validateUploadedFile($file) {
        // Check if file was uploaded
        if (!isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
            return ['valid' => false, 'error' => 'Upload failed'];
        }

        // Validate file size (5MB max)
        if ($file['size'] > 5242880) {
            return ['valid' => false, 'error' => 'File too large'];
        }

        // Get MIME type
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mimeType = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);

        // Validate MIME type
        if (!array_key_exists($mimeType, self::$allowedMimeTypes)) {
            return ['valid' => false, 'error' => 'Invalid file type'];
        }

        // Validate extension matches MIME type
        $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($extension, self::$allowedMimeTypes[$mimeType])) {
            return ['valid' => false, 'error' => 'Extension does not match file type'];
        }

        return ['valid' => true];
    }
}
```

## Laravel File Validation
```php
public function uploadFile(Request $request)
{
    $request->validate([
        'file' => [
            'required',
            'file',
            'max:5120', // 5MB
            'mimes:jpeg,png,pdf,docx',
            'dimensions:min_width=100,min_height=100,max_width=2000,max_height=2000', // For images
        ]
    ]);

    // Additional security checks
    $file = $request->file('file');

    // Check file content (basic malware detection)
    $content = file_get_contents($file->getRealPath());
    if (preg_match('/<\?php|<%|script|javascript:/i', $content)) {
        return response()->json(['error' => 'Suspicious file content detected'], 422);
    }

    // Store securely
    $path = $file->store('uploads', 'public');

    return response()->json(['path' => $path]);
}
```

## Common Input Validation Patterns

### Email Validation with DNS Check
```php
function validateEmailWithDNS($email) {
    // Basic format validation
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return false;
    }

    // Extract domain
    $domain = substr(strrchr($email, "@"), 1);

    // Check DNS records (MX or A record)
    return checkdnsrr($domain, 'MX') || checkdnsrr($domain, 'A');
}
```

### Strong Password Validation
```php
class PasswordValidator
{
    public static function isStrong($password) {
        $checks = [
            'length' => strlen($password) >= 8,
            'uppercase' => preg_match('/[A-Z]/', $password),
            'lowercase' => preg_match('/[a-z]/', $password),
            'digit' => preg_match('/\d/', $password),
            'special' => preg_match('/[@$!%*?&]/', $password),
            'no_common' => !preg_match('/password|123456|qwerty/i', $password),
        ];

        return !in_array(false, $checks, true);
    }

    public static function getStrengthScore($password) {
        $score = 0;

        if (strlen($password) >= 8) $score += 20;
        if (preg_match('/[A-Z]/', $password)) $score += 20;
        if (preg_match('/[a-z]/', $password)) $score += 20;
        if (preg_match('/\d/', $password)) $score += 20;
        if (preg_match('/[@$!%*?&]/', $password)) $score += 20;

        return $score;
    }
}
```

## Best Practices Summary

1. **Always validate input** - Never skip validation
2. **Use allow-lists** - Prefer over block-lists
3. **Validate on server-side** - Client-side validation can be bypassed
4. **Sanitize output** - Escape data based on context
5. **Use appropriate filters** - Choose the right validation method
6. **Handle errors gracefully** - Don't expose validation logic
7. **Log validation failures** - Monitor for attack patterns
8. **Keep validation rules updated** - Regular security reviews

## Next Steps

Now that you understand input handling, explore:

- **[SQL Injection Prevention](SQLInjectionPrevention.md)** - Database security
- **[Authentication & Password Handling](AuthenticationPasswordHandling.md)** - User security
- **[Secure Coding Basics](SecureCodingBasics.md)** - Overall security principles

Remember: Input validation is your first line of defense against web attacks.
