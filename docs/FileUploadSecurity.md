# File Upload Security

## The Dangers of File Uploads

File upload functionality is one of the most dangerous features in web applications. Attackers can exploit file uploads to:

- **Execute malicious code** on the server
- **Access sensitive files** through directory traversal
- **Spread malware** to other users
- **Perform denial of service** attacks
- **Bypass security controls** using uploaded backdoors

### Real-World File Upload Attacks

- **Shell uploads**: PHP shells disguised as images
- **Web shell access**: Remote code execution via uploaded scripts
- **Malware distribution**: Infecting users who download files
- **Server compromise**: Gaining full system access

## File Upload Attack Vectors

### 1. Malicious File Extensions

```php
// VULNERABLE: Only checking client-provided extension
$filename = $_FILES['file']['name'];
$extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

if ($extension === 'jpg' || $extension === 'png') {
    // Attacker can upload shell.php.jpg which becomes shell.php
    move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $filename);
}
```

### 2. MIME Type Spoofing

```php
// VULNERABLE: Trusting MIME type from client
$mimeType = $_FILES['file']['type'];

if ($mimeType === 'image/jpeg') {
    // MIME type can be easily spoofed
    move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $filename);
}
```

### 3. Directory Traversal

```php
// VULNERABLE: Allowing path traversal
$filename = $_FILES['file']['name'];

// Attacker uploads with name: ../../../etc/passwd
if (move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $filename)) {
    // File ends up in /etc/passwd, overwriting system file
}
```

### 4. Null Byte Injection

```php
// VULNERABLE: Null byte injection
$filename = $_FILES['file']['name'];
$filename = str_replace("\0", '', $filename); // Incomplete protection

// Attacker: shell.php%00.jpg becomes shell.php when saved
```

## Secure File Upload Principles

### 1. Never Trust Client Input

- **File names** can be malicious
- **MIME types** can be spoofed
- **File extensions** can be bypassed
- **File contents** can be disguised

### 2. Use Defense in Depth

- **Multiple validation layers**
- **Server-side verification**
- **Content analysis**
- **Secure storage**

### 3. Principle of Least Privilege

- **Restrict file permissions**
- **Limit execution rights**
- **Isolate uploaded files**

## File Validation Strategies

### MIME Type Validation

#### Method 1: File Extension + MIME Type

```php
class FileValidator
{
    private static array $allowedTypes = [
        'image/jpeg' => ['jpg', 'jpeg'],
        'image/png' => ['png'],
        'image/gif' => ['gif'],
        'image/webp' => ['webp'],
        'application/pdf' => ['pdf'],
        'text/plain' => ['txt'],
        'application/msword' => ['doc'],
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => ['docx'],
    ];

    public static function validateFile(array $file): array
    {
        $result = [
            'valid' => false,
            'error' => '',
            'safe_filename' => ''
        ];

        // Check upload errors
        if ($file['error'] !== UPLOAD_ERR_OK) {
            $result['error'] = self::getUploadErrorMessage($file['error']);
            return $result;
        }

        // Validate file size (5MB max)
        if ($file['size'] > 5242880) {
            $result['error'] = 'File size exceeds 5MB limit';
            return $result;
        }

        // Validate file size (minimum 1 byte)
        if ($file['size'] < 1) {
            $result['error'] = 'File is empty';
            return $result;
        }

        // Get MIME type using multiple methods
        $mimeType = self::getSecureMimeType($file['tmp_name']);
        if (!$mimeType) {
            $result['error'] = 'Could not determine file type';
            return $result;
        }

        // Validate MIME type is allowed
        if (!isset(self::$allowedTypes[$mimeType])) {
            $result['error'] = 'File type not allowed';
            return $result;
        }

        // Validate file extension matches MIME type
        $originalExtension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($originalExtension, self::$allowedTypes[$mimeType])) {
            $result['error'] = 'File extension does not match content type';
            return $result;
        }

        // Additional security checks
        if (!self::isSafeFileContent($file['tmp_name'], $mimeType)) {
            $result['error'] = 'File contains potentially unsafe content';
            return $result;
        }

        // Generate safe filename
        $result['safe_filename'] = self::generateSecureFilename($file['name']);
        $result['valid'] = true;

        return $result;
    }

    private static function getSecureMimeType(string $filePath): ?string
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

        // Method 3: mime_content_type (fallback)
        $mime = mime_content_type($filePath);
        if ($mime) return $mime;

        return null;
    }

    private static function isSafeFileContent(string $filePath, string $mimeType): bool
    {
        $content = file_get_contents($filePath);

        // Check for null bytes (common in file upload attacks)
        if (str_contains($content, "\0")) {
            return false;
        }

        // Check for script content in non-script files
        if (!str_starts_with($mimeType, 'text/') && !str_starts_with($mimeType, 'application/')) {
            if (preg_match('/<\?php|<script|<%/i', $content)) {
                return false;
            }
        }

        // Additional checks based on MIME type
        switch ($mimeType) {
            case 'image/jpeg':
            case 'image/png':
            case 'image/gif':
            case 'image/webp':
                // Verify image file headers
                return self::validateImageHeaders($filePath, $mimeType);

            case 'text/plain':
                // Check for script content in text files
                return !preg_match('/<\?php|<script|<%|javascript:/i', $content);

            case 'application/pdf':
                // Check PDF header
                return str_starts_with($content, '%PDF-');

            default:
                return true;
        }
    }

    private static function validateImageHeaders(string $filePath, string $mimeType): bool
    {
        $handle = fopen($filePath, 'rb');
        if (!$handle) return false;

        $header = fread($handle, 12);
        fclose($handle);

        return match ($mimeType) {
            'image/jpeg' => str_starts_with($header, "\xFF\xD8\xFF"),
            'image/png' => str_starts_with($header, "\x89PNG\r\n\x1A\n"),
            'image/gif' => str_starts_with($header, 'GIF87a') || str_starts_with($header, 'GIF89a'),
            'image/webp' => str_starts_with($header, 'RIFF') && strpos($header, 'WEBP') !== false,
            default => false
        };
    }

    private static function generateSecureFilename(string $originalName): string
    {
        // Remove path traversal attempts
        $safeName = basename($originalName);

        // Get extension
        $extension = strtolower(pathinfo($safeName, PATHINFO_EXTENSION));

        // Generate secure random name
        $randomName = bin2hex(random_bytes(16));

        // Add timestamp for uniqueness
        $timestamp = time();

        return $timestamp . '_' . $randomName . '.' . $extension;
    }

    private static function getUploadErrorMessage(int $errorCode): string
    {
        return match ($errorCode) {
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
```

### File Storage Security

#### Never Store in Web Root

```php
// ❌ DANGEROUS: Storing in public web directory
move_uploaded_file($file['tmp_name'], '/var/www/html/uploads/' . $filename);

// ✅ SECURE: Store outside web root
$uploadDir = '/var/secure/uploads/'; // Outside web root
move_uploaded_file($file['tmp_name'], $uploadDir . $safeFilename);

// Serve files through PHP script
if (preg_match('/^[a-f0-9_]+\.[a-zA-Z0-9]+$/', $_GET['file'])) {
    $filePath = $uploadDir . $_GET['file'];
    if (file_exists($filePath)) {
        // Check permissions, log access, etc.
        header('Content-Type: ' . mime_content_type($filePath));
        readfile($filePath);
        exit;
    }
}
```

#### Secure Directory Structure

```php
class SecureFileStorage
{
    private string $baseDir;

    public function __construct(string $baseDir = '/var/secure/uploads/')
    {
        $this->baseDir = rtrim($baseDir, '/') . '/';

        // Ensure base directory exists and is secure
        if (!is_dir($this->baseDir)) {
            mkdir($this->baseDir, 0755, true);
        }

        // Set proper permissions
        chmod($this->baseDir, 0755);
    }

    public function storeFile(string $tempPath, string $safeFilename, string $userId): string
    {
        // Create user-specific directory
        $userDir = $this->baseDir . 'user_' . $userId . '/';
        if (!is_dir($userDir)) {
            mkdir($userDir, 0755, true);
        }

        // Create date-based subdirectory
        $dateDir = $userDir . date('Y/m/d') . '/';
        if (!is_dir($dateDir)) {
            mkdir($dateDir, 0755, true);
        }

        $finalPath = $dateDir . $safeFilename;

        // Move file to secure location
        if (move_uploaded_file($tempPath, $finalPath)) {
            // Set secure permissions (readable by owner and group, no execute)
            chmod($finalPath, 0640);

            return $finalPath;
        }

        throw new RuntimeException('Failed to store file');
    }

    public function getSecurePath(string $filename, string $userId): ?string
    {
        // Validate filename format
        if (!preg_match('/^\d+_[a-f0-9]+\.[a-zA-Z0-9]+$/', $filename)) {
            return null;
        }

        $userDir = $this->baseDir . 'user_' . $userId . '/';

        // Find file in user directory (prevent directory traversal)
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($userDir));
        foreach ($iterator as $file) {
            if ($file->isFile() && basename($file->getFilename()) === $filename) {
                return $file->getPathname();
            }
        }

        return null;
    }
}
```

## Laravel File Upload Security

### Laravel Validation Rules

```php
<?php
namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class SecureFileUploadRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'avatar' => [
                'required',
                'file',
                'max:2048', // 2MB
                'mimes:jpeg,png,jpg,gif,webp',
                'dimensions:min_width=100,min_height=100,max_width=2000,max_height=2000',
                function ($attribute, $value, $fail) {
                    if (!$this->isFileSafe($value)) {
                        $fail('The uploaded file contains potentially unsafe content.');
                    }
                },
            ],
            'document' => [
                'nullable',
                'file',
                'max:10240', // 10MB
                'mimes:pdf,doc,docx,txt',
            ],
        ];
    }

    public function messages(): array
    {
        return [
            'avatar.max' => 'Avatar file size must not exceed 2MB.',
            'avatar.mimes' => 'Avatar must be a JPEG, PNG, JPG, GIF, or WebP image.',
            'avatar.dimensions' => 'Avatar dimensions must be between 100x100 and 2000x2000 pixels.',
            'document.max' => 'Document file size must not exceed 10MB.',
            'document.mimes' => 'Document must be a PDF, DOC, DOCX, or TXT file.',
        ];
    }

    private function isFileSafe($file): bool
    {
        if (!$file instanceof \Illuminate\Http\UploadedFile) {
            return false;
        }

        $path = $file->getRealPath();
        $content = file_get_contents($path);

        // Check for dangerous content
        if (preg_match('/<\?php|<script|<%/i', $content)) {
            return false;
        }

        // Validate image headers for images
        if (str_starts_with($file->getMimeType(), 'image/')) {
            return $this->validateImageHeaders($path, $file->getMimeType());
        }

        return true;
    }

    private function validateImageHeaders(string $path, string $mimeType): bool
    {
        $handle = fopen($path, 'rb');
        if (!$handle) return false;

        $header = fread($handle, 12);
        fclose($handle);

        return match ($mimeType) {
            'image/jpeg' => str_starts_with($header, "\xFF\xD8\xFF"),
            'image/png' => str_starts_with($header, "\x89PNG\r\n\x1A\n"),
            'image/gif' => str_starts_with($header, 'GIF87a') || str_starts_with($header, 'GIF89a'),
            'image/webp' => str_starts_with($header, 'RIFF') && strpos($header, 'WEBP') !== false,
            default => false
        };
    }
}
```

### Laravel Secure File Storage

```php
<?php
namespace App\Services;

use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;

class SecureFileUploadService
{
    public function storeSecurely(UploadedFile $file, string $directory = 'uploads', string $disk = 'secure'): string
    {
        // Generate secure filename
        $originalName = $file->getClientOriginalName();
        $extension = $file->getClientOriginalExtension();
        $filename = Str::uuid() . '_' . time() . '.' . $extension;

        // Store file on secure disk
        $path = $file->storeAs($directory, $filename, $disk);

        // Log upload for security monitoring
        \Log::info('File uploaded securely', [
            'original_name' => $originalName,
            'stored_name' => $filename,
            'size' => $file->getSize(),
            'mime_type' => $file->getMimeType(),
            'user_id' => auth()->id(),
            'ip_address' => request()->ip(),
        ]);

        return $path;
    }

    public function serveSecureFile(string $path, string $disk = 'secure')
    {
        // Check if user has permission to access file
        if (!$this->userCanAccessFile($path)) {
            abort(403, 'Access denied');
        }

        // Log file access
        \Log::info('File accessed', [
            'path' => $path,
            'user_id' => auth()->id(),
            'ip_address' => request()->ip(),
        ]);

        // Serve file with appropriate headers
        return Storage::disk($disk)->download($path);
    }

    private function userCanAccessFile(string $path): bool
    {
        $userId = auth()->id();

        // Check if file belongs to user (based on filename or database)
        // Implementation depends on your access control requirements

        return true; // Placeholder - implement proper access control
    }
}
```

### Laravel Controller with Secure Upload

```php
<?php
namespace App\Http\Controllers;

use App\Http\Requests\SecureFileUploadRequest;
use App\Services\SecureFileUploadService;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Storage;

class FileUploadController extends Controller
{
    private SecureFileUploadService $uploadService;

    public function __construct(SecureFileUploadService $uploadService)
    {
        $this->uploadService = $uploadService;
    }

    public function upload(SecureFileUploadRequest $request): JsonResponse
    {
        try {
            $uploadedFiles = [];

            // Handle avatar upload
            if ($request->hasFile('avatar')) {
                $path = $this->uploadService->storeSecurely(
                    $request->file('avatar'),
                    'avatars',
                    'secure'
                );
                $uploadedFiles['avatar'] = $path;

                // Update user avatar
                auth()->user()->update(['avatar' => $path]);
            }

            // Handle document upload
            if ($request->hasFile('document')) {
                $path = $this->uploadService->storeSecurely(
                    $request->file('document'),
                    'documents',
                    'secure'
                );
                $uploadedFiles['document'] = $path;
            }

            return response()->json([
                'success' => true,
                'message' => 'Files uploaded successfully',
                'files' => $uploadedFiles
            ]);

        } catch (\Exception $e) {
            \Log::error('File upload failed', [
                'error' => $e->getMessage(),
                'user_id' => auth()->id(),
                'ip_address' => $request->ip(),
            ]);

            return response()->json([
                'success' => false,
                'message' => 'File upload failed'
            ], 500);
        }
    }

    public function download(string $filename)
    {
        try {
            return $this->uploadService->serveSecureFile('documents/' . $filename);
        } catch (\Exception $e) {
            abort(404, 'File not found');
        }
    }
}
```

## Advanced Security Measures

### File Content Analysis

```php
class FileContentAnalyzer
{
    public static function analyzeFile(string $filePath): array
    {
        $results = [
            'safe' => true,
            'warnings' => [],
            'threats' => []
        ];

        $content = file_get_contents($filePath);
        $mimeType = mime_content_type($filePath);

        // Check for embedded scripts
        if (preg_match_all('/<\?php|<script|<%|javascript:/i', $content, $matches)) {
            $results['safe'] = false;
            $results['threats'][] = 'Embedded scripts detected: ' . implode(', ', $matches[0]);
        }

        // Check for suspicious file signatures
        if (self::hasSuspiciousSignatures($content, $mimeType)) {
            $results['safe'] = false;
            $results['threats'][] = 'Suspicious file signatures detected';
        }

        // Check file entropy (potential encryption/obfuscation)
        $entropy = self::calculateEntropy($content);
        if ($entropy > 7.5) { // High entropy might indicate compressed/encrypted content
            $results['warnings'][] = 'High file entropy detected (potential obfuscation)';
        }

        return $results;
    }

    private static function hasSuspiciousSignatures(string $content, string $mimeType): bool
    {
        // Check for common malware signatures
        $suspiciousPatterns = [
            '/eval\(/i',
            '/base64_decode\(/i',
            '/gzinflate\(/i',
            '/str_rot13\(/i',
            '/shell_exec\(/i',
            '/exec\(/i',
            '/system\(/i',
        ];

        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }

        return false;
    }

    private static function calculateEntropy(string $content): float
    {
        $length = strlen($content);
        if ($length === 0) return 0;

        $charCounts = count_chars($content, 1);
        $entropy = 0;

        foreach ($charCounts as $count) {
            $probability = $count / $length;
            $entropy -= $probability * log($probability, 2);
        }

        return $entropy;
    }
}
```

### Rate Limiting Uploads

```php
class UploadRateLimiter
{
    private static int $maxUploadsPerHour = 10;
    private static int $maxUploadsPerDay = 50;

    public static function canUpload(string $userId): bool
    {
        $now = time();
        $hourAgo = $now - 3600;
        $dayAgo = $now - 86400;

        // Check hourly limit
        $hourlyUploads = self::countUploads($userId, $hourAgo, $now);
        if ($hourlyUploads >= self::$maxUploadsPerHour) {
            return false;
        }

        // Check daily limit
        $dailyUploads = self::countUploads($userId, $dayAgo, $now);
        if ($dailyUploads >= self::$maxUploadsPerDay) {
            return false;
        }

        return true;
    }

    public static function recordUpload(string $userId, string $filename, int $fileSize): void
    {
        // Store upload record in database/cache
        $stmt = self::getDB()->prepare("
            INSERT INTO upload_logs (user_id, filename, file_size, uploaded_at)
            VALUES (?, ?, ?, NOW())
        ");
        $stmt->execute([$userId, $filename, $fileSize]);
    }

    private static function countUploads(string $userId, int $startTime, int $endTime): int
    {
        $stmt = self::getDB()->prepare("
            SELECT COUNT(*) as count FROM upload_logs
            WHERE user_id = ? AND uploaded_at BETWEEN FROM_UNIXTIME(?) AND FROM_UNIXTIME(?)
        ");
        $stmt->execute([$userId, $startTime, $endTime]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        return (int) $result['count'];
    }

    private static function getDB(): PDO
    {
        // Return database connection
        static $pdo = null;
        if ($pdo === null) {
            $pdo = new PDO("mysql:host=localhost;dbname=secure_uploads", "user", "pass");
        }
        return $pdo;
    }
}
```

## File Upload Security Checklist

### Pre-Upload Validation
- [ ] Validate file size limits
- [ ] Check MIME types against allowlist
- [ ] Verify file extensions match content
- [ ] Scan file content for malicious code
- [ ] Implement rate limiting per user

### Storage Security
- [ ] Store files outside web root
- [ ] Generate secure random filenames
- [ ] Set restrictive file permissions
- [ ] Use separate directories per user
- [ ] Log all upload activities

### Access Control
- [ ] Require authentication for uploads
- [ ] Implement authorization checks
- [ ] Serve files through PHP (not direct access)
- [ ] Add download rate limiting
- [ ] Implement file expiration

### Monitoring & Maintenance
- [ ] Log all file operations
- [ ] Regular malware scanning
- [ ] Implement backup strategies
- [ ] Set up automated cleanup
- [ ] Monitor disk space usage

## Summary: File Upload Security Rules

1. **Never trust client-provided file data** - Validate everything server-side
2. **Use allowlists for file types** - Don't rely on blocklists
3. **Validate file content, not just extensions** - Check actual file headers
4. **Store files securely outside web root** - Prevent direct access
5. **Generate secure random filenames** - Prevent enumeration and traversal
6. **Set restrictive permissions** - Limit access to necessary users
7. **Implement rate limiting** - Prevent abuse and DoS attacks
8. **Log all upload activities** - Monitor for suspicious behavior
9. **Regular security scanning** - Check for malware and vulnerabilities
10. **Test thoroughly** - Include upload security in penetration testing

## Next Steps

Now that you understand file upload security, explore:

- **[Secure Configuration](SecureConfiguration.md)** - Protect your application configuration
- **[Secure Headers](SecureHeaders.md)** - Implement security headers
- **[Authentication & Password Handling](AuthenticationPasswordHandling.md)** - Secure user authentication

Remember: File uploads are a high-risk feature. Implement multiple layers of security and regular monitoring to protect your application and users!
