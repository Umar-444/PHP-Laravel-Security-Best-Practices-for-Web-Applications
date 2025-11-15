<?php

/**
 * File Upload Security Examples: Vulnerable vs Secure File Upload Implementations
 *
 * Practical examples of file upload vulnerabilities and their secure solutions
 */

declare(strict_types=1);

// =============================================================================
// 1. BASIC FILE UPLOAD VULNERABILITIES
// =============================================================================

class FileUploadVulnerabilities
{
    /**
     * ❌ EXTREMELY VULNERABLE: No validation, direct storage in web root
     * Allows any file type, any size, stored in accessible location
     */
    public function uploadFileVulnerable(): string
    {
        if (!isset($_FILES['file'])) {
            return 'No file uploaded';
        }

        $file = $_FILES['file'];

        // NO VALIDATION WHATSOEVER
        $uploadDir = 'uploads/'; // In web root - DANGEROUS!
        $filename = $file['name']; // User-controlled filename - VULNERABLE!

        $destination = $uploadDir . $filename;

        if (move_uploaded_file($file['tmp_name'], $destination)) {
            return "File uploaded successfully: <a href='{$destination}'>{$filename}</a>";
        }

        return 'Upload failed';
    }

    /**
     * ❌ VULNERABLE: Basic extension check only
     * Can be bypassed with double extensions, null bytes, etc.
     */
    public function uploadFileWeakValidation(): string
    {
        if (!isset($_FILES['file'])) {
            return 'No file uploaded';
        }

        $file = $_FILES['file'];
        $filename = $file['name'];

        // WEAK: Only checking file extension
        $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];
        $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

        if (!in_array($extension, $allowedExtensions)) {
            return 'Invalid file type';
        }

        // Still storing in web root - dangerous
        $uploadDir = 'uploads/';
        $destination = $uploadDir . $filename;

        if (move_uploaded_file($file['tmp_name'], $destination)) {
            return "File uploaded: {$filename}";
        }

        return 'Upload failed';
    }

    /**
     * ❌ VULNERABLE: MIME type spoofing
     * MIME types from $_FILES can be easily spoofed
     */
    public function uploadFileMimeSpoofing(): string
    {
        if (!isset($_FILES['file'])) {
            return 'No file uploaded';
        }

        $file = $_FILES['file'];
        $filename = $file['name'];

        // VULNERABLE: Trusting client-provided MIME type
        $allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif'];
        $mimeType = $file['type'];

        if (!in_array($mimeType, $allowedMimeTypes)) {
            return 'Invalid file type';
        }

        // Attacker can spoof MIME type in request
        $uploadDir = 'uploads/';
        $destination = $uploadDir . $filename;

        if (move_uploaded_file($file['tmp_name'], $destination)) {
            return "File uploaded: {$filename}";
        }

        return 'Upload failed';
    }

    /**
     * ❌ VULNERABLE: Directory traversal attack
     * Allows accessing files outside upload directory
     */
    public function uploadFileDirectoryTraversal(): string
    {
        if (!isset($_FILES['file'])) {
            return 'No file uploaded';
        }

        $file = $_FILES['file'];

        // VULNERABLE: Using user filename directly
        $filename = $file['name'];

        // Attacker can use: ../../../etc/passwd
        $uploadDir = 'uploads/';
        $destination = $uploadDir . $filename;

        if (move_uploaded_file($file['tmp_name'], $destination)) {
            return "File uploaded: {$filename}";
        }

        return 'Upload failed';
    }
}

// =============================================================================
// 2. SECURE FILE UPLOAD IMPLEMENTATION
// =============================================================================

class SecureFileUpload
{
    private array $allowedTypes = [
        'image/jpeg' => ['jpg', 'jpeg'],
        'image/png' => ['png'],
        'image/gif' => ['gif'],
        'image/webp' => ['webp'],
        'application/pdf' => ['pdf'],
        'text/plain' => ['txt'],
    ];

    private int $maxFileSize = 5242880; // 5MB
    private string $uploadDir;

    public function __construct(string $uploadDir = '/var/secure/uploads/')
    {
        $this->uploadDir = rtrim($uploadDir, '/') . '/';

        // Ensure upload directory exists and is secure
        if (!is_dir($this->uploadDir)) {
            mkdir($this->uploadDir, 0755, true);
        }

        if (!is_writable($this->uploadDir)) {
            throw new RuntimeException('Upload directory is not writable');
        }
    }

    /**
     * ✅ SECURE: Complete file upload validation and storage
     */
    public function uploadFileSecure(array $file): array
    {
        $result = [
            'success' => false,
            'filename' => null,
            'error' => null,
            'path' => null
        ];

        // Step 1: Validate upload success
        if ($file['error'] !== UPLOAD_ERR_OK) {
            $result['error'] = $this->getUploadErrorMessage($file['error']);
            return $result;
        }

        // Step 2: Validate file size
        if ($file['size'] > $this->maxFileSize) {
            $result['error'] = 'File size exceeds 5MB limit';
            return $result;
        }

        if ($file['size'] < 1) {
            $result['error'] = 'File is empty';
            return $result;
        }

        // Step 3: Validate MIME type and content
        $mimeType = $this->getSecureMimeType($file['tmp_name']);
        if (!$mimeType || !isset($this->allowedTypes[$mimeType])) {
            $result['error'] = 'File type not allowed';
            return $result;
        }

        // Step 4: Validate file extension matches content
        $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($extension, $this->allowedTypes[$mimeType])) {
            $result['error'] = 'File extension does not match content type';
            return $result;
        }

        // Step 5: Additional security checks
        if (!$this->isFileSafe($file['tmp_name'], $mimeType)) {
            $result['error'] = 'File contains potentially unsafe content';
            return $result;
        }

        // Step 6: Generate secure filename
        $safeFilename = $this->generateSecureFilename($file['name']);

        // Step 7: Move file to secure location
        $destination = $this->uploadDir . $safeFilename;

        if (move_uploaded_file($file['tmp_name'], $destination)) {
            // Set secure permissions
            chmod($destination, 0640);

            // Log successful upload
            error_log("Secure file upload: {$safeFilename} ({$mimeType}, {$file['size']} bytes)");

            $result['success'] = true;
            $result['filename'] = $safeFilename;
            $result['path'] = $destination;

            return $result;
        }

        $result['error'] = 'Failed to save file';
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

        // Method 3: mime_content_type (fallback)
        $mime = mime_content_type($filePath);
        if ($mime) return $mime;

        return null;
    }

    private function isFileSafe(string $filePath, string $mimeType): bool
    {
        $content = file_get_contents($filePath);

        // Check for null bytes (file upload attack indicator)
        if (str_contains($content, "\0")) {
            return false;
        }

        // Check for script content in non-script files
        if (!str_starts_with($mimeType, 'text/') && !str_starts_with($mimeType, 'application/')) {
            if (preg_match('/<\?php|<script|<%|javascript:/i', $content)) {
                return false;
            }
        }

        // MIME-type specific validation
        switch ($mimeType) {
            case 'image/jpeg':
            case 'image/png':
            case 'image/gif':
            case 'image/webp':
                return $this->validateImageHeaders($filePath, $mimeType);

            case 'application/pdf':
                return str_starts_with($content, '%PDF-');

            case 'text/plain':
                // Allow basic text but prevent scripts
                return !preg_match('/<\?php|<script|<%/i', $content);

            default:
                return true;
        }
    }

    private function validateImageHeaders(string $filePath, string $mimeType): bool
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

    private function generateSecureFilename(string $originalName): string
    {
        // Remove path traversal attempts
        $safeName = basename($originalName);

        // Get extension (we've already validated it matches content)
        $extension = strtolower(pathinfo($safeName, PATHINFO_EXTENSION));

        // Generate cryptographically secure random name
        $randomName = bin2hex(random_bytes(16));

        // Add timestamp for additional uniqueness
        $timestamp = time();

        return $timestamp . '_' . $randomName . '.' . $extension;
    }

    private function getUploadErrorMessage(int $errorCode): string
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

    /**
     * Serve file securely (outside web root)
     */
    public function serveSecureFile(string $filename, string $userId): void
    {
        // Validate filename format (our secure naming)
        if (!preg_match('/^\d+_[a-f0-9]+\.[a-zA-Z0-9]+$/', $filename)) {
            http_response_code(400);
            echo 'Invalid filename';
            return;
        }

        // Build secure path
        $filePath = $this->uploadDir . $filename;

        // Check file exists and is readable
        if (!file_exists($filePath) || !is_readable($filePath)) {
            http_response_code(404);
            echo 'File not found';
            return;
        }

        // Additional access control (user owns file, etc.)
        if (!$this->userCanAccessFile($filename, $userId)) {
            http_response_code(403);
            echo 'Access denied';
            return;
        }

        // Log file access
        error_log("File served securely: {$filename} to user {$userId}");

        // Serve file with appropriate headers
        $mimeType = mime_content_type($filePath);
        header('Content-Type: ' . $mimeType);
        header('Content-Length: ' . filesize($filePath));
        header('Content-Disposition: inline; filename="' . basename($filename) . '"');
        header('Cache-Control: private, max-age=3600');

        readfile($filePath);
        exit;
    }

    private function userCanAccessFile(string $filename, string $userId): bool
    {
        // Check if user owns the file (based on your access control logic)
        // This is a placeholder - implement based on your requirements

        // For example, check database if user uploaded this file
        // Or check if filename contains user ID

        return true; // Placeholder
    }
}

// =============================================================================
// 3. ADVANCED FILE UPLOAD SECURITY
// =============================================================================

class AdvancedFileSecurity
{
    private PDO $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
        $this->createSecurityTables();
    }

    private function createSecurityTables(): void
    {
        // Upload logs table
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS file_uploads (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT,
                original_name VARCHAR(255),
                stored_name VARCHAR(255),
                mime_type VARCHAR(100),
                file_size INT,
                upload_ip VARCHAR(45),
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user (user_id),
                INDEX idx_uploaded_at (uploaded_at)
            )
        ");

        // Malware scan results
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS file_scans (
                id INT PRIMARY KEY AUTO_INCREMENT,
                file_id INT,
                scan_result ENUM('clean', 'suspicious', 'malicious'),
                scan_details TEXT,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (file_id) REFERENCES file_uploads(id)
            )
        ");
    }

    /**
     * Upload with comprehensive security and logging
     */
    public function uploadWithSecurity(array $file, string $userId): array
    {
        $result = [
            'success' => false,
            'file_id' => null,
            'filename' => null,
            'error' => null
        ];

        // Rate limiting check
        if (!$this->checkUploadRateLimit($userId)) {
            $result['error'] = 'Upload rate limit exceeded';
            return $result;
        }

        // Use secure uploader
        $uploader = new SecureFileUpload();
        $uploadResult = $uploader->uploadFileSecure($file);

        if (!$uploadResult['success']) {
            $result['error'] = $uploadResult['error'];
            return $result;
        }

        // Log upload to database
        $fileId = $this->logUpload([
            'user_id' => $userId,
            'original_name' => $file['name'],
            'stored_name' => $uploadResult['filename'],
            'mime_type' => $this->getSecureMimeType($file['tmp_name']),
            'file_size' => $file['size'],
            'upload_ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ]);

        // Perform security scan
        $scanResult = $this->scanFileForMalware($uploadResult['path']);
        $this->logScanResult($fileId, $scanResult);

        if ($scanResult['result'] === 'malicious') {
            // Delete malicious file
            unlink($uploadResult['path']);
            $result['error'] = 'File contains malicious content';
            return $result;
        }

        $result['success'] = true;
        $result['file_id'] = $fileId;
        $result['filename'] = $uploadResult['filename'];

        return $result;
    }

    private function checkUploadRateLimit(string $userId): bool
    {
        $stmt = $this->pdo->prepare("
            SELECT COUNT(*) as uploads_today
            FROM file_uploads
            WHERE user_id = ? AND DATE(uploaded_at) = CURDATE()
        ");
        $stmt->execute([$userId]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        return ($result['uploads_today'] ?? 0) < 10; // Max 10 uploads per day
    }

    private function logUpload(array $data): int
    {
        $stmt = $this->pdo->prepare("
            INSERT INTO file_uploads (user_id, original_name, stored_name, mime_type, file_size, upload_ip)
            VALUES (?, ?, ?, ?, ?, ?)
        ");
        $stmt->execute([
            $data['user_id'],
            $data['original_name'],
            $data['stored_name'],
            $data['mime_type'],
            $data['file_size'],
            $data['upload_ip']
        ]);

        return $this->pdo->lastInsertId();
    }

    private function scanFileForMalware(string $filePath): array
    {
        $content = file_get_contents($filePath);

        $result = ['result' => 'clean', 'details' => []];

        // Check for common malware signatures
        $malwarePatterns = [
            '/eval\s*\(/i',
            '/base64_decode\s*\(/i',
            '/gzinflate\s*\(/i',
            '/shell_exec\s*\(/i',
            '/exec\s*\(/i',
            '/system\s*\(/i',
        ];

        foreach ($malwarePatterns as $pattern) {
            if (preg_match($pattern, $content)) {
                $result['result'] = 'malicious';
                $result['details'][] = 'Malware signature detected: ' . $pattern;
            }
        }

        // Check file entropy (potential obfuscation)
        $entropy = $this->calculateEntropy($content);
        if ($entropy > 7.8) {
            $result['result'] = 'suspicious';
            $result['details'][] = 'High entropy detected (possible obfuscation)';
        }

        return $result;
    }

    private function calculateEntropy(string $content): float
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

    private function logScanResult(int $fileId, array $scanResult): void
    {
        $stmt = $this->pdo->prepare("
            INSERT INTO file_scans (file_id, scan_result, scan_details)
            VALUES (?, ?, ?)
        ");
        $stmt->execute([
            $fileId,
            $scanResult['result'],
            json_encode($scanResult['details'])
        ]);
    }

    private function getSecureMimeType(string $filePath): ?string
    {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        if ($finfo) {
            $mime = finfo_file($finfo, $filePath);
            finfo_close($finfo);
            return $mime;
        }
        return mime_content_type($filePath);
    }
}

// =============================================================================
// 4. LARAVEL SECURE FILE UPLOAD
// =============================================================================

namespace App\Http\Controllers;

use App\Http\Requests\SecureFileUploadRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

class LaravelSecureFileUploadController extends Controller
{
    /**
     * Laravel secure file upload with comprehensive validation
     */
    public function upload(SecureFileUploadRequest $request)
    {
        try {
            $uploadedFiles = [];

            // Handle avatar upload
            if ($request->hasFile('avatar')) {
                $file = $request->file('avatar');
                $uploadedFiles['avatar'] = $this->storeSecureFile($file, 'avatars');
            }

            // Handle document upload
            if ($request->hasFile('document')) {
                $file = $request->file('document');
                $uploadedFiles['document'] = $this->storeSecureFile($file, 'documents');
            }

            return response()->json([
                'success' => true,
                'message' => 'Files uploaded successfully',
                'files' => $uploadedFiles
            ]);

        } catch (\Exception $e) {
            Log::error('File upload failed', [
                'error' => $e->getMessage(),
                'user_id' => auth()->id(),
                'files' => $request->allFiles()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Upload failed: ' . $e->getMessage()
            ], 500);
        }
    }

    /**
     * Secure file storage with Laravel
     */
    private function storeSecureFile($file, string $directory): string
    {
        // Generate secure filename
        $extension = $file->getClientOriginalExtension();
        $filename = Str::uuid() . '_' . time() . '.' . $extension;

        // Store on secure disk (configured in config/filesystems.php)
        $path = $file->storeAs($directory, $filename, 'secure');

        // Log upload
        Log::info('File uploaded securely', [
            'original_name' => $file->getClientOriginalName(),
            'stored_name' => $filename,
            'size' => $file->getSize(),
            'mime_type' => $file->getMimeType(),
            'user_id' => auth()->id()
        ]);

        return $path;
    }

    /**
     * Serve file securely through Laravel
     */
    public function download(string $filename)
    {
        // Validate filename format
        if (!preg_match('/^[a-f0-9\-_]+\.[a-zA-Z0-9]+$/', $filename)) {
            abort(400, 'Invalid filename');
        }

        // Check user permissions
        if (!$this->userCanAccessFile($filename)) {
            abort(403, 'Access denied');
        }

        // Serve file
        return Storage::disk('secure')->download("documents/{$filename}");
    }

    private function userCanAccessFile(string $filename): bool
    {
        // Implement your access control logic
        // Check if user owns the file, has permissions, etc.
        return true; // Placeholder
    }
}

// =============================================================================
// USAGE EXAMPLES
// =============================================================================

/*
// BASIC USAGE
$vulnerable = new FileUploadVulnerabilities();
// $result = $vulnerable->uploadFileVulnerable(); // DANGEROUS!

$secure = new SecureFileUpload('/var/secure/uploads/');
$result = $secure->uploadFileSecure($_FILES['file'] ?? []);

if ($result['success']) {
    echo "File uploaded securely: {$result['filename']}";
} else {
    echo "Upload failed: {$result['error']}";
}

// ADVANCED SECURITY
$pdo = new PDO("mysql:host=localhost;dbname=file_security", "user", "pass");
$advanced = new AdvancedFileSecurity($pdo);
$result = $advanced->uploadWithSecurity($_FILES['file'] ?? [], 'user123');

// LARAVEL USAGE
// In routes/web.php:
// Route::post('/upload', [LaravelSecureFileUploadController::class, 'upload']);

// In forms:
// <form action="/upload" method="POST" enctype="multipart/form-data">
//     @csrf
//     <input type="file" name="avatar" accept="image/*">
//     <input type="file" name="document" accept=".pdf,.doc,.docx">
//     <button type="submit">Upload</button>
// </form>
*/
?>
