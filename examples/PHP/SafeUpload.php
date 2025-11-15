<?php

/**
 * Secure File Upload Implementation Example
 *
 * This example demonstrates secure file upload practices in PHP
 */

class SafeUpload
{
    private $allowedTypes = [
        'image/jpeg' => ['jpg', 'jpeg'],
        'image/png' => ['png'],
        'image/gif' => ['gif'],
        'image/webp' => ['webp'],
        'application/pdf' => ['pdf'],
        'text/plain' => ['txt'],
    ];

    private $maxFileSize = 5242880; // 5MB
    private $uploadDir;

    public function __construct(string $uploadDir = 'uploads/')
    {
        $this->uploadDir = rtrim($uploadDir, '/') . '/';

        // Create upload directory if it doesn't exist
        if (!is_dir($this->uploadDir)) {
            mkdir($this->uploadDir, 0755, true);
        }

        // Ensure upload directory is outside web root and secure
        if (is_writable($this->uploadDir) === false) {
            throw new Exception("Upload directory is not writable");
        }
    }

    /**
     * Process and validate file upload
     */
    public function processUpload(array $file): array
    {
        $result = [
            'success' => false,
            'filename' => null,
            'error' => null
        ];

        // Check if file was uploaded
        if (!isset($file['error']) || is_array($file['error'])) {
            $result['error'] = 'Invalid file upload';
            return $result;
        }

        // Check upload errors
        switch ($file['error']) {
            case UPLOAD_ERR_OK:
                break;
            case UPLOAD_ERR_NO_FILE:
                $result['error'] = 'No file sent';
                return $result;
            case UPLOAD_ERR_INI_SIZE:
            case UPLOAD_ERR_FORM_SIZE:
                $result['error'] = 'File too large';
                return $result;
            default:
                $result['error'] = 'Unknown upload error';
                return $result;
        }

        // Validate file size
        if ($file['size'] > $this->maxFileSize) {
            $result['error'] = 'File too large (max 5MB)';
            return $result;
        }

        // Get file information
        $fileInfo = $this->getFileInfo($file['tmp_name']);

        if (!$fileInfo) {
            $result['error'] = 'Invalid file';
            return $result;
        }

        // Validate MIME type
        if (!array_key_exists($fileInfo['mime'], $this->allowedTypes)) {
            $result['error'] = 'File type not allowed';
            return $result;
        }

        // Validate file extension matches MIME type
        $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($extension, $this->allowedTypes[$fileInfo['mime']])) {
            $result['error'] = 'File extension does not match content type';
            return $result;
        }

        // Additional security checks
        if (!$this->isSafeFile($file['tmp_name'], $fileInfo['mime'])) {
            $result['error'] = 'Potentially unsafe file detected';
            return $result;
        }

        // Generate secure filename
        $secureFilename = $this->generateSecureFilename($file['name']);
        $destination = $this->uploadDir . $secureFilename;

        // Move uploaded file
        if (move_uploaded_file($file['tmp_name'], $destination)) {
            // Set secure permissions
            chmod($destination, 0644);

            $result['success'] = true;
            $result['filename'] = $secureFilename;

            // Log successful upload
            error_log("File uploaded: {$secureFilename} by user: " . ($_SESSION['user_id'] ?? 'unknown'));

        } else {
            $result['error'] = 'Failed to save file';
        }

        return $result;
    }

    /**
     * Get file information using multiple methods for security
     */
    private function getFileInfo(string $filePath): ?array
    {
        // Method 1: finfo (most reliable)
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        if ($finfo) {
            $mime = finfo_file($finfo, $filePath);
            finfo_close($finfo);

            if ($mime) {
                return ['mime' => $mime];
            }
        }

        // Method 2: getimagesize (for images only)
        $imageInfo = getimagesize($filePath);
        if ($imageInfo && isset($imageInfo['mime'])) {
            return ['mime' => $imageInfo['mime']];
        }

        // Method 3: mime_content_type (fallback)
        $mime = mime_content_type($filePath);
        if ($mime) {
            return ['mime' => $mime];
        }

        return null;
    }

    /**
     * Additional security checks for uploaded files
     */
    private function isSafeFile(string $filePath, string $mimeType): bool
    {
        // Check file header for known signatures
        $handle = fopen($filePath, 'rb');
        if (!$handle) {
            return false;
        }

        $header = fread($handle, 12);
        fclose($handle);

        // JPEG signature
        if ($mimeType === 'image/jpeg' && substr($header, 0, 2) !== "\xFF\xD8") {
            return false;
        }

        // PNG signature
        if ($mimeType === 'image/png' && substr($header, 0, 8) !== "\x89PNG\r\n\x1A\n") {
            return false;
        }

        // GIF signature
        if ($mimeType === 'image/gif' &&
            substr($header, 0, 6) !== 'GIF87a' &&
            substr($header, 0, 6) !== 'GIF89a') {
            return false;
        }

        // Check for embedded PHP or other executable content
        $content = file_get_contents($filePath);
        if (stripos($content, '<?php') !== false ||
            stripos($content, '<script') !== false ||
            stripos($content, '<%') !== false) {
            return false;
        }

        return true;
    }

    /**
     * Generate secure filename to prevent path traversal
     */
    private function generateSecureFilename(string $originalName): string
    {
        // Get file extension
        $extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

        // Generate random filename
        $randomName = bin2hex(random_bytes(16));

        // Add timestamp for additional uniqueness
        $timestamp = time();

        return $timestamp . '_' . $randomName . '.' . $extension;
    }

    /**
     * Delete uploaded file
     */
    public function deleteFile(string $filename): bool
    {
        $filePath = $this->uploadDir . $filename;

        // Security check: ensure file is within upload directory
        $realPath = realpath($filePath);
        $realUploadDir = realpath($this->uploadDir);

        if ($realPath === false || strpos($realPath, $realUploadDir) !== 0) {
            return false;
        }

        return unlink($filePath);
    }
}

// Usage example:
/*
$upload = new SafeUpload('secure_uploads/');

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $result = $upload->processUpload($_FILES['file']);

    if ($result['success']) {
        echo "File uploaded successfully: " . htmlspecialchars($result['filename']);
    } else {
        echo "Upload failed: " . htmlspecialchars($result['error']);
    }
}
*/
?>
