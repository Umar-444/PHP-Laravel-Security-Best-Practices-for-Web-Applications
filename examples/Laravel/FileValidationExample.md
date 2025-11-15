# Laravel File Validation Example

This document demonstrates secure file upload validation in Laravel applications.

## File Upload Validation Rules

### Basic File Validation

```php
// In your controller
public function uploadFile(Request $request)
{
    $request->validate([
        'file' => 'required|file|max:5120|mimes:jpeg,png,pdf,docx', // 5MB max
    ]);

    // Process the uploaded file
    $file = $request->file('file');
    $path = $file->store('uploads', 'public');

    return response()->json(['path' => $path]);
}
```

### Advanced File Validation with Custom Rules

```php
<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Contracts\Validation\Validator;
use Illuminate\Http\Exceptions\HttpResponseException;

class SecureFileUploadRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true; // Adjust based on your authorization logic
    }

    public function rules(): array
    {
        return [
            'document' => [
                'required',
                'file',
                'max:10240', // 10MB
                'mimes:pdf,doc,docx,txt',
                function ($attribute, $value, $fail) {
                    if (!$this->isValidFileContent($value)) {
                        $fail('The uploaded file contains potentially unsafe content.');
                    }
                },
            ],
            'image' => [
                'nullable',
                'image',
                'max:2048', // 2MB
                'dimensions:min_width=100,min_height=100,max_width=2000,max_height=2000',
                'mimes:jpeg,png,jpg,gif,webp',
            ],
        ];
    }

    public function messages(): array
    {
        return [
            'document.max' => 'Document file size must not exceed 10MB.',
            'document.mimes' => 'Document must be a PDF, DOC, DOCX, or TXT file.',
            'image.max' => 'Image file size must not exceed 2MB.',
            'image.dimensions' => 'Image dimensions must be between 100x100 and 2000x2000 pixels.',
            'image.mimes' => 'Image must be a JPEG, PNG, JPG, GIF, or WebP file.',
        ];
    }

    /**
     * Validate file content for security
     */
    private function isValidFileContent($file): bool
    {
        if (!$file instanceof \Illuminate\Http\UploadedFile) {
            return false;
        }

        // Check file header signatures
        $handle = fopen($file->getRealPath(), 'rb');
        if (!$handle) {
            return false;
        }

        $header = fread($handle, 12);
        fclose($handle);

        $mimeType = $file->getMimeType();

        // Validate based on MIME type
        switch ($mimeType) {
            case 'application/pdf':
                return substr($header, 0, 4) === '%PDF';

            case 'application/msword':
            case 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
                // DOC/DOCX validation would be more complex
                return true; // Basic check - you might want more validation

            case 'text/plain':
                // Check for potentially dangerous content
                $content = file_get_contents($file->getRealPath());
                return !preg_match('/<\?php|<script|<%|<%/i', $content);

            default:
                return true;
        }
    }

    protected function failedValidation(Validator $validator)
    {
        throw new HttpResponseException(response()->json([
            'success' => false,
            'message' => 'Validation failed',
            'errors' => $validator->errors()
        ], 422));
    }
}
```

### Secure File Storage

```php
<?php

namespace App\Services;

use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;

class SecureFileUploadService
{
    /**
     * Store file securely with generated filename
     */
    public function storeSecurely(UploadedFile $file, string $directory = 'uploads'): string
    {
        // Generate secure filename
        $originalName = $file->getClientOriginalName();
        $extension = $file->getClientOriginalExtension();
        $filename = Str::uuid() . '_' . time() . '.' . $extension;

        // Store file
        $path = $file->storeAs($directory, $filename, 'private');

        // Set secure permissions (if using local storage)
        if (config('filesystems.default') === 'local') {
            $fullPath = storage_path('app/private/' . $path);
            chmod($fullPath, 0640);
        }

        // Log upload for security auditing
        \Log::info('File uploaded', [
            'original_name' => $originalName,
            'stored_name' => $filename,
            'size' => $file->getSize(),
            'mime_type' => $file->getMimeType(),
            'user_id' => auth()->id(),
            'ip_address' => request()->ip(),
        ]);

        return $path;
    }

    /**
     * Validate and sanitize filename
     */
    public function sanitizeFilename(string $filename): string
    {
        // Remove path traversal attempts
        $filename = basename($filename);

        // Remove potentially dangerous characters
        $filename = preg_replace('/[^a-zA-Z0-9\.\-\_]/', '', $filename);

        // Ensure it has an extension
        if (!pathinfo($filename, PATHINFO_EXTENSION)) {
            $filename .= '.bin';
        }

        return $filename;
    }

    /**
     * Check if file is potentially dangerous
     */
    public function isDangerousFile(UploadedFile $file): bool
    {
        $dangerousExtensions = [
            'php', 'php3', 'php4', 'php5', 'phtml', 'pl', 'py', 'jsp', 'asp', 'exe',
            'com', 'bat', 'cmd', 'scr', 'pif', 'vbs', 'js', 'jar', 'war', 'ear'
        ];

        $extension = strtolower($file->getClientOriginalExtension());

        if (in_array($extension, $dangerousExtensions)) {
            return true;
        }

        // Check file content for embedded scripts
        $content = file_get_contents($file->getRealPath());
        if (preg_match('/<\?php|<script|<%/i', $content)) {
            return true;
        }

        return false;
    }
}
```

### Controller Implementation

```php
<?php

namespace App\Http\Controllers;

use App\Http\Requests\SecureFileUploadRequest;
use App\Services\SecureFileUploadService;
use Illuminate\Http\JsonResponse;

class FileUploadController extends Controller
{
    private $fileUploadService;

    public function __construct(SecureFileUploadService $fileUploadService)
    {
        $this->fileUploadService = $fileUploadService;
    }

    public function upload(SecureFileUploadRequest $request): JsonResponse
    {
        try {
            $file = $request->file('document');
            $image = $request->file('image');

            $uploadedFiles = [];

            // Upload document
            if ($file) {
                $path = $this->fileUploadService->storeSecurely($file, 'documents');
                $uploadedFiles['document'] = $path;
            }

            // Upload image
            if ($image) {
                $path = $this->fileUploadService->storeSecurely($image, 'images');
                $uploadedFiles['image'] = $path;
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
}
```

### Additional Security Measures

1. **File Type Validation**: Use both MIME type and file extension validation
2. **Content Scanning**: Check file headers and content for malicious code
3. **Size Limits**: Implement reasonable file size limits
4. **Storage Security**: Store files outside web root with restricted permissions
5. **Access Control**: Implement proper authorization for file downloads
6. **Logging**: Log all file operations for security auditing
7. **Cleanup**: Implement automatic cleanup of temporary files
8. **Rate Limiting**: Limit upload frequency per user

### Configuration Example

```php
// config/filesystems.php
'disks' => [
    'private' => [
        'driver' => 'local',
        'root' => storage_path('app/private'),
        'permissions' => [
            'file' => [
                'public' => 0640,
                'private' => 0600,
            ],
            'dir' => [
                'public' => 0750,
                'private' => 0700,
            ],
        ],
    ],
],
```

This example provides a comprehensive approach to secure file uploads in Laravel applications.
