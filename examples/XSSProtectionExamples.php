<?php

/**
 * XSS Protection Examples: Vulnerable vs Secure Output Handling
 *
 * Practical examples of XSS vulnerabilities and their secure solutions
 */

declare(strict_types=1);

// =============================================================================
// 1. REFLECTED XSS EXAMPLES
// =============================================================================

class ReflectedXSS
{
    /**
     * ❌ VULNERABLE: Direct output of user input in HTML
     * Attack: ?name=<script>alert('XSS')</script>
     */
    public function vulnerableWelcome(string $name): string
    {
        // DANGER: Direct concatenation without escaping
        return "<h1>Welcome, {$name}!</h1>";
    }

    /**
     * ✅ SECURE: Properly escaped HTML output
     */
    public function secureWelcome(string $name): string
    {
        // SAFE: htmlspecialchars escapes HTML characters
        return "<h1>Welcome, " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "!</h1>";
    }

    /**
     * ❌ VULNERABLE: XSS in HTML attributes
     * Attack: ?url=javascript:alert('XSS')
     */
    public function vulnerableLink(string $url, string $text): string
    {
        // DANGER: Direct URL in href attribute
        return "<a href='{$url}'>{$text}</a>";
    }

    /**
     * ✅ SECURE: Validated and escaped URL
     */
    public function secureLink(string $url, string $text): string
    {
        // SAFE: Validate URL and escape both URL and text
        $safeUrl = filter_var($url, FILTER_VALIDATE_URL) ?: '#';
        $safeText = htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
        $safeUrl = htmlspecialchars($safeUrl, ENT_QUOTES, 'UTF-8');

        return "<a href='{$safeUrl}'>{$safeText}</a>";
    }

    /**
     * ❌ VULNERABLE: XSS in form input values
     * Attack: ?value='><script>alert('XSS')</script>
     */
    public function vulnerableFormInput(string $value): string
    {
        // DANGER: Unescaped value in input
        return "<input type='text' name='search' value='{$value}'>";
    }

    /**
     * ✅ SECURE: Escaped form input
     */
    public function secureFormInput(string $value): string
    {
        // SAFE: Escape the value attribute
        $safeValue = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
        return "<input type='text' name='search' value='{$safeValue}'>";
    }
}

// =============================================================================
// 2. STORED XSS EXAMPLES
// =============================================================================

class StoredXSS
{
    private PDO $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
        $this->createCommentsTable();
    }

    private function createCommentsTable(): void
    {
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS comments (
                id INT PRIMARY KEY AUTO_INCREMENT,
                author VARCHAR(100) NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ");
    }

    /**
     * ❌ VULNERABLE: Store user input without sanitization
     */
    public function storeCommentVulnerable(string $author, string $content): int
    {
        // DANGER: Direct insertion without any validation or sanitization
        $stmt = $this->pdo->prepare("INSERT INTO comments (author, content) VALUES (?, ?)");
        $stmt->execute([$author, $content]);

        return $this->pdo->lastInsertId();
    }

    /**
     * ✅ SECURE: Validate and sanitize before storage
     */
    public function storeCommentSecure(string $author, string $content): int
    {
        // SAFE: Validate input length and content
        $author = trim($author);
        $content = trim($content);

        if (empty($author) || empty($content)) {
            throw new InvalidArgumentException('Author and content are required');
        }

        if (strlen($author) > 100 || strlen($content) > 1000) {
            throw new InvalidArgumentException('Input too long');
        }

        // For rich content, consider using HTML Purifier
        // For plain text, htmlspecialchars is sufficient for storage
        // We store the raw input and escape on output

        $stmt = $this->pdo->prepare("INSERT INTO comments (author, content) VALUES (?, ?)");
        $stmt->execute([$author, $content]);

        return $this->pdo->lastInsertId();
    }

    /**
     * ❌ VULNERABLE: Display stored content without escaping
     */
    public function displayCommentsVulnerable(): string
    {
        $stmt = $this->pdo->query("SELECT author, content, created_at FROM comments ORDER BY created_at DESC");
        $comments = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $html = '<div class="comments">';
        foreach ($comments as $comment) {
            // DANGER: Direct output without escaping
            $html .= "<div class='comment'>
                <h4>{$comment['author']}</h4>
                <p>{$comment['content']}</p>
                <small>{$comment['created_at']}</small>
            </div>";
        }
        $html .= '</div>';

        return $html;
    }

    /**
     * ✅ SECURE: Display with proper escaping
     */
    public function displayCommentsSecure(): string
    {
        $stmt = $this->pdo->query("SELECT author, content, created_at FROM comments ORDER BY created_at DESC");
        $comments = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $html = '<div class="comments">';
        foreach ($comments as $comment) {
            // SAFE: Escape all user-controlled output
            $safeAuthor = htmlspecialchars($comment['author'], ENT_QUOTES, 'UTF-8');
            $safeContent = htmlspecialchars($comment['content'], ENT_QUOTES, 'UTF-8');
            $safeDate = htmlspecialchars($comment['created_at'], ENT_QUOTES, 'UTF-8');

            $html .= "<div class='comment'>
                <h4>{$safeAuthor}</h4>
                <p>{$safeContent}</p>
                <small>{$safeDate}</small>
            </div>";
        }
        $html .= '</div>';

        return $html;
    }

    /**
     * ✅ SECURE: Allow limited HTML with proper sanitization
     */
    public function displayCommentsWithHtml(): string
    {
        // For rich content, use a proper HTML sanitizer
        // This example shows a simple approach - in production, use HTML Purifier

        $stmt = $this->pdo->query("SELECT author, content, created_at FROM comments ORDER BY created_at DESC");
        $comments = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $html = '<div class="comments">';
        foreach ($comments as $comment) {
            $safeAuthor = htmlspecialchars($comment['author'], ENT_QUOTES, 'UTF-8');

            // Allow only safe tags for rich content
            $allowedTags = '<p><br><strong><em><u>';
            $safeContent = strip_tags($comment['content'], $allowedTags);

            // Additional validation - remove dangerous attributes
            $safeContent = preg_replace('/<[^>]*\bon\w+=/i', '<', $safeContent);

            $safeDate = htmlspecialchars($comment['created_at'], ENT_QUOTES, 'UTF-8');

            $html .= "<div class='comment'>
                <h4>{$safeAuthor}</h4>
                <div class='content'>{$safeContent}</div>
                <small>{$safeDate}</small>
            </div>";
        }
        $html .= '</div>';

        return $html;
    }
}

// =============================================================================
// 3. DOM-BASED XSS EXAMPLES
// =============================================================================

class DOMBasedXSS
{
    /**
     * ❌ VULNERABLE: DOM manipulation with user input
     * Attack: #<img src=x onerror=alert('XSS')>
     */
    public function vulnerableDOMDisplay(): string
    {
        // This would be client-side JavaScript - shown here for illustration
        return "
        <script>
            // VULNERABLE: Direct use of location.hash
            var userInput = location.hash.substring(1);
            document.getElementById('content').innerHTML = 'Welcome, ' + userInput;
        </script>
        <div id='content'></div>
        ";
    }

    /**
     * ✅ SECURE: Sanitize input before DOM manipulation
     */
    public function secureDOMDisplay(): string
    {
        return "
        <script>
            // SECURE: Sanitize hash parameter
            function sanitizeInput(input) {
                // Remove script tags and event handlers
                input = input.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
                input = input.replace(/on\w+\s*=/gi, '');
                return input;
            }

            var hash = location.hash.substring(1);
            var safeInput = sanitizeInput(decodeURIComponent(hash));
            document.getElementById('content').innerHTML = 'Welcome, ' + safeInput;
        </script>
        <div id='content'></div>
        ";
    }

    /**
     * ✅ SECURE: Use textContent instead of innerHTML
     */
    public function secureTextContent(): string
    {
        return "
        <script>
            // SECURE: Use textContent for text-only content
            var userInput = location.hash.substring(1);
            var safeInput = decodeURIComponent(userInput).replace(/[<>'\"]/g, '');
            document.getElementById('content').textContent = 'Welcome, ' + safeInput;
        </script>
        <div id='content'></div>
        ";
    }
}

// =============================================================================
// 4. CONTEXT-SPECIFIC ESCAPING EXAMPLES
// =============================================================================

class ContextEscaping
{
    /**
     * HTML Context Escaping
     */
    public function escapeForHtml(string $content): string
    {
        return htmlspecialchars($content, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    /**
     * HTML Attribute Context
     */
    public function escapeForAttribute(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
    }

    /**
     * JavaScript Context
     */
    public function escapeForJavaScript($data): string
    {
        // Use JSON encoding for JavaScript context
        return json_encode($data, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
    }

    /**
     * CSS Context
     */
    public function escapeForCss(string $value): string
    {
        // Remove dangerous characters from CSS
        return preg_replace('/[^\w\s#-]/', '', $value);
    }

    /**
     * URL Context
     */
    public function escapeForUrl(string $url): string
    {
        // Validate URL first, then encode
        $validated = filter_var($url, FILTER_VALIDATE_URL);
        return $validated ? htmlspecialchars($validated, ENT_QUOTES, 'UTF-8') : '#';
    }

    /**
     * Generate secure HTML with proper escaping
     */
    public function generateSecureUserProfile(array $user): string
    {
        $name = $this->escapeForHtml($user['name']);
        $email = $this->escapeForHtml($user['email']);
        $bio = $this->escapeForHtml($user['bio']);
        $website = $this->escapeForUrl($user['website']);
        $themeColor = $this->escapeForCss($user['theme_color']);

        return "
        <div class='user-profile' style='border-color: {$themeColor}'>
            <h2>{$name}</h2>
            <p class='email'>{$email}</p>
            <p class='bio'>{$bio}</p>
            <a href='{$website}' class='website'>Visit Website</a>
        </div>
        ";
    }

    /**
     * Generate secure JavaScript data
     */
    public function generateSecureJavaScriptData(array $userData): string
    {
        $safeData = $this->escapeForJavaScript($userData);

        return "
        <script>
            var userData = {$safeData};
            console.log('User name:', userData.name);
            console.log('User ID:', userData.id);
        </script>
        ";
    }
}

// =============================================================================
// 5. LARAVEL XSS PROTECTION EXAMPLES
// =============================================================================

namespace App\View\Components;

use Illuminate\View\Component;

class SecureUserCard extends Component
{
    public $user;

    public function __construct($user)
    {
        $this->user = $user;
    }

    public function render()
    {
        // Laravel Blade automatically escapes output
        return <<<'blade'
        <div class="user-card">
            {{-- Automatic escaping with {{ }} --}}
            <h3>{{ $user['name'] }}</h3>
            <p>{{ $user['bio'] }}</p>

            {{-- Explicit unescaping (only for trusted content) --}}
            <div class="trusted-content">{!! $user['trusted_html'] !!}</div>

            {{-- JavaScript context --}}
            <script>
                var userData = {!! json_encode($user) !!};
                console.log('User:', userData.name);
            </script>
        </div>
        blade;
    }
}

// Laravel Controller with XSS protection
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class CommentController extends Controller
{
    /**
     * Store comment with XSS protection
     */
    public function store(Request $request)
    {
        $validated = $request->validate([
            'author' => 'required|string|max:100',
            'content' => 'required|string|max:1000',
        ]);

        // Laravel automatically protects against mass assignment
        // Input is automatically sanitized
        DB::table('comments')->insert([
            'author' => $validated['author'],
            'content' => $validated['content'], // Stored as-is, escaped on display
            'created_at' => now(),
        ]);

        return redirect()->back()->with('success', 'Comment added');
    }

    /**
     * Display comments with XSS protection
     */
    public function index()
    {
        $comments = DB::table('comments')->orderBy('created_at', 'desc')->get();

        return view('comments.index', compact('comments'));
    }
}

// =============================================================================
// 6. ADVANCED XSS PROTECTION TECHNIQUES
// =============================================================================

class AdvancedXSSProtection
{
    /**
     * Content Security Policy headers
     */
    public static function addCSPHeaders(): void
    {
        $csp = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' https://trusted-cdn.com",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "img-src 'self' data: https:",
            "font-src 'self' https://fonts.gstatic.com",
            "connect-src 'self'",
            "media-src 'none'",
            "object-src 'none'",
            "child-src 'self'",
            "frame-ancestors 'none'",
            "form-action 'self'",
            "upgrade-insecure-requests"
        ];

        header('Content-Security-Policy: ' . implode('; ', $csp));
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('X-XSS-Protection: 1; mode=block');
    }

    /**
     * Generate nonce for inline scripts
     */
    public static function generateScriptNonce(): string
    {
        $nonce = bin2hex(random_bytes(16));

        // Set CSP with nonce
        header("Content-Security-Policy: script-src 'self' 'nonce-{$nonce}'");

        return $nonce;
    }

    /**
     * Secure HTML generation with nonces
     */
    public function generateSecurePageWithNonce(string $userContent): string
    {
        $nonce = self::generateScriptNonce();

        return "
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secure Page</title>
        </head>
        <body>
            <div id='content'>
                " . htmlspecialchars($userContent, ENT_QUOTES, 'UTF-8') . "
            </div>

            <script nonce='{$nonce}'>
                // This inline script is allowed by CSP
                console.log('Page loaded securely');
                document.getElementById('content').style.color = 'green';
            </script>
        </body>
        </html>
        ";
    }

    /**
     * Input sanitization with HTML Purifier (concept)
     */
    public function sanitizeHtmlContent(string $html): string
    {
        // In production, use: composer require ezyang/htmlpurifier

        // Basic sanitization (not as comprehensive as HTML Purifier)
        $allowedTags = '<p><br><strong><em><u><h1><h2><h3><ul><ol><li><a>';
        $sanitized = strip_tags($html, $allowedTags);

        // Remove dangerous attributes
        $sanitized = preg_replace('/<[^>]*\b(on\w+|style|javascript:)/i', '<', $sanitized);

        return $sanitized;
    }

    /**
     * Template engine with automatic escaping
     */
    public function renderTemplate(string $template, array $data): string
    {
        // Simple template engine with automatic escaping
        foreach ($data as $key => $value) {
            if (is_string($value)) {
                // Auto-escape string values
                $data[$key] = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
            }
        }

        // Replace {{variable}} with escaped values
        $output = $template;
        foreach ($data as $key => $value) {
            if (is_string($value)) {
                $output = str_replace("{{{$key}}}", $value, $output);
            }
        }

        return $output;
    }
}

// =============================================================================
// 7. TESTING XSS PROTECTION
// =============================================================================

class XSSProtectionTester
{
    private array $xssPayloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        'javascript:alert("XSS")',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<div onmouseover=alert("XSS")>Hover me</div>',
        '\'><script>alert("XSS")</script>',
        '<script>alert(String.fromCharCode(88,83,83))</script>',
        '<img src="jav&#x09;ascript:alert(\'XSS\');">',
        '<meta http-equiv="refresh" content="0; url=javascript:alert(\'XSS\');">',
    ];

    /**
     * Test HTML escaping
     */
    public function testHtmlEscaping(): array
    {
        $results = [];

        foreach ($this->xssPayloads as $payload) {
            $escaped = htmlspecialchars($payload, ENT_QUOTES, 'UTF-8');

            // Check that dangerous tags are escaped
            $isSafe = !preg_match('/<script|<img|<iframe|<svg/i', $escaped) ||
                      strpos($escaped, '&lt;') !== false;

            $results[] = [
                'payload' => $payload,
                'escaped' => $escaped,
                'safe' => $isSafe
            ];
        }

        return $results;
    }

    /**
     * Test JavaScript escaping
     */
    public function testJavaScriptEscaping(): array
    {
        $results = [];

        foreach ($this->xssPayloads as $payload) {
            $jsonEncoded = json_encode($payload, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);

            // JSON encoding should make payloads safe for JavaScript context
            $isSafe = strpos($jsonEncoded, '<script>') === false;

            $results[] = [
                'payload' => $payload,
                'json_encoded' => $jsonEncoded,
                'safe' => $isSafe
            ];
        }

        return $results;
    }

    /**
     * Test URL validation
     */
    public function testUrlValidation(): array
    {
        $testUrls = [
            'javascript:alert("XSS")',
            'data:text/html,<script>alert("XSS")</script>',
            'http://example.com',
            'https://trusted.com/path',
            'ftp://invalid.com',
        ];

        $results = [];

        foreach ($testUrls as $url) {
            $validated = filter_var($url, FILTER_VALIDATE_URL);
            $isValidUrl = $validated !== false;

            // Check for dangerous schemes
            $isDangerous = preg_match('/^(javascript|data|vbscript):/i', $url);

            $results[] = [
                'url' => $url,
                'valid_filter' => $isValidUrl,
                'dangerous_scheme' => $isDangerous,
                'safe' => $isValidUrl && !$isDangerous
            ];
        }

        return $results;
    }

    /**
     * Test comprehensive XSS protection
     */
    public function runFullTestSuite(): array
    {
        return [
            'html_escaping' => $this->testHtmlEscaping(),
            'javascript_escaping' => $this->testJavaScriptEscaping(),
            'url_validation' => $this->testUrlValidation(),
        ];
    }
}

// =============================================================================
// USAGE EXAMPLES AND DEMONSTRATIONS
// =============================================================================

/*
// SETUP
$pdo = new PDO("mysql:host=localhost;dbname=xss_test", "user", "pass", [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
]);

// ADD SECURITY HEADERS
AdvancedXSSProtection::addCSPHeaders();

// TEST XSS PROTECTION
$tester = new XSSProtectionTester();
$testResults = $tester->runFullTestSuite();
print_r($testResults);

// REFLECTED XSS EXAMPLES
$reflectedXSS = new ReflectedXSS();

// VULNERABLE (don't use in production!)
// echo $reflectedXSS->vulnerableWelcome($_GET['name']);

// SECURE
echo $reflectedXSS->secureWelcome($_GET['name'] ?? 'Guest');

// STORED XSS EXAMPLES
$storedXSS = new StoredXSS($pdo);

// Store comment securely
$storedXSS->storeCommentSecure('John Doe', 'This is a safe comment.');

// Display comments securely
echo $storedXSS->displayCommentsSecure();

// CONTEXT ESCAPING
$escaper = new ContextEscaping();
$user = [
    'name' => '<script>alert("XSS")</script>',
    'email' => 'user@example.com',
    'bio' => 'I am a <strong>developer</strong>',
    'website' => 'javascript:alert("XSS")',
    'theme_color' => 'red; background: url(javascript:alert("XSS"))'
];

echo $escaper->generateSecureUserProfile($user);
echo $escaper->generateSecureJavaScriptData($user);
*/
?>
