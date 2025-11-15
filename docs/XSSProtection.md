# XSS Protection

## What is XSS?

Cross-Site Scripting (XSS) is a client-side code injection attack where an attacker executes malicious scripts in a victim's browser. XSS allows attackers to:

- **Steal cookies and session tokens**
- **Deface websites**
- **Redirect users to malicious sites**
- **Perform actions on behalf of users**
- **Capture keystrokes and form data**
- **Spread malware and exploits**

### XSS Attack Impact

- **Session hijacking** through cookie theft
- **Identity theft** via credential harvesting
- **Data breach** through keylogging
- **Website defacement** and reputation damage
- **Malware distribution** to site visitors

## Types of XSS Attacks

### 1. Reflected XSS (Non-Persistent)
Attack script is reflected back to the user in the response from the server.

#### How it works:
1. Attacker crafts malicious URL with script
2. Victim clicks link or visits page
3. Server reflects script in response
4. Victim's browser executes malicious script

#### Example:
```php
// VULNERABLE: Direct output of user input
$name = $_GET['name'];
echo "<h1>Welcome, {$name}!</h1>";

// Attack URL: ?name=<script>alert('XSS')</script>
// Result: Script executes in victim's browser
```

### 2. Stored XSS (Persistent)
Attack script is permanently stored on the target server.

#### How it works:
1. Attacker submits malicious script to server
2. Server stores script in database
3. Victim views page with stored script
4. Script executes in victim's browser
5. Affects all users viewing the content

#### Example:
```php
// VULNERABLE: Storing user input without sanitization
$message = $_POST['message'];
$sql = "INSERT INTO comments (message) VALUES ('{$message}')";

// Later, displaying without escaping
$comments = $pdo->query("SELECT message FROM comments");
foreach ($comments as $comment) {
    echo "<div>{$comment['message']}</div>";
}
```

### 3. DOM-based XSS
Attack occurs in the Document Object Model, not in server response.

#### How it works:
1. Client-side JavaScript processes user input
2. Malicious script modifies DOM
3. Browser executes injected script

#### Example:
```javascript
// VULNERABLE: Direct DOM manipulation
var name = location.hash.substring(1); // Gets # parameter
document.getElementById('welcome').innerHTML = 'Welcome ' + name;

// Attack URL: #<script>alert('XSS')</script>
```

## XSS Prevention Fundamentals

### Output Escaping

**Always escape output based on context**. Different contexts require different escaping:

#### HTML Context
```php
// INCORRECT
echo "<div>{$userInput}</div>";

// CORRECT
echo "<div>" . htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8') . "</div>";
```

#### HTML Attribute Context
```php
// INCORRECT
echo "<input value='{$userInput}'>";

// CORRECT
echo "<input value='" . htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8') . "'>";
```

#### JavaScript Context
```php
// INCORRECT
echo "<script>var data = '{$userInput}';</script>";

// CORRECT
echo "<script>var data = " . json_encode($userInput) . ";</script>";
```

#### URL Context
```php
// INCORRECT
echo "<a href='{$userInput}'>Link</a>";

// CORRECT
echo "<a href='" . htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8') . "'>Link</a>";
// Even better: validate as URL first
$url = filter_var($userInput, FILTER_VALIDATE_URL) ? $userInput : '#';
echo "<a href='" . htmlspecialchars($url, ENT_QUOTES, 'UTF-8') . "'>Link</a>";
```

## PHP Output Escaping Functions

### htmlspecialchars()

The primary function for escaping HTML content:

```php
<?php
string htmlspecialchars(
    string $string,
    int $flags = ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401,
    string $encoding = 'UTF-8',
    bool $double_encode = true
): string
```

#### Parameters:
- **$string**: The string to escape
- **$flags**: Which characters to escape (ENT_QUOTES, ENT_NOQUOTES, etc.)
- **$encoding**: Character encoding (UTF-8 recommended)
- **$double_encode**: Whether to encode existing entities

#### Usage Examples:
```php
$name = '<script>alert("XSS")</script>';

// Basic escaping
echo htmlspecialchars($name);
// Output: &lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;

// With ENT_QUOTES (recommended)
echo htmlspecialchars($name, ENT_QUOTES);
// Output: &lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;

// In attribute context
echo '<input value="' . htmlspecialchars($name, ENT_QUOTES) . '">';
// Output: <input value="&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;">
```

### htmlentities()

Similar to htmlspecialchars but converts all applicable characters to HTML entities:

```php
$content = " café & résumé ";
echo htmlentities($content, ENT_QUOTES, 'UTF-8');
// Output: &nbsp;caf&eacute;&nbsp;&amp;&nbsp;r&eacute;sum&eacute;&nbsp;
```

### Context-Specific Escaping

#### CSS Context
```php
function escapeCss($value) {
    // Remove or encode dangerous characters
    return preg_replace('/[^\w\s#-]/', '', $value);
}

// Usage
$color = "red; background: url(javascript:alert('XSS'))";
echo "<div style='color: " . escapeCss($color) . "'>";
```

#### URL Context
```php
function escapeUrl($url) {
    // Use urlencode for URL parameters
    return urlencode($url);
}

// Better: validate and then escape
function safeUrl($url) {
    $validated = filter_var($url, FILTER_VALIDATE_URL);
    return $validated ? htmlspecialchars($validated, ENT_QUOTES, 'UTF-8') : '';
}
```

## Content Security Policy (CSP)

CSP is a security standard that helps prevent XSS by controlling which resources can be loaded and executed.

### Basic CSP Header
```php
// PHP header
header("Content-Security-Policy: default-src 'self'");

// HTML meta tag
<meta http-equiv="Content-Security-Policy" content="default-src 'self'">
```

### Comprehensive CSP
```php
header("Content-Security-Policy: "
    . "default-src 'self'; "
    . "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
    . "style-src 'self' 'unsafe-inline'; "
    . "img-src 'self' data: https:; "
    . "font-src 'self' data:; "
    . "connect-src 'self'; "
    . "media-src 'none'; "
    . "object-src 'none'; "
    . "child-src 'self'; "
    . "frame-ancestors 'none'; "
    . "form-action 'self'; "
    . "upgrade-insecure-requests"
);
```

### CSP Nonces for Inline Scripts
```php
// Generate nonce
$nonce = bin2hex(random_bytes(16));

// Set CSP header
header("Content-Security-Policy: script-src 'self' 'nonce-{$nonce}'");

// Use nonce in script
echo "<script nonce='{$nonce}'>console.log('Safe inline script');</script>";
```

## Input Validation and Sanitization

### Input Validation (Defense in Depth)

```php
// Validate input format before output
function validateAndDisplayName($name) {
    // Validate format (allow-list approach)
    if (!preg_match('/^[a-zA-Z\s\-\.\']{1,100}$/', $name)) {
        return 'Invalid name format';
    }

    // Even with validation, still escape output
    return htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
}
```

### Input Sanitization

```php
function sanitizeHtml($input) {
    // Remove potentially dangerous tags
    $allowedTags = '<p><br><strong><em><u>';
    return strip_tags($input, $allowedTags);
}

function sanitizeForDisplay($input) {
    // Multi-step sanitization
    $input = trim($input);                           // Remove whitespace
    $input = htmlspecialchars($input, ENT_QUOTES);   // Escape HTML
    $input = filter_var($input, FILTER_SANITIZE_STRING); // Additional sanitization

    return $input;
}
```

## Laravel XSS Protection

### Blade Templating Engine

Laravel's Blade engine automatically escapes output:

```blade
{{-- Automatic escaping --}}
<h1>Welcome, {{ $name }}</h1>

{{-- Explicit unescaping (use only for trusted content) --}}
<h1>Welcome, {!! $trustedHtml !!}</h1>
```

### Blade Escaping Functions

```blade
{{-- HTML escaping --}}
{{ $userInput }} {{-- Automatically escaped --}}

{{-- JavaScript escaping --}}
<script>
    var userData = {!! json_encode($userData) !!};
</script>

{{-- Attribute escaping --}}
<input value="{{ $value }}">

{{-- Raw output (dangerous - only for trusted content) --}}
{!! $htmlContent !!}
```

### Laravel Form Helpers

```php
// Form input with automatic escaping
Form::text('name', $value);

// Raw form input (requires manual escaping)
Form::macro('rawText', function($name, $value) {
    return '<input type="text" name="' . e($name) . '" value="' . e($value) . '">';
});
```

### Laravel Security Middleware

```php
<?php
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class XSSProtectionMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);

        // Add XSS protection headers
        $response->headers->set('X-XSS-Protection', '1; mode=block');
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        // Add CSP header
        $response->headers->set('Content-Security-Policy',
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'");

        return $response;
    }
}
```

## Advanced XSS Prevention Techniques

### 1. Template Engines

Using dedicated template engines prevents XSS:

```php
// Twig (PHP template engine)
$loader = new Twig_Loader_Filesystem('templates/');
$twig = new Twig_Environment($loader, [
    'autoescape' => 'html'  // Automatic escaping
]);

echo $twig->render('page.html', ['name' => $userInput]);
```

### 2. HTML Purifier

Comprehensive HTML sanitization library:

```php
require_once 'vendor/ezyang/htmlpurifier/library/HTMLPurifier.auto.php';

$config = HTMLPurifier_Config::createDefault();
$purifier = new HTMLPurifier($config);

// Clean HTML input
$cleanHtml = $purifier->purify($userInput);
echo $cleanHtml; // Safe to display
```

### 3. Input Encoding Validation

Ensure input encoding is valid:

```php
function validateAndNormalizeInput($input) {
    // Check for valid UTF-8
    if (!mb_check_encoding($input, 'UTF-8')) {
        throw new Exception('Invalid character encoding');
    }

    // Normalize Unicode (prevent homograph attacks)
    $input = normalizer_normalize($input, Normalizer::FORM_C);

    // Remove control characters
    $input = preg_replace('/\p{Cc}/u', '', $input);

    return $input;
}
```

## XSS in Different Contexts

### 1. JSON Responses

```php
// VULNERABLE: Direct JSON output
header('Content-Type: application/json');
echo json_encode(['message' => $_GET['msg']]);

// SECURE: Validate input before JSON encoding
$message = htmlspecialchars($_GET['msg'], ENT_QUOTES);
echo json_encode(['message' => $message]);
```

### 2. XML Output

```php
// VULNERABLE: Direct XML output
$message = $_POST['message'];
$xml = "<response><message>{$message}</message></response>";

// SECURE: Escape XML entities
$message = htmlspecialchars($message, ENT_QUOTES);
$xml = "<response><message>{$message}</message></response>";
```

### 3. CSS Injection

```php
// VULNERABLE: Direct CSS output
$color = $_GET['color'];
echo "<style>body { background-color: {$color}; }</style>";

// SECURE: Validate CSS values
$allowedColors = ['red', 'blue', 'green', 'black', 'white'];
$color = in_array($color, $allowedColors) ? $color : 'white';
echo "<style>body { background-color: {$color}; }</style>";
```

## XSS Testing and Detection

### Manual Testing

```html
<!-- Common XSS test payloads -->
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<iframe src="javascript:alert('XSS')"></iframe>
<div onmouseover=alert('XSS')>Hover me</div>
```

### Automated Testing Tools

- **OWASP ZAP** - Web application security scanner
- **Burp Suite** - Intercepting proxy with XSS detection
- **XSStrike** - Advanced XSS detection suite
- **sqlmap** - Can detect XSS along with SQL injection

### Unit Testing for XSS Protection

```php
<?php
class XSSProtectionTest extends PHPUnit_Framework_TestCase
{
    public function testHtmlEscaping()
    {
        $maliciousInput = '<script>alert("XSS")</script>';
        $escaped = htmlspecialchars($maliciousInput, ENT_QUOTES, 'UTF-8');

        $this->assertNotContains('<script>', $escaped);
        $this->assertContains('&lt;script&gt;', $escaped);
    }

    public function testJsonEscaping()
    {
        $maliciousInput = '</script><script>alert("XSS")</script>';
        $json = json_encode(['data' => $maliciousInput]);

        // JSON encoding should make script tags safe
        $this->assertContains('\u003c/script\u003e', $json);
    }

    public function testXSSPayloads()
    {
        $payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            'javascript:alert("XSS")',
            '<iframe src="javascript:alert(\'XSS\')"></iframe>'
        ];

        foreach ($payloads as $payload) {
            $escaped = htmlspecialchars($payload, ENT_QUOTES, 'UTF-8');
            $this->assertNotContains('<script>', $escaped);
            $this->assertNotContains('javascript:', $escaped);
        }
    }
}
```

## Common XSS Mistakes

### 1. Incomplete Escaping

```php
// WRONG: Only escaping quotes, not angle brackets
$userInput = str_replace(['"', "'"], ['&quot;', '&#39;'], $userInput);
echo "<input value='{$userInput}'>";

// RIGHT: Use htmlspecialchars
echo "<input value='" . htmlspecialchars($userInput, ENT_QUOTES) . "'>";
```

### 2. Double Encoding Issues

```php
// PROBLEM: Double encoding can be bypassed
$data = htmlspecialchars($userInput); // First encoding
// Later: htmlspecialchars($data);     // Second encoding creates bypasses

// SOLUTION: Encode once at output
echo htmlspecialchars($userInput, ENT_QUOTES);
```

### 3. Context Confusion

```php
// WRONG: Using HTML escaping in JavaScript context
$userInput = htmlspecialchars($_GET['data']);
echo "<script>var data = '{$userInput}';</script>";

// RIGHT: Use appropriate escaping for context
echo "<script>var data = " . json_encode($_GET['data']) . ";</script>";
```

### 4. Trusted Content Assumptions

```php
// PROBLEM: Assuming database content is safe
$userData = $pdo->query("SELECT bio FROM users WHERE id = 1")->fetch()['bio'];
echo $userData; // Database content can contain XSS if not properly validated

// SOLUTION: Always escape output, regardless of source
echo htmlspecialchars($userData, ENT_QUOTES);
```

## Performance Considerations

### Escaping Performance

```php
// Fast escaping for high-traffic sites
function fastHtmlEscape($string) {
    return str_replace(
        ['&', '<', '>', '"', "'"],
        ['&amp;', '&lt;', '&gt;', '&quot;', '&#39;'],
        $string
    );
}

// Cached escaping for repeated content
class EscapeCache
{
    private static $cache = [];

    public static function cachedEscape($content) {
        $key = md5($content);
        if (!isset(self::$cache[$key])) {
            self::$cache[$key] = htmlspecialchars($content, ENT_QUOTES, 'UTF-8');
        }
        return self::$cache[$key];
    }
}
```

## Summary: XSS Prevention Rules

1. **Escape all output** - Use context-appropriate escaping functions
2. **Validate all input** - Use allow-lists and proper validation
3. **Use Content Security Policy** - Implement CSP headers
4. **Sanitize HTML content** - Use libraries like HTML Purifier for rich content
5. **Use template engines** - Leverage automatic escaping in frameworks
6. **Test thoroughly** - Use both manual and automated XSS testing
7. **Keep libraries updated** - XSS vulnerabilities are found in dependencies
8. **Implement proper encoding** - Ensure UTF-8 and proper character handling
9. **Monitor and log** - Track XSS attempts and suspicious activity
10. **Educate developers** - XSS awareness is crucial for secure coding

## Next Steps

Now that you understand XSS protection, explore:

- **[Input Handling](InputHandling.md)** - Learn about input validation and sanitization
- **[CSRF Protection](CSRFProtection.md)** - Prevent cross-site request forgery
- **[Session Security](SessionSecurity.md)** - Secure session management

Remember: XSS is one of the most common web vulnerabilities. Always escape output and validate input to prevent XSS attacks!
