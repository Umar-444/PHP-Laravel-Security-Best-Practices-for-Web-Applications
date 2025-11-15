# Secure Headers

## Why HTTP Security Headers Matter

HTTP security headers are directives sent by web servers to browsers, instructing them how to behave when handling web content. They provide an additional layer of defense against common web vulnerabilities including XSS, clickjacking, MIME sniffing attacks, and man-in-the-middle attacks.

### Impact of Missing Security Headers

- **Clickjacking attacks** - Pages embedded in malicious frames
- **XSS exploitation** - Malicious scripts executed in trusted contexts
- **MIME confusion** - Files interpreted as different types
- **Protocol downgrade** - HTTP instead of HTTPS
- **Information leakage** - Server details exposed to attackers

## X-Frame-Options Header

### What is Clickjacking?

Clickjacking (UI redress attack) occurs when attackers trick users into clicking on invisible or disguised elements overlaid on legitimate pages. This can lead to:

- Unauthorized actions on social media
- Malicious form submissions
- Password changes
- Financial transactions

### X-Frame-Options Implementation

```php
<?php
// Prevent all framing
header('X-Frame-Options: DENY');

// Allow framing only from same origin
header('X-Frame-Options: SAMEORIGIN');

// Allow framing from specific origin
header('X-Frame-Options: ALLOW-FROM https://trusted-site.com');
```

#### Browser Support
- ✅ Internet Explorer 8+
- ✅ Firefox 3.6.9+
- ✅ Chrome 4.1+
- ✅ Safari 4+
- ❌ Deprecated in favor of CSP frame-ancestors

### Content Security Policy Frame Protection

```php
<?php
// More flexible frame control with CSP
header("Content-Security-Policy: frame-ancestors 'self'");

// Allow specific domains
header("Content-Security-Policy: frame-ancestors 'self' https://trusted.com");
```

## X-Content-Type-Options Header

### What is MIME Sniffing?

MIME sniffing occurs when browsers attempt to determine a file's MIME type by examining its content, rather than relying on the `Content-Type` header. This can lead to:

- JavaScript execution in image files
- HTML rendering of CSS files
- Security policy bypasses

### Implementation

```php
<?php
// Prevent MIME sniffing
header('X-Content-Type-Options: nosniff');
```

#### Example Attack Scenario

```html
<!-- Malicious image that contains HTML/JavaScript -->
<img src="evil.jpg" style="display:none">

<!-- Content of evil.jpg:
    <script>alert('MIME sniffing attack!')</script>
-->

<!-- Without X-Content-Type-Options: nosniff, browser might execute the script -->
```

### Proper Content-Type Headers

```php
<?php
class SecureContentType
{
    private static array $contentTypes = [
        'html' => 'text/html; charset=utf-8',
        'json' => 'application/json; charset=utf-8',
        'xml' => 'application/xml; charset=utf-8',
        'css' => 'text/css; charset=utf-8',
        'js' => 'application/javascript; charset=utf-8',
        'png' => 'image/png',
        'jpg' => 'image/jpeg',
        'pdf' => 'application/pdf',
        'txt' => 'text/plain; charset=utf-8',
    ];

    public static function setContentType(string $type): void
    {
        if (isset(self::$contentTypes[$type])) {
            header('Content-Type: ' . self::$contentTypes[$type]);
            header('X-Content-Type-Options: nosniff');
        }
    }

    public static function serveFileSecurely(string $filePath, string $filename): void
    {
        $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

        if (isset(self::$contentTypes[$extension])) {
            header('Content-Type: ' . self::$contentTypes[$extension]);
            header('Content-Disposition: attachment; filename="' . basename($filename) . '"');
            header('X-Content-Type-Options: nosniff');

            readfile($filePath);
            exit;
        }

        // Unknown file type - force download
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($filename) . '"');
        header('X-Content-Type-Options: nosniff');
    }
}
```

## Content Security Policy (CSP)

### What is CSP?

Content Security Policy is a security standard that helps prevent XSS attacks by controlling which resources can be loaded and executed. CSP provides fine-grained control over:

- Scripts execution sources
- Stylesheet loading
- Image sources
- Font loading
- AJAX requests
- Frame embedding

### Basic CSP Implementation

```php
<?php
// Basic CSP - only allow same-origin resources
header("Content-Security-Policy: default-src 'self'");
```

### Comprehensive CSP

```php
<?php
class ContentSecurityPolicy
{
    private array $policies = [];

    public function __construct()
    {
        // Default restrictive policy
        $this->policies = [
            'default-src' => "'self'",
            'script-src' => "'self'",
            'style-src' => "'self'",
            'img-src' => "'self' data: https:",
            'font-src' => "'self' https://fonts.gstatic.com",
            'connect-src' => "'self'",
            'media-src' => "'self'",
            'object-src' => "'none'",
            'child-src' => "'self'",
            'frame-ancestors' => "'none'",
            'form-action' => "'self'",
        ];
    }

    public function allowInlineScripts(): self
    {
        $this->policies['script-src'] .= " 'unsafe-inline'";
        return $this;
    }

    public function allowInlineStyles(): self
    {
        $this->policies['style-src'] .= " 'unsafe-inline'";
        return $this;
    }

    public function allowExternalDomain(string $domain): self
    {
        $this->policies['default-src'] .= " {$domain}";
        return $this;
    }

    public function allowScriptDomain(string $domain): self
    {
        $this->policies['script-src'] .= " {$domain}";
        return $this;
    }

    public function addNonce(string $nonce): self
    {
        $this->policies['script-src'] = str_replace("'self'", "'self' 'nonce-{$nonce}'", $this->policies['script-src']);
        $this->policies['style-src'] = str_replace("'self'", "'self' 'nonce-{$nonce}'", $this->policies['style-src']);
        return $this;
    }

    public function enableUpgradeInsecureRequests(): self
    {
        $this->policies['upgrade-insecure-requests'] = '';
        return $this;
    }

    public function build(): string
    {
        $directives = [];

        foreach ($this->policies as $directive => $value) {
            if (!empty($value)) {
                $directives[] = "{$directive} {$value}";
            } elseif (isset($this->policies[$directive])) {
                // For directives without values like 'upgrade-insecure-requests'
                $directives[] = $directive;
            }
        }

        return implode('; ', $directives);
    }

    public static function create(): self
    {
        return new self();
    }
}

// Usage
$csp = ContentSecurityPolicy::create()
    ->allowInlineScripts()
    ->allowExternalDomain('https://cdn.example.com')
    ->enableUpgradeInsecureRequests()
    ->build();

header('Content-Security-Policy: ' . $csp);
```

### CSP with Nonces for Inline Scripts

```php
<?php
class CSPNonceManager
{
    private static ?string $nonce = null;

    public static function generateNonce(): string
    {
        if (self::$nonce === null) {
            self::$nonce = bin2hex(random_bytes(16));
        }
        return self::$nonce;
    }

    public static function getCSPHeader(): string
    {
        $nonce = self::generateNonce();
        return "default-src 'self'; script-src 'self' 'nonce-{$nonce}'; style-src 'self' 'nonce-{$nonce}'";
    }

    public static function createSecureScript(string $script): string
    {
        $nonce = self::generateNonce();
        return "<script nonce='{$nonce}'>{$script}</script>";
    }

    public static function createSecureStyle(string $style): string
    {
        $nonce = self::generateNonce();
        return "<style nonce='{$nonce}'>{$style}</style>";
    }
}

// Usage
header('Content-Security-Policy: ' . CSPNonceManager::getCSPHeader());

// Inline scripts are now allowed with nonce
echo CSPNonceManager::createSecureScript('console.log("Secure inline script");');
```

### CSP Violation Reporting

```php
<?php
// Enable CSP violation reporting
header("Content-Security-Policy: default-src 'self'; report-uri /csp-report");

// Or with modern report-to directive
header("Content-Security-Policy: default-src 'self'; report-to csp-endpoint");
header("Report-To: {\"group\":\"csp-endpoint\",\"max_age\":10886400,\"endpoints\":[{\"url\":\"https://yourdomain.com/csp-report\"}]}");
```

## X-XSS-Protection Header

### XSS Auditor

The X-XSS-Protection header controls the browser's built-in XSS filter.

```php
<?php
// Enable XSS protection
header('X-XSS-Protection: 1; mode=block');

// Disable XSS protection (not recommended)
header('X-XSS-Protection: 0');
```

**Note**: This header is deprecated in modern browsers in favor of CSP, but still provides protection for older browsers.

## Strict-Transport-Security (HSTS)

### HTTPS Enforcement

HSTS forces browsers to use HTTPS connections, preventing protocol downgrade attacks.

```php
<?php
// Basic HSTS (6 months)
header('Strict-Transport-Security: max-age=15552000');

// Include subdomains
header('Strict-Transport-Security: max-age=15552000; includeSubDomains');

// Preload for HSTS preload list
header('Strict-Transport-Security: max-age=15552000; includeSubDomains; preload');
```

### HSTS Preloading

HSTS preloading submits your domain to browser vendor lists for built-in HTTPS enforcement.

```php
<?php
class HSTSManager
{
    public static function setHSTSHeader(bool $includeSubdomains = true, bool $preload = false): void
    {
        $maxAge = 31536000; // 1 year

        $header = "max-age={$maxAge}";

        if ($includeSubdomains) {
            $header .= '; includeSubDomains';
        }

        if ($preload) {
            $header .= '; preload';
        }

        header("Strict-Transport-Security: {$header}");
    }

    public static function shouldEnableHSTS(): bool
    {
        // Only enable HSTS for HTTPS connections
        return isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
    }

    public static function validateHSTSPreload(): array
    {
        $issues = [];

        // Check HTTPS redirect
        if (!self::shouldEnableHSTS()) {
            $issues[] = 'HSTS should only be enabled for HTTPS connections';
        }

        // Check for HTTP resources (would break HSTS)
        // This is a simplified check - implement more comprehensive validation

        return $issues;
    }
}
```

## Referrer-Policy Header

### Referrer Information Control

The Referrer-Policy header controls how much referrer information is sent with requests.

```php
<?php
// Strict origin - only send origin (scheme, host, port)
header('Referrer-Policy: strict-origin');

// When cross-origin, only send origin
header('Referrer-Policy: strict-origin-when-cross-origin');

// Never send referrer
header('Referrer-Policy: no-referrer');

// Default behavior (may leak sensitive information)
header('Referrer-Policy: unsafe-url');
```

## Permissions Policy (Feature Policy)

### Controlling Browser Features

Permissions Policy controls access to sensitive browser features.

```php
<?php
// Block camera and microphone access
header('Permissions-Policy: camera=(), microphone=()');

// Allow geolocation only for same origin
header('Permissions-Policy: geolocation=(self)');

// Block all payment APIs
header('Permissions-Policy: payment=()');

// Comprehensive policy
header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()');
```

## Laravel Security Headers Implementation

### Laravel Middleware for Security Headers

```php
<?php
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class SecurityHeadersMiddleware
{
    private array $securityHeaders = [
        'X-Frame-Options' => 'DENY',
        'X-Content-Type-Options' => 'nosniff',
        'X-XSS-Protection' => '1; mode=block',
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
        'Permissions-Policy' => 'camera=(), microphone=(), geolocation=(), payment=()',
    ];

    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);

        // Remove Laravel version header
        $response->headers->remove('X-Powered-By');

        // Set security headers
        foreach ($this->securityHeaders as $header => $value) {
            $response->headers->set($header, $value);
        }

        // Content Security Policy
        $csp = $this->buildContentSecurityPolicy();
        $response->headers->set('Content-Security-Policy', $csp);

        // HSTS for HTTPS
        if ($request->secure()) {
            $response->headers->set('Strict-Transport-Security',
                'max-age=31536000; includeSubDomains; preload');
        }

        return $response;
    }

    private function buildContentSecurityPolicy(): string
    {
        $policies = [
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data: https:",
            "font-src 'self' https://fonts.gstatic.com",
            "connect-src 'self'",
            "media-src 'self'",
            "object-src 'none'",
            "child-src 'self'",
            "frame-ancestors 'none'",
            "form-action 'self'",
        ];

        // Add upgrade-insecure-requests in production
        if (app()->environment('production')) {
            $policies[] = "upgrade-insecure-requests";
        }

        return implode('; ', $policies);
    }
}
```

### Registering Laravel Middleware

```php
<?php
// In app/Http/Kernel.php
protected $middleware = [
    // ... other middleware
    \App\Http\Middleware\SecurityHeadersMiddleware::class,
];

// Or as global middleware
protected $middlewareGroups = [
    'web' => [
        // ... other middleware
        \App\Http\Middleware\SecurityHeadersMiddleware::class,
    ],
];
```

### Laravel CSP Package Usage

```php
<?php
// Using spatie/laravel-csp package
use Spatie\Csp\Directive;
use Spatie\Csp\Keyword;
use Spatie\Csp\Policy;

class CustomCspPolicy extends Policy
{
    public function configure()
    {
        $this
            ->add(Directive::DEFAULT, Keyword::SELF)
            ->add(Directive::SCRIPT, Keyword::SELF)
            ->add(Directive::SCRIPT, 'https://cdn.example.com')
            ->add(Directive::STYLE, Keyword::SELF)
            ->add(Directive::STYLE, Keyword::UNSAFE_INLINE)
            ->add(Directive::IMG, Keyword::SELF)
            ->add(Directive::IMG, 'data:')
            ->add(Directive::FONT, Keyword::SELF)
            ->add(Directive::CONNECT, Keyword::SELF);
    }
}

// In service provider
use Spatie\Csp\AddCspHeaders;

public function boot()
{
    app(AddCspHeaders::class)->addPolicy(new CustomCspPolicy());
}
```

## Testing Security Headers

### Manual Header Testing

```bash
# Check security headers
curl -I https://yourdomain.com

# Expected output includes:
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
# X-XSS-Protection: 1; mode=block
# Content-Security-Policy: default-src 'self'
# Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

### Automated Security Header Testing

```php
<?php
class SecurityHeadersTester
{
    private array $requiredHeaders = [
        'X-Frame-Options',
        'X-Content-Type-Options',
        'X-XSS-Protection',
        'Content-Security-Policy',
        'Strict-Transport-Security',
    ];

    private array $headerChecks = [
        'X-Frame-Options' => ['DENY', 'SAMEORIGIN'],
        'X-Content-Type-Options' => ['nosniff'],
        'X-XSS-Protection' => ['1; mode=block'],
        'Strict-Transport-Security' => null, // Just check presence for HTTPS
    ];

    public static function testHeaders(string $url): array
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_NOBODY, true);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $headers = self::parseHeaders($response);

        return self::analyzeHeaders($headers, $httpCode);
    }

    private static function parseHeaders(string $response): array
    {
        $headers = [];
        $lines = explode("\n", $response);

        foreach ($lines as $line) {
            if (strpos($line, ':') !== false) {
                [$name, $value] = explode(':', $line, 2);
                $headers[trim($name)] = trim($value);
            }
        }

        return $headers;
    }

    private static function analyzeHeaders(array $headers, int $httpCode): array
    {
        $results = [
            'score' => 0,
            'max_score' => 5,
            'issues' => [],
            'passed' => [],
        ];

        $tester = new self();

        // Check required headers
        foreach ($tester->requiredHeaders as $header) {
            if (!isset($headers[$header])) {
                $results['issues'][] = "Missing {$header} header";
            } else {
                $results['passed'][] = "{$header}: {$headers[$header]}";
                $results['score']++;
            }
        }

        // Validate header values
        foreach ($tester->headerChecks as $header => $expectedValues) {
            if (isset($headers[$header]) && $expectedValues !== null) {
                $value = $headers[$header];
                $valid = false;

                foreach ($expectedValues as $expected) {
                    if (stripos($value, $expected) !== false) {
                        $valid = true;
                        break;
                    }
                }

                if (!$valid) {
                    $results['issues'][] = "Invalid {$header} value: {$value}";
                    $results['score']--;
                }
            }
        }

        // Special check for HSTS on HTTPS
        if ($httpCode >= 200 && $httpCode < 400) {
            $url = 'https://' . $_SERVER['HTTP_HOST'] ?? 'localhost';
            if (strpos($url, 'https://') === 0) {
                if (!isset($headers['Strict-Transport-Security'])) {
                    $results['issues'][] = 'Missing HSTS header for HTTPS site';
                    $results['score']--;
                }
            }
        }

        return $results;
    }
}

// Usage
$results = SecurityHeadersTester::testHeaders('https://yourdomain.com');
echo "Security Headers Score: {$results['score']}/{$results['max_score']}\n";

if (!empty($results['issues'])) {
    echo "Issues found:\n";
    foreach ($results['issues'] as $issue) {
        echo "- {$issue}\n";
    }
}
```

## Security Headers Checklist

### Essential Headers
- [ ] `X-Frame-Options: DENY` - Prevent clickjacking
- [ ] `X-Content-Type-Options: nosniff` - Prevent MIME sniffing
- [ ] `X-XSS-Protection: 1; mode=block` - Enable XSS filtering
- [ ] `Content-Security-Policy` - Control resource loading
- [ ] `Strict-Transport-Security` - Enforce HTTPS (HTTPS only)

### Additional Security Headers
- [ ] `Referrer-Policy: strict-origin-when-cross-origin` - Control referrer information
- [ ] `Permissions-Policy` - Control browser features access
- [ ] `Cross-Origin-Embedder-Policy` - COEP protection
- [ ] `Cross-Origin-Opener-Policy` - COOP protection
- [ ] `Cross-Origin-Resource-Policy` - CORP protection

### Implementation Steps
- [ ] Create security headers middleware
- [ ] Implement CSP with appropriate policies
- [ ] Test headers with security scanning tools
- [ ] Monitor CSP violation reports
- [ ] Regularly update policies based on application changes

## Summary: Security Headers Implementation

1. **Implement X-Frame-Options** - Prevent clickjacking attacks
2. **Add X-Content-Type-Options** - Prevent MIME sniffing
3. **Enable Content Security Policy** - Control resource execution
4. **Use Strict-Transport-Security** - Enforce HTTPS connections
5. **Set Referrer-Policy** - Control referrer information leakage
6. **Implement Permissions Policy** - Control browser feature access
7. **Test thoroughly** - Use automated tools and manual testing
8. **Monitor violations** - Set up CSP reporting endpoints
9. **Keep updated** - Regularly review and update policies
10. **Use framework features** - Leverage Laravel's built-in security

## Next Steps

Now that you understand security headers, explore:

- **[Input Handling](InputHandling.md)** - Validate and sanitize user input
- **[XSS Protection](XSSProtection.md)** - Prevent cross-site scripting attacks
- **[CSRF Protection](CSRFProtection.md)** - Prevent cross-site request forgery

Remember: Security headers provide defense-in-depth protection. Implement them consistently across all pages and API endpoints!
