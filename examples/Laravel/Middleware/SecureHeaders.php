<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

/**
 * Security Headers Middleware
 *
 * This middleware adds security headers to HTTP responses
 * to protect against common web vulnerabilities
 */
class SecureHeaders
{
    /**
     * Security headers configuration
     */
    private $headers = [
        // Prevent clickjacking attacks
        'X-Frame-Options' => 'SAMEORIGIN',

        // Prevent MIME type sniffing
        'X-Content-Type-Options' => 'nosniff',

        // Enable XSS protection in older browsers
        'X-XSS-Protection' => '1; mode=block',

        // Referrer Policy
        'Referrer-Policy' => 'strict-origin-when-cross-origin',

        // Content Security Policy (adjust according to your needs)
        'Content-Security-Policy' => "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; media-src 'self'; object-src 'none'; child-src 'self'; frame-ancestors 'self'; form-action 'self'; upgrade-insecure-requests",

        // HTTP Strict Transport Security
        'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains; preload',

        // Feature Policy / Permissions Policy
        'Permissions-Policy' => 'camera=(), microphone=(), geolocation=(), gyroscope=(), magnetometer=(), payment=(), usb=()',

        // Remove server information
        'X-Powered-By' => null,

        // Cross-Origin Embedder Policy
        'Cross-Origin-Embedder-Policy' => 'credentialless',

        // Cross-Origin Opener Policy
        'Cross-Origin-Opener-Policy' => 'same-origin',

        // Cross-Origin Resource Policy
        'Cross-Origin-Resource-Policy' => 'same-origin',
    ];

    /**
     * Environment-specific header adjustments
     */
    private $envHeaders = [
        'local' => [
            // Relax CSP for local development
            'Content-Security-Policy' => "default-src 'self' 'unsafe-inline' 'unsafe-eval' localhost:* 127.0.0.1:*; script-src 'self' 'unsafe-inline' 'unsafe-eval' localhost:* 127.0.0.1:*; style-src 'self' 'unsafe-inline' localhost:* 127.0.0.1:*; img-src 'self' data: https: localhost:* 127.0.0.1:*; font-src 'self' data: localhost:* 127.0.0.1:*; connect-src 'self' localhost:* 127.0.0.1:* ws: wss:",
        ],
        'testing' => [
            // Minimal headers for testing
            'Content-Security-Policy' => "default-src 'self'",
        ],
    ];

    /**
     * Handle an incoming request
     */
    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);

        // Add security headers
        foreach ($this->headers as $header => $value) {
            if ($value === null) {
                // Remove header if value is null
                $response->headers->remove($header);
            } else {
                $response->headers->set($header, $value);
            }
        }

        // Apply environment-specific adjustments
        $environment = app()->environment();
        if (isset($this->envHeaders[$environment])) {
            foreach ($this->envHeaders[$environment] as $header => $value) {
                $response->headers->set($header, $value);
            }
        }

        // Add additional headers for API routes
        if ($request->is('api/*')) {
            $response->headers->set('X-API-Version', config('app.api_version', '1.0'));
        }

        return $response;
    }

    /**
     * Customize headers for specific use cases
     */
    public static function customizeHeaders(array $customHeaders): array
    {
        $middleware = new self();
        return array_merge($middleware->headers, $customHeaders);
    }

    /**
     * Get current headers configuration
     */
    public function getHeaders(): array
    {
        return $this->headers;
    }

    /**
     * Set custom headers (for testing or dynamic configuration)
     */
    public function setHeaders(array $headers): void
    {
        $this->headers = array_merge($this->headers, $headers);
    }
}
