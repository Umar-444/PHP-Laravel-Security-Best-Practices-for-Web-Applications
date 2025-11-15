# Laravel Security Best Practices

## Authentication & Authorization

Laravel provides robust built-in security features for authentication and authorization.

### Key Features:
- Laravel Sanctum for API authentication
- Laravel Passport for OAuth2
- Gate and Policy classes for authorization
- Built-in CSRF protection

## Mass Assignment Protection

Laravel protects against mass assignment vulnerabilities by default.

```php
// Use fillable or guarded properties
protected $fillable = ['name', 'email'];
protected $guarded = ['id', 'password'];
```

## SQL Injection Prevention

- Eloquent ORM automatically prevents SQL injection
- Use query builder methods safely
- Raw queries require proper parameter binding

## Cross-Site Scripting (XSS) Protection

- Blade templating engine auto-escapes output
- Use `{!! !!}` only for trusted content
- Implement Content Security Policy

## File Storage Security

- Use Laravel's Storage facade
- Configure secure disk permissions
- Validate file uploads
- Use secure file naming

## API Security

- Rate limiting with Laravel Throttle
- API authentication with tokens
- Input validation with Form Requests
- CORS configuration

## Environment Security

- Use `.env` files for configuration
- Don't commit sensitive data
- Use Laravel's encryption helpers
- Secure session and cookie configuration

## Security Middleware

- Use Laravel's security middleware
- Implement custom security headers
- Configure HTTPS redirection
- Set up proper CORS policies

## Database Security

- Use database migrations safely
- Encrypt sensitive data
- Implement proper indexing
- Use database-level constraints
