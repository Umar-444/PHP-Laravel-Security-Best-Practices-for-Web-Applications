# PHP Security Best Practices

## Input Validation & Sanitization

Always validate and sanitize user input to prevent injection attacks.

### Key Principles:
- Never trust user input
- Use allowlists for validation
- Sanitize output based on context
- Validate data types and formats

## SQL Injection Prevention

- Use prepared statements with PDO or mysqli
- Avoid string concatenation in queries
- Parameterize all user inputs

## Cross-Site Scripting (XSS) Protection

- Escape output using htmlspecialchars()
- Use Content Security Policy (CSP)
- Validate and sanitize input
- Use secure coding frameworks

## File Upload Security

- Validate file types and extensions
- Check file size limits
- Store files outside web root
- Generate secure filenames
- Scan for malware

## Authentication & Authorization

- Use secure password hashing (password_hash())
- Implement proper session management
- Use HTTPS everywhere
- Implement rate limiting
- Log security events

## Error Handling

- Don't expose sensitive information in errors
- Use custom error pages
- Log errors securely
- Handle exceptions properly

## Configuration Security

- Store sensitive data in environment variables
- Use secure configuration files
- Restrict file permissions
- Keep dependencies updated
