# Common Web Application Vulnerabilities

## OWASP Top 10 Vulnerabilities

### 1. Injection
- **Description**: User input is not properly sanitized and executed as code
- **Examples**: SQL injection, Command injection, LDAP injection
- **Prevention**: Use prepared statements, input validation, parameterized queries

### 2. Broken Authentication
- **Description**: Authentication and session management flaws
- **Examples**: Weak passwords, session fixation, improper logout
- **Prevention**: Multi-factor authentication, secure session handling, password policies

### 3. Sensitive Data Exposure
- **Description**: Sensitive data not properly protected
- **Examples**: Unencrypted data transmission, weak encryption
- **Prevention**: Use TLS, encrypt sensitive data, proper key management

### 4. XML External Entities (XXE)
- **Description**: External entity references in XML processing
- **Examples**: Local file inclusion, server-side request forgery
- **Prevention**: Disable external entities, use safe XML parsers

### 5. Broken Access Control
- **Description**: Users can access unauthorized resources
- **Examples**: IDOR, privilege escalation, insecure direct object references
- **Prevention**: Implement proper authorization checks, use role-based access

### 6. Security Misconfiguration
- **Description**: Incorrect security settings and defaults
- **Examples**: Default passwords, unnecessary services, verbose error messages
- **Prevention**: Secure configuration management, regular audits

### 7. Cross-Site Scripting (XSS)
- **Description**: Malicious scripts injected into trusted websites
- **Examples**: Reflected XSS, Stored XSS, DOM-based XSS
- **Prevention**: Input validation, output encoding, Content Security Policy

### 8. Insecure Deserialization
- **Description**: Unsafe deserialization of user data
- **Examples**: Remote code execution, privilege escalation
- **Prevention**: Avoid deserialization of untrusted data, use safe formats

### 9. Vulnerable Components
- **Description**: Using components with known vulnerabilities
- **Examples**: Outdated libraries, unpatched software
- **Prevention**: Dependency scanning, regular updates, vulnerability monitoring

### 10. Insufficient Logging & Monitoring
- **Description**: Lack of proper logging and monitoring
- **Examples**: Undetected breaches, lack of incident response
- **Prevention**: Comprehensive logging, security monitoring, incident response plans

## PHP-Specific Vulnerabilities

### Remote File Inclusion (RFI)
- **Prevention**: Disable allow_url_include, validate file paths

### Local File Inclusion (LFI)
- **Prevention**: Use whitelists, avoid user-controlled file paths

### Session Hijacking
- **Prevention**: Use secure cookies, regenerate session IDs

### Type Juggling Vulnerabilities
- **Prevention**: Use strict comparison operators, proper type checking

## Laravel-Specific Vulnerabilities

### Mass Assignment
- **Prevention**: Use $fillable and $guarded properties

### Route Model Binding Issues
- **Prevention**: Implement proper authorization checks

### Middleware Bypass
- **Prevention**: Properly configure middleware groups

### Blade Template Injection
- **Prevention**: Avoid using unescaped output, validate user input
