# Secure Coding Basics

## What is Secure Coding?

Secure coding is the practice of writing software that protects against security vulnerabilities and threats. It involves implementing security measures throughout the development lifecycle to prevent, detect, and respond to security incidents.

### Key Principles of Secure Coding

1. **Defense in Depth** - Multiple layers of security controls
2. **Least Privilege** - Grant minimal necessary permissions
3. **Fail-Safe Defaults** - Default to secure behavior
4. **Input Validation** - Never trust user input
5. **Error Handling** - Don't expose sensitive information in errors

## Why Security Matters in Web Applications

### The Cost of Security Breaches

- **Financial Impact**: Data breaches cost companies millions annually
- **Reputation Damage**: Loss of customer trust and brand value
- **Legal Consequences**: Compliance violations and lawsuits
- **Operational Disruption**: System downtime and recovery costs

### Real-World Statistics

- **78%** of web applications have at least one serious vulnerability (OWASP)
- **300,000** new malware samples discovered daily
- **43%** of cyber attacks target small businesses
- **Average breach cost**: $4.45 million (IBM Cost of a Data Breach Report)

## How Attackers Target PHP and Laravel Applications

### Common Attack Vectors

#### 1. **Injection Attacks**
```php
// VULNERABLE - Direct string concatenation
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];

// SECURE - Prepared statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
```

#### 2. **Cross-Site Scripting (XSS)**
```php
// VULNERABLE - Direct output without escaping
echo "<h1>Welcome, " . $_GET['name'] . "!</h1>";

// SECURE - Proper output escaping
echo "<h1>Welcome, " . htmlspecialchars($_GET['name']) . "!</h1>";
```

#### 3. **Cross-Site Request Forgery (CSRF)**
- Attackers trick users into performing unwanted actions
- Laravel provides built-in CSRF protection with `@csrf` tokens

#### 4. **Broken Authentication**
- Weak password policies
- Session fixation attacks
- Improper logout handling

#### 5. **Sensitive Data Exposure**
- Storing passwords in plain text
- Transmitting data over unencrypted connections
- Improper error handling revealing sensitive information

### PHP-Specific Vulnerabilities

#### **File Inclusion Attacks**
```php
// VULNERABLE - Direct file inclusion
include($_GET['page'] . '.php');

// SECURE - Whitelist approach
$allowed_pages = ['home', 'about', 'contact'];
$page = $_GET['page'] ?? 'home';
if (in_array($page, $allowed_pages)) {
    include($page . '.php');
}
```

#### **Command Injection**
```php
// VULNERABLE - Direct shell execution
exec("ping " . $_GET['host']);

// SECURE - Input validation and escaping
$host = escapeshellarg($_GET['host']);
exec("ping " . $host);
```

### Laravel-Specific Attack Vectors

#### **Mass Assignment Vulnerabilities**
```php
// VULNERABLE - Mass assignment without protection
User::create($request->all());

// SECURE - Use fillable properties
class User extends Model
{
    protected $fillable = ['name', 'email'];
}
```

#### **Route Model Binding Issues**
```php
// POTENTIALLY VULNERABLE - Direct ID usage
public function show($id)
{
    return User::find($id);
}

// SECURE - Authorization checks
public function show(User $user)
{
    $this->authorize('view', $user);
    return $user;
}
```

## The Attack Lifecycle

### 1. **Reconnaissance**
- Information gathering about the target
- Scanning for vulnerabilities
- Identifying entry points

### 2. **Weaponization**
- Creating exploit code
- Preparing attack payloads
- Setting up command and control

### 3. **Delivery**
- Injecting malicious code
- Social engineering attacks
- Phishing attempts

### 4. **Exploitation**
- Executing the attack
- Gaining unauthorized access
- Escalating privileges

### 5. **Installation**
- Installing backdoors
- Creating persistence mechanisms
- Covering tracks

### 6. **Command and Control**
- Maintaining access
- Exfiltrating data
- Further exploitation

## Defense Strategies

### **Prevention**
- Input validation and sanitization
- Proper authentication and authorization
- Secure coding practices
- Regular security updates

### **Detection**
- Intrusion detection systems
- Log monitoring and analysis
- Security scanning tools
- Anomaly detection

### **Response**
- Incident response plans
- Backup and recovery procedures
- Communication protocols
- Forensic analysis

## Secure Development Lifecycle

### 1. **Requirements Phase**
- Include security requirements
- Threat modeling
- Risk assessment

### 2. **Design Phase**
- Security architecture review
- Secure design patterns
- Threat mitigation strategies

### 3. **Implementation Phase**
- Secure coding standards
- Code reviews
- Static analysis tools

### 4. **Testing Phase**
- Security testing (penetration testing)
- Vulnerability scanning
- Code analysis

### 5. **Deployment Phase**
- Secure configuration
- Hardening procedures
- Monitoring setup

### 6. **Maintenance Phase**
- Regular updates and patches
- Continuous monitoring
- Incident response

## Common Security Mistakes to Avoid

### **Trusting User Input**
```php
// WRONG - Blind trust
$user_id = $_POST['user_id'];
$query = "SELECT * FROM users WHERE id = $user_id";

// RIGHT - Validate and sanitize
$user_id = filter_var($_POST['user_id'], FILTER_VALIDATE_INT);
if ($user_id === false) {
    die("Invalid user ID");
}
```

### **Using Deprecated Functions**
```php
// AVOID - Deprecated and insecure
mysql_connect(); // Removed in PHP 7.0
md5(); // Cryptographically broken

// USE - Modern secure alternatives
$pdo = new PDO(); // For database connections
password_hash(); // For password hashing
```

### **Improper Error Handling**
```php
// WRONG - Exposing sensitive information
try {
    $user = User::findOrFail($id);
} catch (Exception $e) {
    echo $e->getMessage(); // Reveals database structure
}

// RIGHT - Generic error messages
try {
    $user = User::findOrFail($id);
} catch (ModelNotFoundException $e) {
    abort(404, 'User not found');
} catch (Exception $e) {
    Log::error($e->getMessage()); // Log internally
    abort(500, 'Internal server error');
}
```

## Tools for Secure Development

### **Static Analysis Tools**
- **PHPStan** - PHP static analysis tool
- **Psalm** - Static analysis for PHP
- **PHPCS** - PHP CodeSniffer for coding standards

### **Security Scanners**
- **OWASP ZAP** - Web application security scanner
- **Nikto** - Web server scanner
- **SQLMap** - SQL injection testing tool

### **Dependency Checkers**
- **Composer Audit** - Check for vulnerable PHP packages
- **NPM Audit** - Check for vulnerable JavaScript packages
- **Snyk** - Comprehensive vulnerability scanning

## Best Practices Summary

1. **Validate all inputs** - Never trust user data
2. **Use prepared statements** - Prevent SQL injection
3. **Escape outputs** - Prevent XSS attacks
4. **Implement proper authentication** - Secure user sessions
5. **Keep software updated** - Apply security patches promptly
6. **Use secure configurations** - Follow security hardening guides
7. **Monitor and log** - Detect and respond to security events
8. **Follow least privilege** - Grant minimal necessary permissions
9. **Encrypt sensitive data** - Protect data at rest and in transit
10. **Regular security testing** - Penetration testing and code reviews

## Next Steps

Now that you understand the basics of secure coding, dive deeper into specific topics:

- **[Input Handling](InputHandling.md)** - Learn about validation and sanitization
- **[SQL Injection Prevention](SQLInjectionPrevention.md)** - Master database security
- **[Authentication & Password Handling](AuthenticationPasswordHandling.md)** - Secure user management

Remember: Security is not a one-time implementation but an ongoing process. Stay vigilant, keep learning, and regularly update your security practices.
