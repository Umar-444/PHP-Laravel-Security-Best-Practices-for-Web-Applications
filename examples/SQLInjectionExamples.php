<?php

/**
 * SQL Injection Examples: Vulnerable vs Secure Code
 *
 * This file demonstrates various SQL injection vulnerabilities and their secure alternatives
 * WARNING: The vulnerable examples are for educational purposes only!
 * NEVER use them in production code!
 */

declare(strict_types=1);

// =============================================================================
// SETUP - Database Connection
// =============================================================================

class DatabaseSetup
{
    private static ?PDO $pdo = null;

    public static function getPDO(): PDO
    {
        if (self::$pdo === null) {
            self::$pdo = new PDO("mysql:host=localhost;dbname=test", "user", "pass", [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false, // Use real prepared statements
            ]);
        }
        return self::$pdo;
    }

    public static function setupTestTables(): void
    {
        $pdo = self::getPDO();

        // Create test tables
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(50) UNIQUE,
                email VARCHAR(100),
                password VARCHAR(255),
                role ENUM('user', 'admin') DEFAULT 'user',
                active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ");

        $pdo->exec("
            CREATE TABLE IF NOT EXISTS products (
                id INT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(100),
                price DECIMAL(10,2),
                category VARCHAR(50),
                stock INT DEFAULT 0
            )
        ");

        // Insert test data
        $pdo->exec("INSERT IGNORE INTO users (username, email, password, role) VALUES
            ('admin', 'admin@example.com', '$2y$10$hash1', 'admin'),
            ('user1', 'user1@example.com', '$2y$10$hash2', 'user'),
            ('user2', 'user2@example.com', '$2y$10$hash3', 'user')
        ");

        $pdo->exec("INSERT IGNORE INTO products (name, price, category, stock) VALUES
            ('Laptop', 999.99, 'electronics', 10),
            ('Book', 19.99, 'books', 50),
            ('Phone', 699.99, 'electronics', 5)
        ");
    }
}

// =============================================================================
// 1. BASIC SQL INJECTION EXAMPLES
// =============================================================================

class BasicSQLInjection
{
    private PDO $pdo;

    public function __construct()
    {
        $this->pdo = DatabaseSetup::getPDO();
    }

    /**
     * ❌ VULNERABLE: Direct string concatenation
     * Attacker can input: 1' OR '1'='1
     * Result: SELECT * FROM users WHERE id = 1' OR '1'='1
     */
    public function getUserVulnerable(string $userId): ?array
    {
        // WARNING: This is VULNERABLE to SQL injection!
        $query = "SELECT id, username, email, role FROM users WHERE id = {$userId}";
        $stmt = $this->pdo->query($query);

        return $stmt->fetch();
    }

    /**
     * ✅ SECURE: Prepared statement with positional parameters
     */
    public function getUserSecure(string $userId): ?array
    {
        $stmt = $this->pdo->prepare("SELECT id, username, email, role FROM users WHERE id = ?");
        $stmt->execute([$userId]);

        return $stmt->fetch();
    }

    /**
     * ❌ VULNERABLE: Authentication bypass
     * Attacker can input username: admin' --
     * Password: anything
     */
    public function loginVulnerable(string $username, string $password): ?array
    {
        // WARNING: This is EXTREMELY VULNERABLE!
        $query = "SELECT * FROM users WHERE username = '{$username}' AND password = '{$password}'";
        $stmt = $this->pdo->query($query);

        return $stmt->fetch();
    }

    /**
     * ✅ SECURE: Secure authentication
     */
    public function loginSecure(string $username, string $password): ?array
    {
        $stmt = $this->pdo->prepare("SELECT id, username, email, role FROM users WHERE username = ? AND active = 1");
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {
            return $user;
        }

        return null;
    }
}

// =============================================================================
// 2. UNION-BASED SQL INJECTION EXAMPLES
// =============================================================================

class UnionSQLInjection
{
    private PDO $pdo;

    public function __construct()
    {
        $this->pdo = DatabaseSetup::getPDO();
    }

    /**
     * ❌ VULNERABLE: Union-based injection
     * Attacker can input: 1' UNION SELECT username, password, role, null FROM users --
     */
    public function getProductVulnerable(string $productId): array
    {
        // WARNING: VULNERABLE to union-based attacks!
        $query = "SELECT id, name, price, category FROM products WHERE id = {$productId}";
        $stmt = $this->pdo->query($query);

        return $stmt->fetchAll();
    }

    /**
     * ✅ SECURE: Prepared statement prevents union attacks
     */
    public function getProductSecure(string $productId): array
    {
        $stmt = $this->pdo->prepare("SELECT id, name, price, category FROM products WHERE id = ?");
        $stmt->execute([$productId]);

        return $stmt->fetchAll();
    }

    /**
     * ❌ VULNERABLE: Multiple column union attack
     * Attacker can dump database structure
     */
    public function searchProductsVulnerable(string $category): array
    {
        // WARNING: VULNERABLE!
        $query = "SELECT id, name, price, category FROM products WHERE category = '{$category}'";
        $stmt = $this->pdo->query($query);

        return $stmt->fetchAll();
    }

    /**
     * ✅ SECURE: Parameterized search
     */
    public function searchProductsSecure(string $category): array
    {
        $stmt = $this->pdo->prepare("SELECT id, name, price, category FROM products WHERE category = ?");
        $stmt->execute([$category]);

        return $stmt->fetchAll();
    }
}

// =============================================================================
// 3. LIKE QUERY SQL INJECTION
// =============================================================================

class LikeQueryInjection
{
    private PDO $pdo;

    public function __construct()
    {
        $this->pdo = DatabaseSetup::getPDO();
    }

    /**
     * ❌ VULNERABLE: LIKE query injection
     * Attacker can input: %' UNION SELECT username, password, '1', '1' FROM users --
     */
    public function searchUsersVulnerable(string $searchTerm): array
    {
        // WARNING: VULNERABLE!
        $query = "SELECT id, username, email, role FROM users WHERE username LIKE '%{$searchTerm}%'";
        $stmt = $this->pdo->query($query);

        return $stmt->fetchAll();
    }

    /**
     * ✅ SECURE: LIKE with prepared statements
     */
    public function searchUsersSecure(string $searchTerm): array
    {
        $stmt = $this->pdo->prepare("SELECT id, username, email, role FROM users WHERE username LIKE ?");
        $stmt->execute(["%{$searchTerm}%"]);

        return $stmt->fetchAll();
    }

    /**
     * ✅ SECURE: LIKE with named parameters
     */
    public function searchProductsByName(string $name): array
    {
        $stmt = $this->pdo->prepare("SELECT * FROM products WHERE name LIKE :search");
        $stmt->execute(['search' => "%{$name}%"]);

        return $stmt->fetchAll();
    }
}

// =============================================================================
// 4. DYNAMIC TABLE/COLUMN NAME INJECTION
// =============================================================================

class DynamicNameInjection
{
    private PDO $pdo;

    public function __construct()
    {
        $this->pdo = DatabaseSetup::getPDO();
    }

    /**
     * ❌ VULNERABLE: Dynamic table name
     * Attacker can input: users; DROP TABLE products; --
     */
    public function getRecordsFromTableVulnerable(string $tableName): array
    {
        // WARNING: EXTREMELY DANGEROUS!
        $query = "SELECT * FROM {$tableName}";
        $stmt = $this->pdo->query($query);

        return $stmt->fetchAll();
    }

    /**
     * ✅ SECURE: Whitelist table names
     */
    public function getRecordsFromTableSecure(string $tableName): array
    {
        $allowedTables = ['users', 'products'];

        if (!in_array($tableName, $allowedTables)) {
            throw new InvalidArgumentException('Invalid table name');
        }

        $stmt = $this->pdo->prepare("SELECT * FROM {$tableName}");
        $stmt->execute();

        return $stmt->fetchAll();
    }

    /**
     * ❌ VULNERABLE: Dynamic column name for ordering
     * Attacker can input: id; DROP TABLE users; --
     */
    public function getProductsOrderedVulnerable(string $orderBy): array
    {
        // WARNING: VULNERABLE!
        $query = "SELECT id, name, price, category FROM products ORDER BY {$orderBy}";
        $stmt = $this->pdo->query($query);

        return $stmt->fetchAll();
    }

    /**
     * ✅ SECURE: Whitelist column names
     */
    public function getProductsOrderedSecure(string $orderBy): array
    {
        $allowedColumns = ['id', 'name', 'price', 'category', 'stock'];

        if (!in_array($orderBy, $allowedColumns)) {
            $orderBy = 'id'; // Default
        }

        $stmt = $this->pdo->prepare("SELECT id, name, price, category FROM products ORDER BY {$orderBy}");
        $stmt->execute();

        return $stmt->fetchAll();
    }
}

// =============================================================================
// 5. IN CLAUSE SQL INJECTION
// =============================================================================

class InClauseInjection
{
    private PDO $pdo;

    public function __construct()
    {
        $this->pdo = DatabaseSetup::getPDO();
    }

    /**
     * ❌ VULNERABLE: IN clause injection
     * Attacker can input: 1,2); DROP TABLE users; --
     */
    public function getUsersByIdsVulnerable(string $ids): array
    {
        // WARNING: VULNERABLE!
        $query = "SELECT id, username, email FROM users WHERE id IN ({$ids})";
        $stmt = $this->pdo->query($query);

        return $stmt->fetchAll();
    }

    /**
     * ✅ SECURE: IN clause with prepared statements
     */
    public function getUsersByIdsSecure(string $ids): array
    {
        $idArray = explode(',', $ids);
        $idArray = array_map('intval', $idArray); // Sanitize
        $idArray = array_filter($idArray, function($id) {
            return $id > 0; // Only positive integers
        });

        if (empty($idArray)) {
            return [];
        }

        // Create placeholders: ?, ?, ?
        $placeholders = str_repeat('?,', count($idArray) - 1) . '?';

        $stmt = $this->pdo->prepare("SELECT id, username, email FROM users WHERE id IN ({$placeholders})");
        $stmt->execute($idArray);

        return $stmt->fetchAll();
    }

    /**
     * ✅ SECURE: IN clause with named parameters
     */
    public function getProductsByCategories(array $categories): array
    {
        if (empty($categories)) {
            return [];
        }

        // Create named parameters: :cat0, :cat1, :cat2
        $params = [];
        $paramNames = [];
        foreach ($categories as $i => $category) {
            $paramName = ":cat{$i}";
            $paramNames[] = $paramName;
            $params[$paramName] = $category;
        }

        $placeholders = implode(',', $paramNames);

        $stmt = $this->pdo->prepare("SELECT * FROM products WHERE category IN ({$placeholders})");
        $stmt->execute($params);

        return $stmt->fetchAll();
    }
}

// =============================================================================
// 6. SECOND-ORDER SQL INJECTION
// =============================================================================

class SecondOrderInjection
{
    private PDO $pdo;

    public function __construct()
    {
        $this->pdo = DatabaseSetup::getPDO();
    }

    /**
     * ❌ VULNERABLE: Second-order injection setup
     * Step 1: Store malicious data
     */
    public function createUserVulnerable(string $username, string $email): int
    {
        // This part might be safe, but stored data can cause issues later
        $stmt = $this->pdo->prepare("INSERT INTO users (username, email) VALUES (?, ?)");
        $stmt->execute([$username, $email]);

        return $this->pdo->lastInsertId();
    }

    /**
     * ❌ VULNERABLE: Second-order injection exploitation
     * Step 2: Use stored malicious data in vulnerable query
     * If username was stored as: admin'; --
     * This query becomes: SELECT * FROM users WHERE username = 'admin'; --' AND password = ?
     */
    public function loginSecondOrderVulnerable(string $username, string $password): ?array
    {
        // WARNING: This creates a second-order vulnerability!
        // The username comes from database but is used in vulnerable query
        $storedUsername = $this->getStoredUsername($username);

        $query = "SELECT * FROM users WHERE username = '{$storedUsername}' AND password = '{$password}'";
        $stmt = $this->pdo->query($query);

        return $stmt->fetch();
    }

    private function getStoredUsername(string $username): string
    {
        $stmt = $this->pdo->prepare("SELECT username FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $result = $stmt->fetch();

        return $result ? $result['username'] : '';
    }

    /**
     * ✅ SECURE: Prevent second-order injection
     */
    public function loginSecondOrderSecure(string $username, string $password): ?array
    {
        // Always use prepared statements - this prevents second-order attacks
        $stmt = $this->pdo->prepare("SELECT id, username, email, role FROM users WHERE username = ? AND active = 1");
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {
            return $user;
        }

        return null;
    }
}

// =============================================================================
// 7. LARAVEL ELOQUENT & QUERY BUILDER EXAMPLES
// =============================================================================

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class User extends Model
{
    use HasFactory;

    protected $fillable = ['username', 'email', 'password', 'role'];

    // ✅ SECURE: Eloquent automatically prevents SQL injection
    public static function findUserById(int $id): ?self
    {
        return self::where('id', $id)->where('active', true)->first();
    }

    // ✅ SECURE: Parameter binding in raw queries
    public static function findUsersByRole(string $role): array
    {
        return self::whereRaw('role = ?', [$role])->get()->toArray();
    }
}

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class UserController extends Controller
{
    /**
     * ✅ SECURE: Laravel Query Builder
     */
    public function getUser(Request $request)
    {
        // Automatic parameter binding
        $user = DB::table('users')
            ->where('id', $request->id)
            ->where('active', true)
            ->first();

        return response()->json($user);
    }

    /**
     * ✅ SECURE: Eloquent with relationships
     */
    public function getUserWithPosts(Request $request)
    {
        $user = User::with('posts')
            ->where('id', $request->id)
            ->where('active', true)
            ->first();

        return response()->json($user);
    }

    /**
     * ✅ SECURE: Complex query with multiple conditions
     */
    public function searchUsers(Request $request)
    {
        $query = User::query();

        if ($request->has('role')) {
            $query->where('role', $request->role);
        }

        if ($request->has('search')) {
            $query->where('username', 'LIKE', '%' . $request->search . '%');
        }

        return response()->json($query->paginate());
    }
}

// =============================================================================
// TESTING EXAMPLES
// =============================================================================

class SQLInjectionTester
{
    public static function testInjections(): array
    {
        DatabaseSetup::setupTestTables();

        $results = [];

        // Test basic injection
        $basic = new BasicSQLInjection();

        // Should return null (no user with malicious ID)
        $result = $basic->getUserSecure("1' OR '1'='1");
        $results['basic_injection'] = $result === null ? 'PREVENTED' : 'VULNERABLE';

        // Test union injection
        $union = new UnionSQLInjection();
        $result = $union->getProductSecure("1' UNION SELECT username, password, role, null FROM users --");
        $results['union_injection'] = count($result) === 1 ? 'PREVENTED' : 'VULNERABLE';

        // Test LIKE injection
        $like = new LikeQueryInjection();
        $result = $like->searchUsersSecure("'% UNION SELECT username, password, '1', '1' FROM users --");
        $results['like_injection'] = count($result) <= 3 ? 'PREVENTED' : 'VULNERABLE'; // Max 3 test users

        return $results;
    }
}

// =============================================================================
// USAGE EXAMPLES AND WARNINGS
// =============================================================================

/*
// Initialize database
DatabaseSetup::setupTestTables();

// DANGER: These vulnerable methods should NEVER be used!
$vulnerable = new BasicSQLInjection();

// This would be exploited:
// $user = $vulnerable->getUserVulnerable("1' OR '1'='1"); // Returns all users!

// SAFE: Always use prepared statements
$secure = new BasicSQLInjection();
$user = $secure->getUserSecure("1"); // Safe, even with malicious input

// Test injection prevention
$testResults = SQLInjectionTester::testInjections();
print_r($testResults);

// Laravel examples would go in their respective files:
// - User model in app/Models/User.php
// - Controller in app/Http/Controllers/UserController.php
*/
?>
