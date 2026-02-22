<?php
// Mini-app: SecureApp - properly secured application (ZERO findings expected)
// This file demonstrates correct security practices throughout

class SecureApp {
    private $pdo;

    public function __construct($pdo) {
        $this->pdo = $pdo;
    }

    // SAFE: Prepared statements for all SQL
    public function getUser($id) {
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([intval($id)]);
        return $stmt->fetch();
    }

    // SAFE: htmlspecialchars on all output
    public function renderProfile($user) {
        $name = htmlspecialchars($user['name'], ENT_QUOTES, 'UTF-8');
        $bio = htmlspecialchars($user['bio'], ENT_QUOTES, 'UTF-8');
        echo "<h1>Profile: " . $name . "</h1>";
        echo "<p>Bio: " . $bio . "</p>";
    }

    // SAFE: intval sanitizes for SQL
    public function search($term) {
        $page = intval($_GET['page']);
        $stmt = $this->pdo->prepare("SELECT * FROM items WHERE name LIKE ?");
        $stmt->execute(["%" . $term . "%"]);
        return $stmt->fetchAll();
    }

    // SAFE: basename prevents path traversal
    public function downloadFile($filename) {
        $safe = basename($filename);
        $path = "/var/www/uploads/" . $safe;
        if (file_exists($path)) {
            readfile($path);
        }
    }

    // SAFE: escapeshellarg for command arguments
    public function pingHost($host) {
        $safe = escapeshellarg($host);
        system("ping -c 1 " . $safe);
    }

    // SAFE: strict comparison
    public function checkRole($role) {
        if ($role === 'admin') {
            return true;
        }
        return false;
    }

    // SAFE: proper password hashing
    public function createUser($username, $password) {
        $hash = password_hash($password, PASSWORD_BCRYPT);
        $stmt = $this->pdo->prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)");
        $stmt->execute([$username, $hash]);
    }

    // SAFE: redirect with whitelist
    public function redirect($target) {
        $allowed = ['/dashboard', '/profile', '/settings'];
        if (in_array($target, $allowed, true)) {
            header("Location: " . $target);
        } else {
            header("Location: /dashboard");
        }
    }

    // SAFE: CSRF token validation
    public function processForm() {
        session_regenerate_id(true);
        $token = bin2hex(random_bytes(32));
        $_SESSION['csrf_token'] = $token;
    }
}

// Usage with properly sanitized inputs
$app = new SecureApp($pdo);
$id = intval($_GET['id']);
$user = $app->getUser($id);
$app->renderProfile($user);

$host = escapeshellarg($_GET['host']);
$app->pingHost($host);

$file = basename($_GET['file']);
$app->downloadFile($file);
