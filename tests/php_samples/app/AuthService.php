<?php
// Mini-app: AuthService - handles authentication logic
// Expected vulns: sql_injection (1), type_juggling (pattern), hardcoded_secrets (pattern), crypto_weakness (pattern)

class AuthService {
    private $db;
    private $secret_key = "s3cr3t_k3y_h4rdc0d3d_123";

    public function __construct($db) {
        $this->db = $db;
    }

    // VULN: SQL injection via login - classic auth bypass
    public function login($username, $password) {
        $query = "SELECT * FROM users WHERE username = '" . $username . "' AND password = '" . $password . "'";
        $result = mysqli_query($this->db, $query);
        $user = mysqli_fetch_assoc($result);
        if ($user) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['role'] = $user['role'];
            return true;
        }
        return false;
    }

    // SAFE: login with prepared statement (this is just pattern, not actual PDO)
    public function loginSafe($username, $password) {
        $stmt = $this->db->prepare("SELECT * FROM users WHERE username = ? AND password_hash = ?");
        $hash = password_hash($password, PASSWORD_BCRYPT);
        $stmt->execute([$username, $hash]);
        return $stmt->fetch();
    }

    // VULN (pattern): weak crypto for password storage
    public function hashPassword($password) {
        return md5($password);
    }

    // VULN (pattern): type juggling in admin check
    public function isAdmin($user) {
        if ($user['role'] == 'admin') {
            return true;
        }
        return false;
    }

    // SAFE: strict comparison
    public function isAdminSafe($user) {
        if ($user['role'] === 'admin') {
            return true;
        }
        return false;
    }

    // Method that passes tainted data through multiple layers
    public function processToken($token) {
        $decoded = base64_decode($token);
        $parts = explode(':', $decoded);
        return $parts;
    }

    // VULN: uses tainted token in query
    public function validateToken($token) {
        $parts = $this->processToken($token);
        $userId = $parts[0];
        $query = "SELECT * FROM sessions WHERE user_id = " . $userId;
        mysqli_query($this->db, $query);
    }
}

// Usage scenario: tainted inputs from login form
$auth = new AuthService($conn);

$username = $_POST['username'];
$password = $_POST['password'];
$auth->login($username, $password);

// Tainted token from cookie
$token = $_COOKIE['auth_token'];
$auth->validateToken($token);
