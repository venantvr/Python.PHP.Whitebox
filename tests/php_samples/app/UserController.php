<?php
// Mini-app: UserController - handles user CRUD operations
// Expected vulns: sql_injection (2), xss (2), open_redirect (1)

class UserController {
    private $db;
    private $templateEngine;

    public function __construct($db) {
        $this->db = $db;
    }

    // VULN: SQL injection via unsanitized parameter in query
    public function getUser($id) {
        $query = "SELECT * FROM users WHERE id = " . $id;
        $result = mysqli_query($this->db, $query);
        return mysqli_fetch_assoc($result);
    }

    // VULN: XSS - user input echoed without encoding
    public function renderProfile($user) {
        echo "<h1>Profile: " . $user['name'] . "</h1>";
        echo "<p>Bio: " . $user['bio'] . "</p>";
    }

    // SAFE: properly parameterized
    public function getUserSafe($id) {
        $id = intval($id);
        $query = "SELECT * FROM users WHERE id = " . $id;
        return mysqli_query($this->db, $query);
    }

    // VULN: SQL injection through string building across methods
    public function searchUsers($keyword) {
        $term = trim($keyword);
        $term = strtolower($term);
        $query = $this->buildSearchQuery($term);
        mysqli_query($this->db, $query);
    }

    private function buildSearchQuery($term) {
        return "SELECT * FROM users WHERE name LIKE '%" . $term . "%'";
    }

    // VULN: Open redirect via unvalidated redirect target
    public function logout() {
        $redirect = $_GET['redirect_url'];
        session_destroy();
        header("Location: " . $redirect);
    }

    // SAFE: redirect to whitelist
    public function logoutSafe() {
        $allowed = ['/login', '/home', '/'];
        $target = $_GET['redirect_url'];
        if (in_array($target, $allowed)) {
            header("Location: " . $target);
        } else {
            header("Location: /login");
        }
    }
}

// Usage: controller receives tainted input from request
$controller = new UserController($conn);

// Tainted $id flows into getUser -> SQL injection
$id = $_GET['user_id'];
$user = $controller->getUser($id);

// Tainted data rendered -> XSS
$controller->renderProfile($user);

// Tainted keyword flows through searchUsers -> SQL injection
$keyword = $_POST['search'];
$controller->searchUsers($keyword);

// Logout with open redirect
$controller->logout();
