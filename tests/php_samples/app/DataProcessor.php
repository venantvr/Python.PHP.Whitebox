<?php
// Mini-app: DataProcessor - complex data flows with multiple transformations
// Expected vulns: sql_injection (1), xss (2), ldap_injection (1), session_fixation (1)

class DataProcessor {
    private $db;
    private $config;

    public function __construct($db, $config) {
        $this->db = $db;
        $this->config = $config;
    }

    // Complex multi-step taint: input -> trim -> lower -> substr -> concat -> sink
    // VULN: sql_injection through chain of propagators
    public function processAndStore($input) {
        $cleaned = trim($input);
        $normalized = strtolower($cleaned);
        $truncated = substr($normalized, 0, 100);
        $formatted = sprintf("('%s')", $truncated);
        $query = "INSERT INTO data_log (entry) VALUES " . $formatted;
        mysqli_query($this->db, $query);
    }

    // VULN: XSS via heredoc string interpolation
    public function renderDashboard($username) {
        $greeting = "Welcome back, " . $username;
        echo <<<HTML
        <div class="dashboard">
            <h1>{$greeting}</h1>
            <p>Your dashboard is ready.</p>
        </div>
HTML;
    }

    // Ternary operator with taint on one branch
    // VULN: XSS - taint propagates through ternary
    public function displayMessage() {
        $msg = isset($_GET['msg']) ? $_GET['msg'] : 'default message';
        echo "<p>" . $msg . "</p>";
    }

    // VULN: LDAP injection via user input
    public function lookupUser($username) {
        $filter = "(uid=" . $username . ")";
        $result = ldap_search($ldapConn, "dc=example,dc=com", $filter);
        return ldap_get_entries($ldapConn, $result);
    }

    // VULN: Session fixation
    public function setSessionFromInput() {
        $sid = $_GET['session_id'];
        session_id($sid);
        session_start();
    }

    // Augmented assignment with taint: $x .= tainted
    public function buildReport() {
        $html = "<html><body>";
        $title = $_POST['report_title'];
        $html .= "<h1>" . $title . "</h1>";
        // $html is now tainted via augmented assignment
        echo $html;
    }

    // Array creation with mixed tainted/clean values
    public function processFormData() {
        $data = [
            'name' => $_POST['name'],
            'email' => $_POST['email'],
            'role' => 'user',
            'created' => date('Y-m-d'),
        ];
        // The whole array is tainted because name and email are tainted
        $query = "INSERT INTO users (name, email) VALUES ('" . $data['name'] . "', '" . $data['email'] . "')";
        mysqli_query($this->db, $query);
    }

    // Switch statement with taint in multiple cases
    public function handleAction() {
        $action = $_GET['action'];
        $output = "";
        switch ($action) {
            case 'greet':
                $output = "Hello, " . $_GET['name'];
                break;
            case 'search':
                $output = "Results for: " . $_GET['q'];
                break;
            default:
                $output = "Unknown action: " . $action;
        }
        // All branches produce tainted output
        echo $output;
    }
}

// Usage: full lifecycle with tainted user inputs
$processor = new DataProcessor($conn, []);

// Multi-step propagation to SQL
$userInput = $_POST['data'];
$processor->processAndStore($userInput);

// XSS via method call with tainted param
$name = $_GET['username'];
$processor->renderDashboard($name);

// Ternary taint
$processor->displayMessage();

// LDAP injection
$ldapUser = $_POST['ldap_user'];
$processor->lookupUser($ldapUser);

// Session fixation
$processor->setSessionFromInput();
