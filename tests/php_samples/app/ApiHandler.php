<?php
// Mini-app: ApiHandler - REST API with JSON processing
// Expected vulns: sql_injection (2), xss (1), rce (1), insecure_deserialization (1), xxe (1)

class ApiHandler {
    private $db;

    public function __construct($db) {
        $this->db = $db;
    }

    // Route dispatcher
    public function handleRequest() {
        $action = $_GET['action'];
        $data = $_POST;

        switch ($action) {
            case 'get_user':
                return $this->getUser($data);
            case 'search':
                return $this->search($data);
            case 'export':
                return $this->exportData($data);
            case 'import_xml':
                return $this->importXml($data);
            case 'run_report':
                return $this->runReport($data);
        }
    }

    // VULN: SQL injection - user data in WHERE clause
    private function getUser($data) {
        $userId = $data['user_id'];
        $query = "SELECT username, email FROM users WHERE id = " . $userId;
        $result = mysqli_query($this->db, $query);
        $user = mysqli_fetch_assoc($result);
        return json_encode($user);
    }

    // VULN: SQL injection - ORDER BY injection
    private function search($data) {
        $term = $data['q'];
        $orderBy = $data['sort'];
        $safeterm = mysqli_real_escape_string($this->db, $term);
        // term is sanitized but orderBy is NOT
        $query = "SELECT * FROM products WHERE name LIKE '%" . $safeterm . "%' ORDER BY " . $orderBy;
        $result = mysqli_query($this->db, $query);
        $rows = [];
        while ($row = mysqli_fetch_assoc($result)) {
            $rows[] = $row;
        }
        return json_encode($rows);
    }

    // VULN: Insecure deserialization from user input
    private function exportData($data) {
        $config = $data['export_config'];
        $options = unserialize($config);
        return $this->generateExport($options);
    }

    private function generateExport($options) {
        // Process export options...
        return "export_done";
    }

    // VULN: XXE via XML parsing without disabling entities
    private function importXml($data) {
        $xmlString = $data['xml_content'];
        $doc = new DOMDocument();
        $doc->loadXML($xmlString);
        $items = $doc->getElementsByTagName('item');
        $count = 0;
        foreach ($items as $item) {
            $name = $item->nodeValue;
            // Process item...
            $count++;
        }
        return json_encode(['imported' => $count]);
    }

    // VULN: RCE via unsanitized report name in command
    // Using shell_exec with tainted input
    private function runReport($data) {
        $reportName = $data['report'];
        $cmd = "php /var/www/reports/" . $reportName . ".php";
        $output = shell_exec($cmd);
        return $output;
    }

    // VULN: XSS in error response
    public function handleError($message) {
        echo "<div class='error'>Error: " . $message . "</div>";
    }

    // Middleware: logs request with tainted data
    public function logRequest() {
        $ip = $_SERVER['REMOTE_ADDR'];
        $uri = $_SERVER['REQUEST_URI'];
        $method = $_SERVER['REQUEST_METHOD'];
        $logLine = "[{$method}] {$uri} from {$ip}";
        file_put_contents("/var/log/api.log", $logLine . "\n", FILE_APPEND);
    }
}

// Usage: full request lifecycle
$api = new ApiHandler($conn);
$api->logRequest();

// Dispatch based on action - all paths lead to vulns
$response = $api->handleRequest();

// Error handling with tainted message
$errorMsg = $_GET['error'];
if ($errorMsg) {
    $api->handleError($errorMsg);
}
