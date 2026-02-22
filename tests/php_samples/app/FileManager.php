<?php
// Mini-app: FileManager - file upload, download, and template rendering
// Expected vulns: path_traversal (2), file_inclusion (1), insecure_upload (1), xss (1), ssrf (1)

class FileManager {
    private $uploadDir;
    private $templateDir;

    public function __construct($uploadDir, $templateDir) {
        $this->uploadDir = $uploadDir;
        $this->templateDir = $templateDir;
    }

    // VULN: Path traversal - user controls filename in read operation
    public function downloadFile($filename) {
        $path = $this->uploadDir . "/" . $filename;
        $content = file_get_contents($path);
        header("Content-Type: application/octet-stream");
        header("Content-Disposition: attachment; filename=\"" . $filename . "\"");
        echo $content;
    }

    // SAFE: basename strips directory traversal
    public function downloadFileSafe($filename) {
        $safe_name = basename($filename);
        $path = $this->uploadDir . "/" . $safe_name;
        if (file_exists($path)) {
            $content = file_get_contents($path);
            echo $content;
        }
    }

    // VULN: File inclusion via user-controlled template name
    public function renderTemplate($name) {
        $templatePath = $this->templateDir . "/" . $name . ".php";
        include($templatePath);
    }

    // VULN: Insecure upload - no validation on file type
    public function uploadAvatar() {
        $tmpFile = $_FILES['avatar']['tmp_name'];
        $destName = $_FILES['avatar']['name'];
        $dest = $this->uploadDir . "/" . $destName;
        move_uploaded_file($tmpFile, $dest);
        return $dest;
    }

    // SAFE: validated upload
    public function uploadAvatarSafe() {
        $tmpFile = $_FILES['avatar']['tmp_name'];
        $destName = $_FILES['avatar']['name'];
        $ext = strtolower(pathinfo($destName, PATHINFO_EXTENSION));
        $allowed = ['jpg', 'jpeg', 'png', 'gif'];
        if (!in_array($ext, $allowed)) {
            return false;
        }
        $safeName = bin2hex(random_bytes(16)) . "." . $ext;
        $dest = $this->uploadDir . "/" . $safeName;
        move_uploaded_file($tmpFile, $dest);
        return $dest;
    }

    // VULN: Path traversal in delete operation
    public function deleteFile($filename) {
        $path = $this->uploadDir . "/" . $filename;
        unlink($path);
    }

    // VULN: SSRF - user-provided URL fetched server-side
    public function importFromUrl($url) {
        $content = file_get_contents($url);
        $dest = $this->uploadDir . "/imported_" . time() . ".dat";
        file_put_contents($dest, $content);
        return $dest;
    }

    // VULN: XSS in file listing
    public function listFiles() {
        $search = $_GET['filter'];
        echo "<h2>Files matching: " . $search . "</h2>";
        $files = glob($this->uploadDir . "/*" . $search . "*");
        foreach ($files as $file) {
            echo "<li>" . basename($file) . "</li>";
        }
    }
}

// Usage: all methods called with tainted user input
$fm = new FileManager("/var/www/uploads", "/var/www/templates");

// Path traversal via download
$file = $_GET['file'];
$fm->downloadFile($file);

// File inclusion via template
$template = $_GET['page'];
$fm->renderTemplate($template);

// Insecure upload
$fm->uploadAvatar();

// Path traversal via delete
$toDelete = $_POST['filename'];
$fm->deleteFile($toDelete);

// SSRF via import
$importUrl = $_POST['import_url'];
$fm->importFromUrl($importUrl);

// XSS in listing
$fm->listFiles();
