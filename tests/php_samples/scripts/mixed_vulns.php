<?php
// Multiple vulnerability types in one file
// SQLi
$id = $_GET['id'];
mysqli_query($conn, "DELETE FROM users WHERE id = " . $id);
// XSS
echo "User: " . $_POST['name'];
// Path traversal
$log = file_get_contents("/var/log/" . $_GET['logfile']);
// Open redirect
header("Location: " . $_GET['next']);
// Hardcoded secret
$api_key = "sk_live_abcdef123456";
