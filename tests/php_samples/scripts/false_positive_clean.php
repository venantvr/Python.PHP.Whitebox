<?php
// Clean file: all user input properly sanitized - should produce ZERO findings
$id = intval($_GET['id']);
$name = htmlspecialchars($_POST['name'], ENT_QUOTES, 'UTF-8');
echo "<h1>Hello " . $name . "</h1>";
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
$host = escapeshellarg($_GET['host']);
system("ping " . $host);
$stmt = $pdo->prepare("SELECT * FROM items WHERE category = ?");
$stmt->execute([$_GET['cat']]);
echo htmlentities($_REQUEST['msg']);
session_regenerate_id(true);
$hash = password_hash($password, PASSWORD_BCRYPT);
