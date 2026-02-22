<?php
$id = intval($_GET['id']);
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
$name = mysqli_real_escape_string($conn, $_POST['name']);
$result2 = mysqli_query($conn, "SELECT * FROM users WHERE name = '" . $name . "'");
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
$stmt->execute([$_GET['email']]);
