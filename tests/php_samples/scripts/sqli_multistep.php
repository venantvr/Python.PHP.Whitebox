<?php
// Multi-step SQL injection: taint flows through variable assignments
$raw = $_POST['search'];
$trimmed = trim($raw);
$lower = strtolower($trimmed);
$query = "SELECT * FROM products WHERE name LIKE '%" . $lower . "%'";
$result = mysqli_query($conn, $query);
