<?php
// Taint in conditional branches
$input = $_GET['action'];
if ($input === "list") {
    $data = "safe_value";
} else {
    $data = $_GET['custom'];
}
echo $data;

$sort = isset($_GET['sort']) ? $_GET['sort'] : 'id';
$query = "SELECT * FROM items ORDER BY " . $sort;
mysqli_query($conn, $query);
