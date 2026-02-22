<?php
// Taint propagation through foreach loops
$items = $_POST['items'];
foreach ($items as $item) {
    echo "<li>" . $item . "</li>";
}
$params = $_GET;
foreach ($params as $key => $value) {
    $query = "SELECT * FROM data WHERE " . $key . " = '" . $value . "'";
    mysqli_query($conn, $query);
}
