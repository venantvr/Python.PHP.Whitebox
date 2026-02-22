<?php
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
$name = $_POST['name'];
$result2 = mysqli_query($conn, "SELECT * FROM users WHERE name = '" . $name . "'");
