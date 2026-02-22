<?php
$name = $_GET['name'];
echo "<h1>Hello " . $name . "</h1>";
$msg = $_POST['message'];
print("Your message: " . $msg);
echo "Search: " . $_REQUEST['q'];
