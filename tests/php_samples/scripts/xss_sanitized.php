<?php
$name = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
echo "<h1>Hello " . $name . "</h1>";
$msg = htmlentities($_POST['message']);
print("Your message: " . $msg);
echo "Search: " . strip_tags($_REQUEST['q']);
