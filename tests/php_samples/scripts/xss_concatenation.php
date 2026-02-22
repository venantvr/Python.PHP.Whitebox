<?php
// XSS through string concatenation and interpolation
$user = $_GET['user'];
$msg = "Welcome, " . $user;
$output = "<div class='greeting'>" . $msg . "</div>";
echo $output;
$comment = $_POST['comment'];
echo "<p>$comment</p>";
echo "Last search: {$_GET['q']}";
