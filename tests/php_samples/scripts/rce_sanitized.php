<?php
// PHP test sample: RCE properly sanitized with escapeshellarg/escapeshellcmd
// Expected: ZERO findings from the scanner
$host = escapeshellarg($_POST['host']);
$output = array();
exec("ping -c 3 " . $host, $output);  // safe: escapeshellarg applied
$file = escapeshellcmd($_GET['file']);
system("cat " . $file);  // safe: escapeshellcmd applied
