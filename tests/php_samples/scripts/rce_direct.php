<?php
// RCE test: user input reaching OS command functions
$cmd = $_GET['cmd'];
system($cmd);
$host = $_POST['host'];
$output = array();
exec("ping -c 3 " . $host, $output);
$file = $_GET['file'];
passthru("cat " . $file);
$input = $_REQUEST['data'];
$result = shell_exec("echo " . $input);
