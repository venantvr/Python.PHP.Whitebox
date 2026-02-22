<?php
// Path traversal test: user input in filesystem operations
$file = $_GET['file'];
$content = file_get_contents("/uploads/" . $file);
echo $content;
$path = $_POST['path'];
$data = fopen($path, "r");
unlink("/tmp/" . $_GET['name']);
readfile($_REQUEST['doc']);
