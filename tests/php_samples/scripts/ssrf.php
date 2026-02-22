<?php
// SSRF test: user input as URL for server-side requests
$url = $_GET['url'];
$content = file_get_contents($url);
echo $content;
$target = $_POST['target'];
$ch = curl_init($target);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$response = curl_exec($ch);  // SSRF: user-controlled URL
curl_close($ch);
