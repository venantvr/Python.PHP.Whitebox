<?php
// Open redirect test: user input in Location header
$url = $_GET['url'];
header("Location: " . $url);
$redirect = $_POST['redirect'];
header("Location: " . $redirect);
