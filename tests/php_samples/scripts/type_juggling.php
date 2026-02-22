<?php
// Type juggling test: loose comparison in auth context
$token = $_GET['token'];
$valid_token = getStoredToken();
if ($token == $valid_token) {
    grantAccess();
}
$password = $_POST['password'];
$hash = getPasswordHash($user);
if ($password == $hash) {
    loginUser($user);
}
