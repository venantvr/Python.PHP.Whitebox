<?php
// Weak cryptography test: insecure hash/random functions
$hash = md5($password);
$token = sha1($secret);
$iv = "1234567890123456";
$random = rand(0, 999999);
$bytes = mt_rand(0, PHP_INT_MAX);
