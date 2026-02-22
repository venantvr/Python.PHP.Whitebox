<?php
// Hardcoded secrets test: credentials in source code
$db_password = "SuperSecret123!";
$api_key = "sk-1234567890abcdef1234567890abcdef";
$aws_key = "AKIAIOSFODNN7EXAMPLE";
define("DB_PASSWORD", "root123");
$config = array(
    "secret_key" => "my_secret_key_12345",
    "api_token" => "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12",
);
