<?php
// Insecure deserialization test: unserialize with user input
$data = $_COOKIE['session_data'];
$obj = unserialize($data);
$payload = $_POST['payload'];
$result = unserialize(base64_decode($payload));
