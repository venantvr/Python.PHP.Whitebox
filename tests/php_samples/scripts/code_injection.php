<?php
// Code injection test: dynamic code execution with user input
$code = $_GET['code'];
$func = $_POST['func'];
$callback = create_function('$a', $func);
$pattern = $_GET['pattern'];
$result = preg_replace('/' . $pattern . '/e', '$1', $input);
