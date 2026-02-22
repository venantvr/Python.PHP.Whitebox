<?php
// Session fixation test: user input sets session ID
$sid = $_GET['sid'];
session_id($sid);
session_start();
