<?php
// File inclusion test: user input in include/require
$page = $_GET['page'];
include($page);
$module = $_POST['module'];
require("modules/" . $module . ".php");
$template = $_REQUEST['tpl'];
include_once($template);
