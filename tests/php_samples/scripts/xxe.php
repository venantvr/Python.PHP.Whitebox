<?php
// XXE test: XML parsing with user input without entity protection
$xml = $_POST['xml'];
$doc = new DOMDocument();
$doc->loadXML($xml);
$data = simplexml_load_string($_POST['data']);
