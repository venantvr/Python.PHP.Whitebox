<?php
// LDAP injection test: user input in LDAP filter
$user = $_GET['username'];
$filter = "(uid=" . $user . ")";
$result = ldap_search($ds, "dc=example,dc=com", $filter);
