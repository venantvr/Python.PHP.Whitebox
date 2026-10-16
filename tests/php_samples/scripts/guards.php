<?php
// Validation guards in conditions must neutralize taint path-sensitively.

// SAFE: early exit on failed validation
$id = $_GET['id'];
if (!is_numeric($id)) {
    die('bad id');
}
mysqli_query($conn, "SELECT * FROM t WHERE id = " . $id);

// SAFE: whitelist via in_array
$sort = $_GET['sort'];
$allowed = ['name', 'date', 'id'];
if (in_array($sort, $allowed, true)) {
    mysqli_query($conn, "SELECT * FROM t ORDER BY " . $sort);
} else {
    mysqli_query($conn, "SELECT * FROM t ORDER BY id");
}

// VULN: validation only in else branch, sink in then branch
$page = $_GET['page'];
if (ctype_digit($page)) {
    $p = (int) $page;
} else {
    include "pages/" . $page . ".php";
}

// SAFE: strict anchored regex
$slug = $_GET['slug'];
if (!preg_match('/^[a-z0-9_-]+$/', $slug)) {
    exit;
}
readfile("/var/www/pages/" . $slug);

// VULN: non-anchored / wildcard regex does not sanitize
$file = $_GET['file'];
if (preg_match('/\.txt$/', $file)) {
    readfile("/var/www/files/" . $file);
}

// SAFE: literal comparison
$action = $_POST['action'];
if ($action === 'list') {
    system("ls " . $action);
}

// SAFE: arithmetic yields a number
$offset = $_GET['offset'] + 0;
mysqli_query($conn, "SELECT * FROM t LIMIT " . $offset);

// SAFE: whitelist lookup with isset()
$map = ['a' => 'alpha.php', 'b' => 'beta.php'];
$k = $_GET['k'];
if (isset($map[$k])) {
    include $map[$k];
    echo $k;
}

// SAFE: filter_var with validating flag ; VULN: filter_var without flag
$n = filter_var($_GET['n'], FILTER_VALIDATE_INT);
mysqli_query($conn, "SELECT * FROM t WHERE n = " . $n);
$raw = filter_var($_GET['raw']);
mysqli_query($conn, "SELECT * FROM t WHERE r = '" . $raw . "'");

// SAFE: preg_match with strict regex captures digits only
if (preg_match('/^(\d+)$/', $_GET['num'], $m)) {
    mysqli_query($conn, "SELECT * FROM t WHERE n = " . $m[1]);
}

// VULN: htmlspecialchars on one operand does not protect the other
echo "<a href='" . htmlspecialchars($_GET['u']) . "'>" . $_GET['label'] . "</a>";

// SAFE: $_SERVER keys not under client control ; VULN: HTTP_ headers are
echo $_SERVER['DOCUMENT_ROOT'];
echo $_SERVER['HTTP_USER_AGENT'];

// VULN: weak sanitizer keeps a low-confidence finding
$name = addslashes($_POST['name']);
mysqli_query($conn, "SELECT * FROM t WHERE name = " . $name);
