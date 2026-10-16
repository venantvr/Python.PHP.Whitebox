<?php
// Inter-procedural flows: parameters reaching sinks, return propagation, class properties.

function run_query($db, $sql) {
    return mysqli_query($db, $sql);              // sink reached via param #1
}

function build_sql($table, $id) {
    return "SELECT * FROM " . $table . " WHERE id = " . $id;
}

function clean_int($v) {
    return intval($v);
}

function sanitize_name($v) {
    return preg_replace('/[^a-z]/', '', $v);
}

class Repo {
    private $db;
    private $term;

    public function __construct($db) {
        $this->db = $db;
    }

    public function find($id) {
        $sql = "SELECT * FROM users WHERE id = " . $id;
        return mysqli_query($this->db, $sql);    // VULN via Repo::find() call below
    }

    public function findSafe($id) {
        $id = (int) $id;
        return mysqli_query($this->db, "SELECT * FROM users WHERE id = " . $id);   // SAFE
    }

    public function setTerm() {
        $this->term = $_GET['term'];
    }

    public function search() {
        return mysqli_query($this->db, "SELECT * FROM users WHERE name = '" . $this->term . "'");   // VULN via property
    }

    public static function render($html) {
        echo $html;                              // VULN via static call below
    }
}

// VULN: tainted argument reaches sink inside run_query()
run_query($conn, "SELECT * FROM t WHERE x = " . $_GET['x']);

// VULN: return value of build_sql carries taint of $id argument
$sql = build_sql("users", $_POST['id']);
mysqli_query($conn, $sql);

// SAFE: build_sql result built from an intval'd argument
$sql2 = build_sql("users", clean_int($_POST['id']));
mysqli_query($conn, $sql2);

// SAFE: user-defined sanitizer
$safe = sanitize_name($_GET['n']);
mysqli_query($conn, "SELECT * FROM t WHERE n = '" . $safe . "'");

$repo = new Repo($conn);
$repo->find($_GET['id']);          // VULN (sink inside Repo::find)
$repo->findSafe($_GET['id']);      // SAFE
$repo->setTerm();
$repo->search();
Repo::render($_POST['html']);      // VULN (sink inside Repo::render)

// Closures capturing tainted variables
$input = $_GET['cmd'];
$runner = function () use ($input) {
    system($input);                // VULN
};
$runner();
$fmt = fn($x) => $x . $input;
echo $fmt('cmd: ');                // VULN xss via arrow fn capture

// Dedup: loops must not duplicate findings
for ($i = 0; $i < 3; $i++) {
    echo $_GET['loop'];            // VULN once
}

// Backticks and dynamic calls
$host = $_GET['host'];
$out = `ping -c 1 $host`;          // VULN rce
$cls = $_GET['cls'];
$obj = new $cls();                 // VULN code_injection

// extract / parse_str
extract($_POST);                   // VULN variable_overwrite
parse_str($_SERVER['QUERY_STRING']);  // VULN variable_overwrite
parse_str($_SERVER['QUERY_STRING'], $out2);  // SAFE

// XPath
$xp = new DOMXPath($doc);
$xp->query("//user[name='" . $_GET['u'] . "']");   // VULN xpath_injection

// Object injection guarded by allowed_classes
unserialize($_COOKIE['c'], ['allowed_classes' => false]);   // SAFE
