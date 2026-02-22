<?php
// Cross-function taint: data flows through function calls
function getInput() {
    return $_GET['data'];
}
function renderOutput($content) {
    echo "<div>" . $content . "</div>";
}
$data = getInput();
renderOutput($data);

function buildQuery($table, $id) {
    return "SELECT * FROM " . $table . " WHERE id = " . $id;
}
$query = buildQuery("users", $_POST['uid']);
mysqli_query($conn, $query);
