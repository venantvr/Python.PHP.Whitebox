<?php
// Insecure file upload test: no validation on uploaded files
$target = "uploads/" . $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], $target);
$ext = pathinfo($_FILES['avatar']['name'], PATHINFO_EXTENSION);
$dest = "images/" . $_FILES['avatar']['name'];
move_uploaded_file($_FILES['avatar']['tmp_name'], $dest);
