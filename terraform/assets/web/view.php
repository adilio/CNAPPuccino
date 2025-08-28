<?php
if (isset($_GET['file'])) {
    $file = $_GET['file'];
    echo "<pre>";
    @readfile($file);
    echo "</pre>";
} else {
    echo "No file specified.";
}
?>