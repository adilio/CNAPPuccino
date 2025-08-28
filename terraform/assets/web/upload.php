<?php
if (isset($_POST['submit'])) {
    $target_dir = "/var/www/html/uploads/";
    $target_file = $target_dir . basename($_FILES["file"]["name"]);
    
    if (!is_dir($target_dir)) {
        mkdir($target_dir, 0755, true);
    }
    
    // No validation - completely insecure!
    if (move_uploaded_file($_FILES["file"]["tmp_name"], $target_file)) {
        echo "File uploaded: <a href='/uploads/" . basename($_FILES["file"]["name"]) . "'>" . $target_file . "</a>";
    } else {
        echo "Upload failed.";
    }
}
?>
<!DOCTYPE html>
<html>
<head><title>Vulnerable File Upload</title></head>
<body>
    <h2>CNAPPuccino File Upload (No Restrictions!)</h2>
    <form action="upload.php" method="post" enctype="multipart/form-data">
        <input type="file" name="file">
        <input type="submit" value="Upload" name="submit">
    </form>
    <p><strong>Warning:</strong> This upload has no security restrictions!</p>
</body>
</html>