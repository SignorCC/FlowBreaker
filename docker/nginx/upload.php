<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

$max_file_size = 8000 * 1024 * 1024; // 8000 MB
$upload_dir = "/usr/share/nginx/html/uploads/";
$zipped_logs_dir = "/usr/share/nginx/html/zipped-logs/";

// Upload functionality
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["submit"])) {
    $target_file = $upload_dir . basename($_FILES["fileToUpload"]["name"]);
    $uploadOk = 1;
    $fileType = strtolower(pathinfo($target_file,PATHINFO_EXTENSION));

    // Check file size
    if ($_FILES["fileToUpload"]["size"] > $max_file_size) {
        echo "Sorry, your file is too large. Maximum size is " . ($max_file_size / 1024 / 1024) . " MB.";
        $uploadOk = 0;
    }

    // Check if $uploadOk is set to 0 by an error
    if ($uploadOk == 0) {
        echo "Sorry, your file was not uploaded.";
    // If everything is ok, try to upload file
    } else {
        if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
            echo "The file ". basename( $_FILES["fileToUpload"]["name"]). " has been uploaded.";
        } else {
            echo "Sorry, there was an error uploading your file.";
            echo "Error: " . error_get_last()['message'];
        }
    }
}

// Download functionality
if (isset($_GET['download'])) {
    $file = isset($_GET['type']) && $_GET['type'] == 'zipped' ? $zipped_logs_dir . $_GET['download'] : $upload_dir . $_GET['download'];
    if (file_exists($file)) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="'.basename($file).'"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($file));
        readfile($file);
        exit;
    }
}

// Delete functionality
if (isset($_GET['delete'])) {
    $file = isset($_GET['type']) && $_GET['type'] == 'zipped' ? $zipped_logs_dir . $_GET['delete'] : $upload_dir . $_GET['delete'];
    if (file_exists($file)) {
        unlink($file);
        echo "File deleted successfully.";
    } else {
        echo "File not found.";
    }
}

// List files
$upload_files = array_diff(scandir($upload_dir), array('.', '..'));
$zipped_logs = array_diff(scandir($zipped_logs_dir), array('.', '..'));
?>

<!DOCTYPE html>
<html>
<body>
<h2>File Upload</h2>
<form action="upload.php" method="post" enctype="multipart/form-data">
    Select file to upload (max <?php echo $max_file_size / 1024 / 1024; ?> MB):
    <input type="file" name="fileToUpload" id="fileToUpload">
    <input type="submit" value="Upload File" name="submit">
</form>

<h2>Uploaded Files</h2>
<table border="1">
    <tr>
        <th>File Name</th>
        <th>Actions</th>
    </tr>
    <?php foreach($upload_files as $file): ?>
    <tr>
        <td><?php echo $file; ?></td>
        <td>
            <a href="?download=<?php echo urlencode($file); ?>">Download</a> |
            <a href="?delete=<?php echo urlencode($file); ?>" onclick="return confirm('Are you sure you want to delete this file?');">Delete</a>
        </td>
    </tr>
    <?php endforeach; ?>
</table>

<h2>Zipped Log Files</h2>
<table border="1">
    <tr>
        <th>File Name</th>
        <th>Actions</th>
    </tr>
    <?php foreach($zipped_logs as $file): ?>
    <tr>
        <td><?php echo $file; ?></td>
        <td>
            <a href="?download=<?php echo urlencode($file); ?>&type=zipped">Download</a> |
            <a href="?delete=<?php echo urlencode($file); ?>&type=zipped" onclick="return confirm('Are you sure you want to delete this file?');">Delete</a>
        </td>
    </tr>
    <?php endforeach; ?>
</table>
</body>
</html>
