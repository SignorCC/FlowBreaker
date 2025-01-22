<?php
// This is a more or less basic php script, that handles uploading/downloading
// files and checks every 5s for new zipped files to show
// It provides a progressbar while uploading, an abort function and performs
// input validation on the files that can be uploaded.
session_start();
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

$max_file_size = 8000 * 1024 * 1024; // 8000 MB
$upload_dir = "/usr/share/nginx/html/uploads/";
$zipped_logs_dir = "/usr/share/nginx/html/zipped-logs/";

$message = "";

// Handle file upload
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['fileToUpload'])) {
    $target_file = $upload_dir . basename($_FILES["fileToUpload"]["name"]);
    $file_extension = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));

    // Check file size
    if ($_FILES["fileToUpload"]["size"] > $max_file_size) {
        echo json_encode(['status' => 'error', 'message' => 'File is too large.']);
        exit;
    }

    // Check file extension
    if ($file_extension != "pcap" && $file_extension != "pcapng") {
        echo json_encode(['status' => 'error', 'message' => 'Only .pcap and .pcapng files are allowed.']);
        exit;
    }

    if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
        echo json_encode(['status' => 'success', 'message' => 'File uploaded successfully. Processing might take a while']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Error uploading file.']);
    }
    exit;
}

// Handle abort request
if (isset($_GET['abort'])) {
    echo json_encode(['status' => 'success', 'message' => 'Upload aborted.']);
    exit;
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
        $message = "File deleted successfully.";
    } else {
        $message = "File not found.";
    }
}

// List files
$upload_files = array_diff(scandir($upload_dir), array('.', '..'));
$zipped_logs = array_diff(scandir($zipped_logs_dir), array('.', '..'));

// Check if it's an AJAX request for file count
if(isset($_GET['get_file_count'])) {
    echo json_encode(['count' => count($zipped_logs)]);
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Upload and Management</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f4f4f4;
        }
        h2 {
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        form {
            background-color: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        input[type="file"] {
            margin-bottom: 10px;
        }
        input[type="submit"] {
            background-color: #3498db;
            color: #fff;
            padding: 10px 15px;
            border: none;
            border-radius: 3px;
            cursor: pointer;
        }
        input[type="submit"]:hover {
            background-color: #2980b9;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background-color: #fff;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #3498db;
            color: #fff;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        a {
            color: #3498db;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        .message {
            background-color: #2ecc71;
            color: #fff;
            padding: 10px;
            border-radius: 3px;
            margin-bottom: 20px;
        }
        #progressBar {
            width: 100%;
            background-color: #ddd;
        }
        #progressBar div {
            width: 0%;
            height: 30px;
            background-color: #4CAF50;
            text-align: center;
            line-height: 30px;
            color: white;
        }
        #abortButton {
            margin-top: 10px;
            background-color: #f44336;
            color: white;
            padding: 10px 15px;
            border: none;
            border-radius: 3px;
            cursor: pointer;
        }
        #abortButton:hover {
            background-color: #d32f2f;
        }
    </style>
</head>
<body>
    <?php if ($message): ?>
    <div class="message"><?php echo $message; ?></div>
    <?php endif; ?>

    <h2>File Upload</h2>
    <form id="uploadForm" enctype="multipart/form-data">
        Select file to upload (max <?php echo $max_file_size / 1024 / 1024; ?> MB, only .pcap and .pcapng files):
        <input type="file" name="fileToUpload" id="fileToUpload" accept=".pcap,.pcapng">
        <input type="submit" value="Upload File" name="submit">
    </form>
    <div id="progressBar" style="display:none;"><div></div></div>
    <button id="abortButton" style="display:none;">Abort Upload</button>

    <h2>Uploaded Files</h2>
    <table>
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
    <table id="zippedLogsTable">
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

    <script>
    let currentFileCount = <?php echo count($zipped_logs); ?>;
    let isUploading = false;
    let xhr;

    document.getElementById('uploadForm').addEventListener('submit', function(e) {
        e.preventDefault();

        let file = document.getElementById('fileToUpload').files[0];
        if (!file) {
            alert('Please select a file to upload.');
            return;
        }

        // Check file extension
        let fileName = file.name;
        let fileExtension = fileName.split('.').pop().toLowerCase();
        if (fileExtension !== 'pcap' && fileExtension !== 'pcapng') {
            alert('Only .pcap and .pcapng files are allowed.');
            return;
        }

        let formData = new FormData();
        formData.append('fileToUpload', file);

        xhr = new XMLHttpRequest();
        xhr.open('POST', 'upload.php', true);

        xhr.upload.onprogress = function(e) {
            if (e.lengthComputable) {
                let percentComplete = (e.loaded / e.total) * 100;
                document.querySelector('#progressBar div').style.width = percentComplete + '%';
                document.querySelector('#progressBar div').textContent = percentComplete.toFixed(2) + '%';
            }
        };

        xhr.onload = function() {
            if (xhr.status === 200) {
                let response = JSON.parse(xhr.responseText);
                alert(response.message);
                location.reload();
            } else {
                alert('Upload failed. Please try again.');
            }
            isUploading = false;
            document.getElementById('progressBar').style.display = 'none';
            document.getElementById('abortButton').style.display = 'none';
        };

        xhr.onerror = function() {
            alert('Upload failed. Please try again.');
            isUploading = false;
            document.getElementById('progressBar').style.display = 'none';
            document.getElementById('abortButton').style.display = 'none';
        };

        isUploading = true;
        document.getElementById('progressBar').style.display = 'block';
        document.getElementById('abortButton').style.display = 'inline-block';
        xhr.send(formData);
    });

    document.getElementById('abortButton').addEventListener('click', function() {
        if (xhr && isUploading) {
            xhr.abort();
            fetch('upload.php?abort=' + encodeURIComponent(document.getElementById('fileToUpload').files[0].name))
                .then(response => response.json())
                .then(data => {
                    alert(data.message);
                    isUploading = false;
                    document.getElementById('progressBar').style.display = 'none';
                    document.getElementById('abortButton').style.display = 'none';
                });
        }
    });

    function checkForNewFiles() {
        if (!isUploading) {
            fetch('upload.php?get_file_count=1')
                .then(response => response.json())
                .then(data => {
                    if (data.count > currentFileCount) {
                        location.reload();
                    }
                });
        }
    }

    setInterval(checkForNewFiles, 5000); // Check every 5 seconds
    </script>
</body>
</html>
