<?php

if (  isset($_FILES['UploadImage'])) {
    $fileError = $_FILES["UploadImage"]["error"]; // where FILE_NAME is the name attribute of the file input in your form
    switch($fileError) {
        case UPLOAD_ERR_INI_SIZE:
            echo "File too big";
            // Exceeds max size in php.ini
            exit;
        case UPLOAD_ERR_PARTIAL:
            echo "File too big  in html" ;
            // Exceeds max size in html form
            exit;
        case UPLOAD_ERR_NO_FILE:
            echo "No file?";
            // No file was uploaded
            exit;
        case UPLOAD_ERR_NO_TMP_DIR:
            echo "No tmp dir";
            // No /tmp dir to write to
            exit;
        case UPLOAD_ERR_CANT_WRITE:
            echo "can't write to tmp.. maybe full if this is new error. ";
            // Error writing to disk
            exit;
        default:
            // No error was faced! Phew!
            break;
    }
    $target_dir = dirname(__FILE__)."/../../images/";
    $target_file = $target_dir . basename($_FILES["UploadImage"]["name"]);
    $uploadOk = 1;
    $imageFileType = strtolower(pathinfo($target_file,PATHINFO_EXTENSION));
    if (move_uploaded_file($_FILES["UploadImage"]["tmp_name"], $target_file)) {
        if(!isset($_REQUEST['json'])) {
            echo "The file " . basename($_FILES["UploadImage"]["name"]) . " has been uploaded.";
        }else{
            echo json_encode(array("file"=>"/images/".basename($_FILES["UploadImage"]["name"])));
        }
    } else {
        echo "Sorry, there was an error uploading your file.";
    }
}
?><!DOCTYPE html>
<html>
<head>

    <link rel="stylesheet"
          href="/assets/css/main<?php if (isset($_REQUEST['variation'])) echo $_REQUEST['variation']; ?>.css"/>
</head>
<body>

<form  method="post" enctype="multipart/form-data">
    Select image to upload:
    <input type="file" name="UploadImage" id="fileToUpload">
    <input type="submit" value="Upload Image" name="submit">
</form>

</body>
</html>