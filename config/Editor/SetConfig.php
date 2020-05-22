<?php


include_once(dirname(__FILE__) . "../../../config/config.php");
$configData = json_decode(file_get_contents($ConfigFilePath), true);
if (isset($_REQUEST['Json'])) {


    file_put_contents($ConfigFilePath, $_REQUEST['Json']);

    echo "Content Updated. Refresh to see changes.";
    exit;
}


?>
<!DOCTYPE html>
<html>
<head>


    <link href="/dist/jsoneditor.min.css" rel="stylesheet" type="text/css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jsoneditor/8.6.4/jsoneditor.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/jsoneditor/8.6.4/jsoneditor.min.css" rel="stylesheet"
          type="text/css">

</head>
<body>
<a href="ImportContent.php?overwrite=<?php echo $_REQUEST['overwrite']; ?>">Html Parser</a> - <a
    href="SetStructure.php?overwrite=<?php echo $_REQUEST['overwrite']; ?>">Structure Editor</a> - <a
    href="UploadImage.php?overwrite=<?php echo $_REQUEST['overwrite']; ?>">Image Uploader</a> - <a
    href="ClonePage.php?overwrite=<?php echo $_REQUEST['overwrite']; ?>">Page Creator</a> - <a
    href="SearchReplace.php?overwrite=<?php echo $_REQUEST['overwrite']; ?>">Search/replace </a>  - <a
    href="SetOverwriteData.php?overwrite=<?php echo $_REQUEST['overwrite']; ?>"> Edit Page Data </a>

<button type="button" class="Save" value="Save">Save</button>
<div id="jsoneditor"></div>
<button type="button" class="Save" value="Save">Save</button>
<script src="/assets/js/jquery.min.js"></script>
<script>
    var editor;
    $(document).ready(LoadJsonEditor);

    function LoadJsonEditor(e) {
        editor = new JSONEditor(document.getElementById('jsoneditor'))
        editor.set(<?php echo json_encode($configData); ?>);
        $('.Save').click(SaveJson);

    }

    function SaveJson() {
        $.ajax({
                'url': 'SetConfig.php',
                data: "Json=" + encodeURIComponent(editor.getText()),
                method: 'POST',
                success(a) {
                    alert(a);
                }
            }
        )
    }
</script>
</body>
</html>