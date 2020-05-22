<?php
$Images = array_diff(scandir(dirname(__FILE__) . "/../../images"), array('.', '..'));

include_once(dirname(__FILE__) . "../../../config/config.php");
if (isset($_REQUEST['SetContent'])) {

    SetCurrentValueByDataPosition($_REQUEST['dp'], $_REQUEST['overwrite'], $_POST);
    echo "Content Updated. Refresh to see changes.";
}


$Content = (object)GetCurrentValueByDataPosition($_REQUEST['dp'], $_REQUEST['overwrite']);


?>
<!DOCTYPE html>
<html>
<head>

    <link rel="stylesheet"
          href="/assets/css/main<?php if (isset($_REQUEST['variation'])) echo $_REQUEST['variation']; ?>.css"/>
</head>
<body>

<form method="post" enctype="multipart/form-data">
    <label for="Text">Text Node:</label>

    <textarea id="Text" rows="<?php echo count(explode("\n", $Content->Text)); ?>"
              name="Text"><?php echo htmlentities($Content->Text); ?></textarea>
    <label for="Url">Url:</label>
    <input id="Url" name="Url" type="text" value="<?php echo htmlentities($Content->Url); ?>" />

    <input type="hidden" name="dp" value="<?php echo $_REQUEST['dp']; ?>"/>
    <input type="hidden" name="overwrite" value="<?php echo $_REQUEST['overwrite']; ?>"/>

    <button type="submit" class="fit" value="Set Content" name="SetContent">Set Content</button>
</form>
<script src="/assets/js/jquery.min.js"></script>
<script>


</script>
</body>
</html>