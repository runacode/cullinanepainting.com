<?php
$Images = array_diff(scandir(dirname(__FILE__) . "/../../images"), array('.', '..'));

include_once(dirname(__FILE__) . "../../../config/config.php");
if (isset($_REQUEST['SetContent'])) {

    SetCurrentValueByDataPosition($_REQUEST['dp'], $_REQUEST['overwrite'], $_REQUEST['Text']);
    echo "Content Updated. Refresh to see changes.";
}


$Content = GetCurrentValueByDataPosition($_REQUEST['dp'], $_REQUEST['overwrite']);


?>
<!DOCTYPE html>
<html>
<head>

    <link rel="stylesheet"
          href="/assets/css/main<?php if (isset($_REQUEST['variation'])) echo $_REQUEST['variation']; ?>.css"/>
</head>
<body>

<form method="post" enctype="multipart/form-data">
    <label for="Text">Html Node:</label>

    <textarea id="Text" rows="<?php echo count(explode("\n", $Content)); ?>"
              name="Text"><?php echo htmlentities($Content); ?></textarea>

    <input type="hidden" name="dp" value="<?php echo $_REQUEST['dp']; ?>"/>
    <input type="hidden" name="overwrite" value="<?php echo $_REQUEST['overwrite']; ?>"/>

    <button type="submit" class="fit" value="Set Content" name="SetContent">Set Content</button>
</form>
<script src="/assets/js/jquery.min.js"></script>
<script>




</script>
</body>
</html>