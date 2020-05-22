<?php
$Images = array_diff(scandir(dirname(__FILE__) . "/../../images"), array('.', '..'));

include_once(dirname(__FILE__) . "../../../config/config.php");
if (isset($_REQUEST['SetContent'])) {

    SetCurrentValueByDataPosition($_REQUEST['dp'], $_REQUEST['overwrite'], array("Url"=>$_REQUEST['ImageUrl'],'Alt'=>$_REQUEST['AltText']));
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
    <label for="Text">Html Node:</label>

    <label for="ImageUrl">Image Url</label>
    <select id="ImageUrl" name="ImageUrl">
         <?php foreach ($Images as $image) { ?>

            <option value="<?php echo "images/" . $image; ?>" <?php if (strcmp("images/" . $image, $Content->Url) === 0) echo "selected"; ?> ><?php echo $image; ?></option>
        <?php } ?>
    </select>
    <label for="AltText">Alt Text</label>

    <textarea id="AltText" rows="<?php echo count(explode("\n", $Content->Alt)); ?>"
              name="AltText"><?php echo htmlentities($Content->Alt); ?></textarea>
    <input type="hidden" name="dp" value="<?php echo $_REQUEST['dp']; ?>"/>
    <input type="hidden" name="overwrite" value="<?php echo $_REQUEST['overwrite']; ?>"/>

    <button type="submit" class="fit" value="Set Content" name="SetContent">Set Content</button>
</form>
<script src="/assets/js/jquery.min.js"></script>
<script>




</script>
</body>
</html>