<?php



include_once(dirname(__FILE__) . "../../../config/config.php");
$Structures = array_diff(scandir( "{$BasePath}Structures/Pages"), array('.', '..'));
$OverwritePath = "{$BasePath}config/Pages/{$_REQUEST['overwrite']}";
$overwritedata = json_decode(file_get_contents($OverwritePath), true);

if (isset($_REQUEST['SetStructure'])) {
    unset($_POST['SetStructure']);
    $overwritedata['Structure'] = $_POST['Structure'];
    file_put_contents($OverwritePath, json_encode($overwritedata));
    echo "Content Updated. Refresh to see changes.";

}

$ConfigItems = array_keys((array)$data);

?>
<!DOCTYPE html>
<html>
<head>

    <link rel="stylesheet"
          href="/assets/css/main<?php if (isset($_REQUEST['variation'])) echo $_REQUEST['variation']; ?>.css"/>
</head>
<body>


<form method="post" enctype="multipart/form-data">
    <select id="Structure" name="Structure">
          <?php


        foreach ($Structures as $structure) {
            $structure = substr( $structure,'0',-4);
            ?>

            <option value="<?php echo   $structure; ?>" <?php if (strcmp(  $structure, $overwritedata['Structure']) === 0) echo "selected"; ?> ><?php echo $structure; ?></option>
        <?php } ?>
    </select>
    <button type="submit" class="fit" value="Set Structure" name="SetStructure">Set Structure</button>
    <input type="hidden" name="overwrite" value="<?php echo $_REQUEST['overwrite']; ?>"/>

</form>
<script src="/assets/js/jquery.min.js"></script>
<script>
    function AddNode(node) {
        var New = prompt("Name Config Key")
        if (!New) {
            return;
        }
        if (node) {
            $(node).before($(` <div>
                <label for="Text">Config Node (${New})
                    <button type="button" onclick="$(this).parent().parent().remove()">delete</button>
                    <button type="button" class="  primary" onclick="AddNode($(this).parent().parent())">Add Config Node</button>
                </label>
                <textarea name="${New}"></textarea>
            </div>`
            ))
            return;
        }
        $('#TextNodes').append($(` <div>
                <label for="Text">Config Node (${New})
                    <button type="button" onclick="$(this).parent().parent().remove()">delete</button>
                    <button type="button" class="  primary" onclick="AddNode($(this).parent().parent())">Add Config Node</button>
                </label>
                <textarea name="${New}"></textarea>
            </div>`
        ))
    }
</script>
</body>
</html>