<?php
$PagesPath = $_SERVER['DOCUMENT_ROOT'] . '/config/Pages/';

if (isset($_REQUEST['Replace'])) {
    $DataToCopy = file_get_contents("$PagesPath{$_REQUEST['overwrite']}");

    $dta = json_decode($DataToCopy, true);
    function Replace_String(&$item, $key)
    {
        if (is_string($item)) {
            $item = str_replace($_REQUEST['Search'], $_REQUEST['Replace'], $item);
        }
    }

    array_walk_recursive($dta, 'Replace_String');
    file_put_contents("$PagesPath{$_REQUEST['overwrite']}",json_encode($dta));

}

?><!DOCTYPE html>
<html>
<head>

    <link rel="stylesheet"
          href="/assets/css/main<?php if (isset($_REQUEST['variation'])) echo $_REQUEST['variation']; ?>.css"/>
</head>
<body>

<form method="post" enctype="multipart/form-data" class="form">
    <p><?php echo $_SERVER['DOCUMENT_ROOT']; ?> </p>
    <label for="Search">Search</label>
    <input type="text" name="Search" id="Search">
    <label for="Replace">Replace</label>
    <input type="text" name="Replace" id="Replace">
    <input type="hidden" name="overwrite" value="<?php echo $_REQUEST['overwrite']; ?>"/>




    <input type="submit" value="Replace Page" name="Clone">

</form>

</body>
</html>
