<?php
$Images = array_diff(scandir(dirname(__FILE__) . "/../../images"), array('.', '..'));

include_once(dirname(__FILE__) . "../../../config/config.php");

$OverwritePath = "{$BasePath}config/Pages/{$_REQUEST['overwrite']}";
$overwritedata = json_decode(file_get_contents($OverwritePath), true);

if (isset($_REQUEST['SetContent'])) {

    $newContent = $overwritedata[$_REQUEST['ContentPlace']] ;

    $appended =array_merge($newContent,json_decode($_REQUEST['json'],true));
    unset($_REQUEST['Text']);


    SetCurrentValueByDataPosition($_REQUEST['ContentPlace']  , $_REQUEST['overwrite'], $appended);
    echo "Content Updated. Refresh to see changes.";
    exit;
}


?>
<!DOCTYPE html>
<html>
<head>

    <link rel="stylesheet"
          href="/assets/css/main<?php if (isset($_REQUEST['variation'])) echo $_REQUEST['variation']; ?>.css"/>
</head>
<body>

<form method="post" enctype="multipart/form-data" onsubmit="Import()">


    <div>
        <label for="Text">Import, no surrounding element.


        </label>
        <textarea id="Importer" rows="10"
                  name="Text"></textarea>
    </div>

    <button type="button" onclick="Read()">Read</button>
    <pre id="preview">

        </pre>
    <select name="ContentPlace">
        <option value="ContentIndex1">Content 1 (usually above)</option>
        <option value="ContentIndex2">Content 2 (usually left)</option>
        <option value="ContentIndex3">Content 3 (usually right)</option>
        <option value="ContentIndex4">Content 4 (usually below)</option>
    </select>



    <input type="hidden" name="dp" value="<?php echo $_REQUEST['dp']; ?>"/>
    <input type="hidden" name="overwrite" value="<?php echo $_REQUEST['overwrite']; ?>"/>
    <input name="json" type="text" value=""/>
    <button type="submit" class="fit" value="Set Content" name="SetContent">Import</button>
</form>
<script src="/assets/js/jquery.min.js"></script>
<script>
    function Read() {
        try {

            var doc = document.createElement('div')
            doc.innerHTML = $('#Importer').val()
            var count = "Count : " + doc.childElementCount;
            var items = Array.prototype.slice.call(doc.children).map(a => {
                return {Text: [a.outerHTML]}
            })
            $('#preview').text(count + JSON.stringify(items, null, ' '))
            $('[name="json"]').val(JSON.stringify(items));
        } catch (e) {
            alert(e.message);
        }
    }

    function Import() {
        try {

            var doc = document.createElement('div')
            doc.innerHTML = $('#Importer').val()

            var items = Array.prototype.slice.call(doc.children).map(a => {
                return {Text: [a.outerHTML]}
            })
            $('[name="json"]').val(JSON.stringify(items));

        } catch (e) {
            alert(e.message);

        }
    }
</script>
</body>
</html>