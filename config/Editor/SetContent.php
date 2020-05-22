<?php
$Images = array_diff(scandir(dirname(__FILE__) . "/../../images"), array('.', '..'));

include_once(dirname(__FILE__) . "../../../config/config.php");
if (isset($_REQUEST['SetContent'])) {

    if (!isset($_REQUEST['Text'])) {
        $Nodes = [];
    } else {
        $Nodes = $_REQUEST['Text'];
    }
    if ($Nodes === null) {
        $Nodes = [];
    }
    $newContent = array("Text" => $Nodes);

    SetCurrentValueByDataPosition($_REQUEST['dp'], $_REQUEST['overwrite'], $newContent);
    echo "Content Updated. Refresh to see changes.";
}
if (isset($_REQUEST['Delete'])) {
    DeleteCurrentValueByDataPosition($_REQUEST['dp'], $_REQUEST['overwrite']);
    echo "Content Updated. Refresh to see changes.";
    exit;
}

if (!preg_match('/\[\]$/', $_REQUEST['dp'])) {


    $Content = GetCurrentValueByDataPosition($_REQUEST['dp'], $_REQUEST['overwrite']);
    if (!isset($Content)) {
        echo "No such Content " . $_REQUEST['dp'] . ' ' . $_REQUEST['overwrite'];
        $Content = (object)array("ImageBefore" => '', "ImageAfter" => '', "Text" => [], "SubHeader" => '');
    } else {
        $Content = (object)$Content;
    }
} else {
    $Content = (object)array("ImageBefore" => '', "ImageAfter" => '', "Text" => [], "SubHeader" => '');
}

?>
<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" type="text/css" href="styles.css">
</head>

<body data-editor="DecoupledDocumentEditor" data-collaboration="false">
<form method="post" enctype="multipart/form-data">
    <main>

        <div class="centered">
            <div class="row">
                <div class="document-editor__toolbar"></div>
            </div>
            <div class="row row-editor">
                <div class="editor">

                </div>
            </div>
        </div>
        </div>
    </main>
    <footer>
        <button id="SwitchButton" type="button" onclick="SwitchEditor()">Switch Editor to Text</button>
        <button type="submit" name="SetContent" onclick="UpdateText()">Save</button>
        <button type="submit" name="Delete">Delete this node (careful no undo)</button>
        <textarea style="display:none" name="Text[]" id="SaveText" rows="200" cols="200"><?php echo htmlentities($Content->Text[0]); ?></textarea>
        <input type="hidden" name="dp" value="<?php echo $_REQUEST['dp']; ?>"/>
        <input type="hidden" name="overwrite" value="<?php echo $_REQUEST['overwrite']; ?>"/>

    </footer>
</form>
<script src="./ckeditor.js"></script>
<script src="ckfinder/ckfinder.js"></script>
<script>
    var SwitchedEditor = false;
    function SwitchEditor(){
        SwitchedEditor = true;
        document.querySelector('#SwitchButton').remove();
        document.querySelector('#SaveText').style.display = 'block';
        document.querySelector('#SaveText').setAttribute('rows',document.querySelector('#SaveText').value.split(/\n/).length);
        document.querySelector('main').remove();
    }
    function UpdateText() {
        if(!SwitchedEditor) {
            document.querySelector('#SaveText').value = editor.getData();
        }
    }

    let config = {

        removePlugins: ['htmldataprocessor'],
        toolbar: {
            items: [

                'heading',
                '|',
                'fontSize',
                'fontFamily',
                'fontColor',
                'fontBackgroundColor',
                '|',
                'bold',
                'italic',
                'underline',
                'strikethrough',
                'highlight',
                '|',
                'alignment',
                'subscript',
                'superscript',
                '|',
                'numberedList',
                'bulletedList',
                '|',
                'indent',
                'outdent',
                '|',
                'todoList',
                'link',
                'blockQuote',
                'imageUpload',
                'insertTable',
                'mediaEmbed',
                '|',
                'undo',
                'redo',
                'CKFinder',
                'horizontalLine',
                'specialCharacters'
            ]
        },
        language: 'en',
        image: {
            toolbar: [
                'imageTextAlternative',
                'imageStyle:full',
                'imageStyle:side'
            ]
        },
        table: {
            contentToolbar: [
                'tableColumn',
                'tableRow',
                'mergeTableCells',
                'tableCellProperties',
                'tableProperties'
            ]
        },
        licenseKey: '',
        ckfinder: {
            // Upload the images to the server using the CKFinder QuickUpload command.
            uploadUrl: '/config/Editor/ckfinder/core/connector/php/connector.php?command=QuickUpload&type=Images&responseType=json&EditMode=<?php echo rawurlencode($_REQUEST['EditMode']); ?>'
        }
    };
    config.allowedContent = true;
    DecoupledDocumentEditor
        .create(document.querySelector('.editor'), config)
        .then(editor => {
            window.editor = editor;
            editor.setData(<?php echo json_encode($Content->Text[0]); ?>);
            // Set a custom container for the toolbar.
            document.querySelector('.document-editor__toolbar').appendChild(editor.ui.view.toolbar.element);
            document.querySelector('.ck-toolbar').classList.add('ck-reset_all');
        })
        .catch(error => {
            console.error('Oops, something gone wrong!');
            console.error('Please, report the following error in the https://github.com/ckeditor/ckeditor5 with the build id and the error stack trace:');
            console.warn('Build id: vv5rd1zh7ag5-k32qgio4tpas');
            console.error(error);
        });

</script>
</body>


</html>