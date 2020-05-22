<div id="myModal" class="modaxl">
    <div class="modaxl-content">
        <span class="close">&times;</span>
        <iframe id="IframeEditor" src="" class="fit" style="width:100% ;height:90%"></iframe>
    </div>

</div>
<script>
    $(document).ready(Init)
    var IframeEditor, modal;
    var Overwrite = <?php echo json_encode($overwrite); ?>;

    function ShowModal() {

        modal.style.display = "block";
    }

    function HideModal() {

        modal.style.display = "none";
    }


    function EditItem(e) {
        e.preventDefault();
        e.stopPropagation();
        var item = $(e.currentTarget);
        var dataposition = encodeURIComponent(item.attr('data-position'));

        switch (item.attr('datatype')) {
            case 'Content':
                window.open("/config/Editor/SetContent.php?overwrite=" + Overwrite + "&dp=" + dataposition,"_Editor")
                break;
            case 'ConfigEditor':
                IframeEditor.attr('src', "/config/Editor/SetConfig.php?overwrite=" + Overwrite)
                ShowModal();
                break;
            case 'Clickable':
                IframeEditor.attr('src', "/config/Editor/SetClickableContent.php?overwrite=" + Overwrite + "&dp=" + dataposition)
                ShowModal();
                break;
            case 'TextBox':
                IframeEditor.attr('src', "/config/Editor/SetTextContent.php?overwrite=" + Overwrite + "&dp=" + dataposition)
                ShowModal();
                break;
            case 'Image':
                IframeEditor.attr('src', "/config/Editor/SetImage.php?overwrite=" + Overwrite + "&dp=" + dataposition)
                ShowModal();
                break;
            default:
                IframeEditor.attr('src', "/config/Editor/SetValue.php?" + Overwrite + "&dp=" + dataposition)
                ShowModal();
        }

    }

    function Init() {
        modal = document.getElementById("myModal");
        IframeEditor = $('#IframeEditor');
        var span = document.getElementsByClassName("close")[0];
        $('.close').click(function () {
            modal.style.display = "none";
        })
        $(window).click(function (event) {
            if (event.target == modal) {
                modal.style.display = "none";
            }
        });
        $('[data-position]').click(EditItem);

    }
</script>
<style>
    .modaxl {
        display: none; /* Hidden by default */
        position: fixed; /* Stay in place */
        z-index: 1; /* Sit on top */
        left: 0;
        top: 0;
        width: 100%; /* Full width */
        height: 100%; /* Full height */
        overflow: auto; /* Enable scroll if needed */
        background-color: rgb(0, 0, 0); /* Fallback color */
        background-color: rgba(0, 0, 0, 0.4); /* Black w/ opacity */
    }

    /* Modal Content/Box */
    .modaxl-content {
        background-color: #fefefe;
        margin: 15% auto; /* 15% from the top and centered */
        padding: 20px;
        border: 1px solid #888;
        width: 80%; /* Could be more or less, depending on screen size */
        height: 100%;
    }

    /* The Close Button */
    .close {
        color: #aaa;
        float: right;
        font-size: 28px;
        font-weight: bold;
    }

    .close:hover,
    .close:focus {
        color: black;
        text-decoration: none;
        cursor: pointer;
    }
</style>