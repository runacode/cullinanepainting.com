<?php
global $visitor;
include(dirname(__FILE__) . "/config/config.php");
include("haggle/main.php");

$Country = "unset";
if (isset($visitor) && isset($visitor['ip']) && isset($visitor['ip']['country_geoname_name'])) {
    if (isset($_REQUEST['DUMP']) ) {
        ?>
        <pre>
    <?php print_r($visitor); ?>
</pre>

        <?php
        exit;
    }
    $Country = $visitor['ip']['country_geoname_name'];
    $keys = array_keys((array)$data);
    foreach ($keys as $key) {

        if (is_string($data->$key)) {
            $test = "|$Country";
            if (endswith($key, $test)) {

                $property = substr($key, 0, strlen($key) - strlen($test));
                if (property_exists($data, $property)) {
                    $data->$property = $data->$key;
                }
            }
        }
    }
}


include("{$BasePath}/config/editmode.php");
include("{$BasePath}Structures/Sections/Header.php");
?>
<body>

<?php
$PageStructure = "{$BasePath}Structures/Pages/" . $data->Structure . ".php";
if (isset($data->Structure) && file_exists($PageStructure)) {
    include($PageStructure);
} else {
    include("{$BasePath}Structures/Pages/NoSideBar.php");
}

?>


</body>
<?php
if ($EditMode) {
    ?>
    <a href="#" style="position: absolute ;top:55px ;left 10px;z-index:10000"
       datatype="ConfigEditor"
       data-position="SiteTextLogo"
    >Edit</a>
<?php } ?>

<?php include("{$BasePath}Structures/Sections/Scripts.php"); ?>
<script>
    var IsClicked = false;

    function RE(e) {
        IsClicked = true;
        var href = e.currentTarget.getAttribute('href');
        if (!href) {
            href = "no link on a tag"
        }
        $.ajax({
            url: '/e/',
            method: 'post',
            data: {link: href}
        });

    }

    $(document).ready(function () {
        $('a').click(RE);
    })
    window.onbeforeunload = function () {
        if (IsClicked) return;
        $.ajax({
            url: '/e/',
            method: 'post',
            data: {link: "Page Closed"}
        });
    }
</script>
