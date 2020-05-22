<header>
    <h2 data-position="SubHeaderText"><?= $data->SubHeaderText ?></h2>
</header>
<?php if (isset($data->HeaderImage)) { ?>
    <span class="image featured">
        <img class="image fit" <?php if ($EditMode) { ?> datatype="SetImage" data-position="HeaderImage" <?php } ?> src="<?= $data->HeaderImage ?>"/>
    </span>
<?php }
else{



}

?>
