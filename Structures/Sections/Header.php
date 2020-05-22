<!DOCTYPE HTML>
<html>
<head>
    <title><?= $data->SiteTextLogo ?></title>
    <meta charset="utf-8"/>
    <?php foreach ($data->MetaTags as $item) { ?>
        <meta name="<?php echo $item->Name; ?>" content="<?php echo $item->Content; ?>"/>
    <?php } ?>
    <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no"/>

    <?php
    if (isset($data->CssList)) {
        ?>

        <?php echo $data->CssList; ?>

        <?php

    }

    ?>
    <?php
    if (isset($data->CssIn)) {
        ?>
        <style>
            <?php echo $data->CssIn; ?>
        </style>
        <?php

    }

    ?>
</head>
