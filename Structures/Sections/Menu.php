<h1 id="logo">
    <a href="/" <?php if ($EditMode) { ?>
        datatype="ConfigEditor"
        data-position="SiteTextLogo" <?php } ?>><?= $data->SiteTextLogo ?></a>
    <a href="<?php echo  $data->LoginTextButton->Url; ?>" <?php if ($EditMode) { ?>
        datatype="Clickable"
        data-position="LoginTextButton" <?php } ?> class="FloatRight NavMenu"><?= $data->LoginTextButton->Text ?></a>
    <a href="<?php echo  $data->MenuCartText->Url; ?>" <?php if ($EditMode) { ?>
        datatype="Clickable"
        data-position="MenuCartText" <?php } ?> class="FloatRight NavMenu"><?= $data->MenuCartText->Text; ?></a>
</h1>
