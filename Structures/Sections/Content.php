<?php
$i = 0;
$ContentName = "ContentIndex$ContentIndex";

foreach ($data->$ContentName as $item) { ?>
    <?php if ($EditMode) { ?>   <section  datatype="Content" data-position="<?php echo $ContentName; ?>-<?php echo $i; ?>"> <?php } ?>

    <?php

    foreach ($item->Text as $text) { ?>
        <?php eval(' ?>'.$text.'<?php ');  ?>
        <?php

    }

    ?>
    <?php if ($EditMode) { ?>   </section>  <?php }
    $i++;
}
if ($EditMode) { ?>

    <section datatype="Content" data-position="<?php echo $ContentName; ?>-[]">
        <h3 class="button">New Item for <?php echo $ContentName; ?></h3>


    </section>
<?php } ?>
