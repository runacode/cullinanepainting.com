<section>
    <ul class="divided">
        <li>
            <article class="box highlight">
                <img src="/<?= $data->MainImage ?>" <?php if ($EditMode) { ?> datatype="Image" data-position="<?php echo MainImage; ?>"  <?php } ?>
                     class="image fit MainImage"/>
            </article>
            <!-- Highlight -->
            <article class="box highlight">
                <?php $i = 0; ?>
                <?php foreach ($data->Images as $image) { ?>


                    <a href="javascript:void(0)" class="image linkimageswap">
                        <img style="max-width: 10vw;" src="/<?= $image->Url ?>"
                             class="ImageSwap  " <?php if ($EditMode) { ?> datatype="Image" data-position="<?php echo "Images-$i"; ?>"  <?php } ?>
                             alt="<?= $image->Alt ?>"/>
                    </a>

                    <?php
                    $i++;
                } ?>

            </article>

        </li>

    </ul>
</section>
