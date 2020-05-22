<section>
    <div class="container">
        <header>
            <h2 <?php if ($EditMode) { ?>
                datatype="TextBox"
                data-position="ProductName"
            <?php } ?>><?= $data->ProductName; ?></h2>
        </header>
        <h2 class="alt"
            <?php if ($EditMode) { ?>
            datatype="TextBox"
            data-position="ProductPrice"
            <?php } ?>><?= $data->CurrencySymbol; ?><?= $data->ProductPrice; ?></h2>
        <div class="row">
            <div class="col-12">
                <section>
                    <form method="post" action="<?php echo $data->AddToCart->Url; ?>">
                        <div class="row gtr-50">
                            <div class="col-12">
                                <input name="Quantity" min="1" placeholder="Quantity" type="number" value="1"/>
                            </div>


                            <div class="col-12">
                                <button type="submit" class="form-button-submit button icon solid fa-plus centered"
                                    <?php if ($EditMode) { ?> datatype="Clickable" data-position="AddToCart" <?php } ?>
                                ><?= $data->AddToCart->Text; ?></button>
                            </div>
                        </div>
                    </form>
                </section>
            </div>

        </div>
    </div>

</section>
