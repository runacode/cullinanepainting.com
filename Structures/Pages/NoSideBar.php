<section class="container">
    <?php $ContentIndex = 1; ?>
    <?php include("{$BasePath}/Structures/Sections/Content.php"); ?>
</section>

<div class="container content">
    <!-- Post -->
    <div class="row">
        <div class="col-md-8">
            <?php $ContentIndex = 2; ?>
            <?php include("{$BasePath}/Structures/Sections/Content.php"); ?>
        </div>
        <div class="col-md-4">
            <?php $ContentIndex = 3; ?>
            <?php include("{$BasePath}/Structures/Sections/Content.php"); ?>
        </div>
    </div>

    <div class="container comments">
        <?php $ContentIndex = 4; ?>
        <?php include("{$BasePath}/Structures/Sections/Content.php"); ?>
    </div>

</div>
<?php $ContentIndex = 5; ?>
<?php include("{$BasePath}/Structures/Sections/Content.php"); ?>