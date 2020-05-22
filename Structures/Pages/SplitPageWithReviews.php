<!-- Sidebar -->


<div id="sidebar" class="col-6 col-12-medium">


    <?php $ContentIndex = 2; ?>
    <?php include("{$BasePath}/Structures/Sections/Content.php"); ?>

</div>

<!-- Content -->
<div id="content" class="col-6 col-12-medium imp-medium">
    <!-- Post -->
    <article class="box post">


        <?php $ContentIndex = 3; ?>
        <?php include("{$BasePath}/Structures/Sections/Content.php"); ?>


    </article>
</div>
<div id="content" class="col-12 col-12-medium imp-medium">
    <?php include_once("{$BasePath}/Structures/Widgets/Reviews.php"); ?>
</div>
