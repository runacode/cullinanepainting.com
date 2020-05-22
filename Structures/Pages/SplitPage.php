 <!-- Sidebar -->


                <div id="sidebar" class="col-6 col-12-medium">

                    <?php include_once("{$BasePath}/Structures/Widgets/ImageSelector.php"); ?>
                    <?php $ContentIndex = 2; ?>
                    <?php include("{$BasePath}/Structures/Sections/Content.php"); ?>

                </div>

                <!-- Content -->
                <div id="content" class="col-6 col-12-medium imp-medium">
                    <!-- Post -->
                    <article class="box post">
                        <?php include_once("{$BasePath}/Structures/Widgets/Add-ToCart.php"); ?>

                        <?php $ContentIndex = 3; ?>
                        <?php include("{$BasePath}/Structures/Sections/Content.php"); ?>


                    </article>
                </div>

