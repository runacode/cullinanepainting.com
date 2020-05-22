<?php include_once("../../SafePage/Sections/header.php"); ?>
<body class="left-sidebar is-preload">
<div id="page-wrapper">
    <!-- Header -->
    <?php include_once("../../SafePage/Sections/Menu.php"); ?>

    <!-- Main -->
    <section id="main">
        <div class="container">
            <div class="row">
                <form method="post" action="">
                    <div class="row gtr-50">
                        <div class="col-6 col-12-small">
                            <input name="email" placeholder="Email" type="text"/>
                        </div>
                        <div class="col-6 col-12-small">
                            <input name="password" placeholder="Password" type="password"/>
                        </div>


                        <div class="col-12">
                            <button type="submit" class="form-button-submit button icon solid fa-envelope">Login
                            </button>
                        </div>
                    </div>
                </form>
            </div>
        </div>
    </section>

    <?php include_once("../../SafePage/Sections/footer.php"); ?>

</div>
</body>
<?php include_once("../../SafePage/Sections/scripts.php"); ?>

<?php include_once("../../pixel.php"); ?>
