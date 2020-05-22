<?php include_once("SafePage/Sections/header.php"); ?>
<body class="left-sidebar is-preload">
<div id="page-wrapper">
    <!-- Header -->
    <?php include_once("SafePage/Sections/Menu.php"); ?>

    <!-- Main -->
    <section id="main">
        <div class="container">
            <div class="row">
                <h1 id="logo">
                  <?php echo "{$_REQUEST['Quantity']} Items have been added to your cart"; ?>
                </h1>
            </div>
        </div>
    </section>

    <?php include_once("SafePage/Sections/footer.php"); ?>

</div>
</body>
<?php include_once("SafePage/Sections/scripts.php"); ?>

