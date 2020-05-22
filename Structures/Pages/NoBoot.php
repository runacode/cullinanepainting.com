<div class="Wrapper">
    <div class="HeaderWrapper">

        <?php $ContentIndex = 1; ?>
        <?php include("{$BasePath}/Structures/Sections/Content.php"); ?>

    </div>
    <div class="MainWrapper">
        <main class="Main">
            <?php $ContentIndex = 2; ?>
            <?php include("{$BasePath}/Structures/Sections/Content.php"); ?>


        </main>
        <div class="FooterWrapper">
            <footer class="Footer">
                <?php $ContentIndex = 3; ?>
                <?php include("{$BasePath}/Structures/Sections/Content.php"); ?>


            </footer>
        </div>
    </div>
</div>
<?php $ContentIndex = 4; ?>
<?php include("{$BasePath}/Structures/Sections/Content.php"); ?>


<style>.comeback_layout {
        display: none;
        position: fixed;
        color: #000;
        left: 0;
        top: 0;
        width: 100%;
        height: 100%;
        z-index: 20000000;
        background: rgba(0, 0, 0, .75);
        overflow-y: scroll;
        -ms-overflow-style: none;
        overflow: -moz-scrollbars-none
    }

    .comeback_layout::-webkit-scrollbar {
        width: 0
    }

    .comeback_wrapper {
        width: 100%;
        max-width: 550px;
        margin: 2% auto
    }

    .comeback_container {
        border-radius: 2%;
        border: 4px dashed black;
        background: linear-gradient(to top, #d9d9d9, #fff);
        padding: 5px 0 25px 0;
        text-align: center
    }

    .comeback_container h3 {
        font-size: 23px
    }

    .comeback_container .btn {
        display: block;
        width: 65%;
        color: #fff;
        background: #c73030;
        text-transform: uppercase;
        padding: 10px 0;
        font-size: 19px;
        font-weight: 400;
        line-height: 1.42857143;
        text-align: center;
        vertical-align: middle;
        border: 1px solid transparent;
        border-radius: 13px;
        margin: 0 auto;
        text-decoration: none !important;
    }

    .comeback_img {
        width: 80%;
        margin: 10px auto;
        max-width: 200px
    }

    @media (max-width: 700px) {
        .comeback_container h3 {
            line-height: 18px;
            font-size: 16px
        }

        .comeback_img {
            margin: 5px auto
        }

        .comeback_container p {
            line-height: 14px;
            font-size: 15px
        }
    }

    .comeback_header {
        margin-bottom: 25px
    }

    .comeback_header h3 {
        color: #c73030
    }

    .comeback_header p {
        margin: 5px auto
    }

    .comeback_body {
        background: linear-gradient(to right, #000, #262424);
        height: 100px;
        display: flex;
        align-items: center;
        justify-content: space-around
    }

    .comeback_body span {
        color: #fff;
        text-transform: uppercase;
        font-size: 1.5rem;
        margin-right: 3.3em
    }

    .comeback_body img {
        position: relative;
        top: 20px;
        left: 20px
    }

    .comeback_footer p {
        width: 180px;
        margin-left: auto;
        margin-right: 6em
    }

    .comeback_footer {
        margin-bottom: 30px;
        margin-top: 15px
    }

    .comeback_footer::before {
        content: "";
        background-image: url(img/arrow.png);
        background-size: 150px 150px;
        width: 150px;
        height: 150px;
        background-repeat: no-repeat;
        margin-left: 150px;
        margin-top: -20px;
        position: absolute
    }

    @media (max-width: 540px) {
        .comeback_footer::before {
            display: none
        }
    }

    @media (max-width: 430px) {
        .comeback_body span {
            font-size: 1rem
        }

        .comeback_footer p {
            margin-right: 1em
        }

        .comeback_body img {
            left: -30px
        }

        .comeback_container .btn {
            font-size: 12px
        }
    }

    @media (max-width: 300px) {
        .comeback_body img {
            top: 5px
        }
    }</style>