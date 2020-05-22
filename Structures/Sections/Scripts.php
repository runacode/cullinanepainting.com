<!-- Scripts -->

<script src="/assets/js/jquery.min.js"></script>
<?php include_once("{$BasePath}pixel.php");
if ($EditMode) {
    include_once("{$BasePath}config/Editor/Editor.php");
}
?>

<?php
if (isset($data->JavascriptList)) {
    ?>

    <?php echo $data->JavascriptList; ?>

    <?php

}

if (isset($data->JavascriptIn) && !$EditMode) {
    ?>
    <script>
        <?php echo $data->JavascriptIn; ?>
    </script>
    <?php

}
if (isset($overwritedata->VoluumCpid) && strlen($overwritedata->VoluumCpid) > 0) {
    ?>

    <style>.dtpcnt {
            opacity: 0;
        }</style>
    <script> (function (b, c, f, l, m, e, n, r, d, g, p, a, h, k) {
            function q() {
                for (var a = c.querySelectorAll(".dtpcnt"), b = 0, d = a.length; b < d; b++) a[b][n] = a[b][n].replace(/(^|\s+)dtpcnt($|\s+)/g, "")
            }

            b[d] || (b[d] = function () {
                (b[d].q = b[d].q || []).push(arguments)
            }, k = c[l], c[l] = function () {
                k && k.apply(this, arguments);
                if (b[d] && !b[d].hasOwnProperty("params") && /loaded|interactive|complete/.test(c.readyState)) for (; a = c[m][g++];) /\/?click($|(\/[0-9]+)?$)/.test(a.pathname) && (a[e] = "javascrip" + b.postMessage.toString().slice(4, 5) + ":" + d + '.l="' + a[e] + '",void 0')
            }, setTimeout(function () {
                a = c.createElement("script");
                h = c.scripts[0];
                a.defer = 1;
                a.src = p + (-1 === p.indexOf("?") ? "?" : "&") + "lpref=" + f(c.referrer) + "&lpurl=" + f("<?php echo $VoluumUrl; ?>") + "&lpt=" + f(c.title) + "&t=" + (new Date).getTime();
                a[r] = function () {
                    for (g = 0; a = c[m][g++];) /dtpCallback\.l/.test(a[e]) && (a[e] = a[e].match(/dtpCallback\.l="([^"]+)/)[1]);
                    q()
                };
                h.parentNode.insertBefore(a, h)
            }, 0), setTimeout(q, 7E3))
        })(window, document, encodeURIComponent, "onreadystatechange", "links", "href", "className", "onerror", "dtpCallback", 0, "https://examences-chounded.icu/d/.js"); </script>
    <noscript>
        <link href="https://examences-chounded.icu/d/.js?noscript=true" rel="stylesheet"/>
    </noscript>

    <?php
}
?>
</html>
