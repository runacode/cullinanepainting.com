<?php

$FaceCon = json_decode( file_get_contents(sprintf("%s/config/data.json", dirname(__FILE__))));

//pixel code
function extract_subdomains($domain)
{
    $subdomains = $domain;
    $domain = extract_domain($subdomains);

    $subdomains = rtrim(strstr($subdomains, $domain, true), '.');

    return $subdomains;
}

function extract_domain($domain)
{
    if (preg_match("/(?P<domain>[a-z0-9][a-z0-9\-]{1,63}\.[a-z\.]{2,6})$/i", $domain, $matches)) {
        return $matches['domain'];
    } else {
        return $domain;
    }
}

$currentsubdomain = extract_subdomains($_SERVER['HTTP_HOST']);
$currentdomain = extract_domain($_SERVER['HTTP_HOST']);


$Event='PageView';
$Value='';
$PixelValue ='';
if(isset($qs)) {
    if (isset($qs['Event'])) {
        $Event = $qs['Event'];
    }
    if (isset($qs['Value'])) {
        $Value  = ','.json_encode($qs['Value']);
        $obj = $qs['Value'];
        $PixelValue = '&cd[value]=' . $obj['value'] . '&cd[currency]=' . $obj['currency'];

    }
}
if(isset($FaceCon->pixel_id) && strlen($FaceCon->pixel_id )>0 || strcmp($FaceCon->pixel_id, "1212") !==0) {

    ?>
    <script>


		!function (f, b, e, v, n, t, s) {
			if (f.fbq) return;
			n = f.fbq = function () {
				n.callMethod ?
					n.callMethod.apply(n, arguments) : n.queue.push(arguments)
			};
			if (!f._fbq) f._fbq = n;
			n.push = n;
			n.loaded = !0;
			n.version = '2.0';
			n.queue = [];
			t = b.createElement(e);
			t.async = !0;
			t.src = v;
			s = b.getElementsByTagName(e)[0];
			s.parentNode.insertBefore(t, s)
		}(window, document, 'script',
			'https://connect.facebook.net/en_US/fbevents.js');

		fbq('init', <?= $FaceCon->pixel_id; ?>);
		fbq('track', '<?php echo $Event; ?>'<?php echo $Value; ?>);


    </script>

    <noscript><img height="1" width="1" style="display:none"
                   src="https://www.facebook.com/tr?id=<?= $FaceCon->pixel_id; ?>&ev=<?php echo $Event; ?><?php echo $PixelValue; ?>&noscript=1"
        /></noscript>
    <?php

}
?>
