<?php


$pixelId = $_REQUEST['fbid'];
if (isset($_REQUEST['Event'])) {
    $Event = $_REQUEST['Event'];
} else {
    $Event = 'Purchase';
}
if (isset($_REQUEST['currency'])) {
    $Currency = $_REQUEST['currency'];
} else {
    $Currency = $data->FacebookCurrency;
}
if (isset($_REQUEST['price'])) {
    $PixelValue = "&cd[value]={$_REQUEST['price']}&cd[currency]={$Currency}";
}
$Event = isset($_REQUEST['Event']) ? $_REQUEST['Event'] : 'Purchase';

?>
    <img height="1" width="1" style="display:none"
         src="https://www.facebook.com/tr?id=<?= $pixelId; ?>&ev=<?php echo $Event; ?><?php echo $PixelValue; ?>"/>
 