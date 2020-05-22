<?php

include_once ("../config/config.php");

$tmp['Outbound'] = $_REQUEST['link'];
$tmp['Ip'] = $_SERVER['REMOTE_ADDR'];
$tmp['Now'] = date(DATE_RFC2822);
$now =getdate();
error_log(  str_putcsv($tmp) . "\n",3,$BasePath . "/logs/{$now['year']}_{$now['day']}_{$now['month']}.csv");

?>