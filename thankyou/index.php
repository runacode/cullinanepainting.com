<?php
$qs = "leadid={$_REQUEST['leadid']}&affid={$_REQUEST['affid']}&oid={$_REQUEST['oid']}&campid={$_REQUEST['campid']}&cid={$_REQUEST['cid']}&tid={$_REQUEST['tid']}&s1={$_REQUEST['s1']}&s2={$_REQUEST['s2']}&s3={$_REQUEST['s3']}&s4={$_REQUEST['s4']}&s5={$_REQUEST['s5']}&price={$_REQUEST['price']}&udid={$_REQUEST['udid']}";

header("location: {$_REQUEST['s1']}/thankyou/redirect.php?$qs")
?>
