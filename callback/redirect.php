<?php

//s1 = domain
//s2 = fb id
//s3 = Custom Event
//s4 = Currency



$price = $_REQUEST['price'];
$fbid = $_REQUEST['s2'];
$Event = $_REQUEST['s3'];
$Currency = $_REQUEST['s4'];

?>
<script>
    window.location = "fb.php?fbid=<?php echo $fbid; ?>&Event=<?php echo $Event; ?>&currency=<?php echo $Currency; ?>&price=<?php echo $price; ?>";
</script>
