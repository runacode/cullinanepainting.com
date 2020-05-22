<?php

$EditMode = false;

if (isset($_REQUEST['EditMode']) && isset($data->EditMode)) {

    if (strcmp($_REQUEST['EditMode'], $data->EditMode) === 0) {
        session_start();
        $_SESSION['EditMode'] =true;
        $EditMode = true;
    }
}
if ($EditMode && isset($_REQUEST['SetConfig'])) {
    $ConfigItems = preg_split('/-/', $_REQUEST['SetConfig']);
    $ConfigItem=$ConfigItems[0];
    $ConfigValue = $_REQUEST['ConfigValue'];
    if (isset($data->$ConfigItem)) {
        switch(count($ConfigItem)){
            case 1:
                $data->$ConfigItem = $ConfigValue;
                break;
            case 2:
                $ObjectIndex = $ConfigItems[1];
                $data->$ConfigItem[$ObjectIndex] = $ConfigValue;
                break;
            case 3:
                $ObjectIndex = $ConfigItems[1];
                $Property = $ConfigItems[2];
                $data->$ConfigItem[$ObjectIndex][$Property] = $ConfigValue;
                break;
        }
        file_put_contents($ConfigTextData,json_encode($data));
    }
}
?>
