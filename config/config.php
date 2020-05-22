<?php
include_once(dirname(__FILE__) . "/Functions.php");


$BasePath = realpath( dirname(__FILE__).'/../') .'/';


$ConfigFilePath = dirname(__FILE__) . '/data.json';
$ConfigTextData = file_get_contents($ConfigFilePath);
$data = json_decode($ConfigTextData);
if (isset($overwrite)) {
    $overwritedata = json_decode(file_get_contents(dirname(__FILE__) . '/Pages/' . $overwrite));
    foreach (array_keys((array)$overwritedata) as $key) {
        $data->$key = $overwritedata->$key;
    }
} else {
    $overwritedata = array();
}

$actual_domain = "https://$_SERVER[HTTP_HOST]/";
$actual_link = "https://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
$url_parts = parse_url($actual_link);
$hostData = explode('.', $url_parts['host']);


$hostData = TrimDomain($hostData);
$lowdomain = join(".", $hostData);
if (isset($overwritedata->VoluumCpid) && strlen($overwritedata->VoluumCpid) > 0) {
    if (strpos($_SERVER['QUERY_STRING'], $overwritedata->VoluumCpid) === false) {


        if (isset($url_parts['query'])) { // Avoid 'Undefined index: query'
            parse_str($url_parts['query'], $params);
        } else {
            $params = array();
        }
        $params['cpid'] = $overwritedata->VoluumCpid;
        $url_parts['query'] = http_build_query($params);
        $VoluumUrl = http_build_url($url_parts);
        //header("location: " . http_build_url($url_parts));
        //exit;
    }
}

?>
