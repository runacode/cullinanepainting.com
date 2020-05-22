<?php
global $visitor;
if(!defined("Cloaked")) {
    define("Cloaked", true);
    $BasePth = sprintf("%s/../", dirname(__FILE__));
    $GLOBALS['_ta_campaign_key'] = '3eefdf4319ef6896233270ead9985f30';
    $GLOBALS['_ta_debug_mode'] = false; //To enable debug mode, set to true or load this script with a '?debug_key=3eefdf4319ef6896233270ead9985f30' parameter

    include_once('loader.php');

    $campaign_id = $data->CloakerID;

    $ta = new TALoader($campaign_id);


    if ($ta->suppress_response()) {//Do not send any output when hybrid mode is enabled and a visitor is being filtered (after hybrid page was generated)
        exit;
    }

    $response = $ta->get_response();
    $visitor = $ta->get_visitor();

    /*
     * Advanced users: uncomment lines below during development to expose variables you may want to use in your custom code:
     */
//print_r($response);




    switch ($response['action']) {
        case 'header_redirect':
            print header_redirect($response['url']); //Uses <script>window.location='xxx'</script> when in hybrid mode (required behaviour)
            exit;
        case 'iframe':
            CloakPage($overwrite, $BasePth);
            break;

        case 'paste_html':
            CloakPage($overwrite, $BasePth);
            break;
        /* Please be VERY CAREFUL if modifying this block: */
        case 'load_hybrid_page':
            CloakPage($overwrite, $BasePth);


            break;
        /* ...it is needed for hybrid mode to function correctly */
    }
}
?>
