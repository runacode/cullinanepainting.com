<?php
if (!function_exists("CloakPage")) {

    function CloakPage($overwrite, $BasePth)
    {

        $path = sprintf("%s/../config/Pages/$overwrite", dirname(__FILE__));

        $overwritedatatmp = json_decode(file_get_contents($path));
        if (strlen($overwritedatatmp->CloakerPath) > 0) {
            $CloakerPath = sprintf("%s/..{$overwritedatatmp->CloakerPath}", dirname(__FILE__));

            if (!file_exists($CloakerPath)) {
                echo "could not find c file";
                exit;
            }

            include($CloakerPath);
            exit;
        }
    }
}
if (!function_exists("endswith")) {
    function endswith($string, $test)
    {
        $strlen = strlen($string);
        $testlen = strlen($test);
        if ($testlen > $strlen) return false;
        return substr_compare($string, $test, $strlen - $testlen, $testlen) === 0;
    }
}
if (!function_exists('Zroscrubrotate')) {
    function Zroscrubrotate()
    {
        global $VoluumUrl;
        $api_url = "https://zroscrubrotate.com/o/96/";
        $vertical = "";

//// Fetch Offer Data  /////

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $api_url . $vertical);

//curl_setopt($curl, CURLOPT_REFERER, $_SERVER['HTTP_REFERER']);
        curl_setopt($ch, CURLOPT_REFERER, $VoluumUrl);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array("Content-Type: application/json"));
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($ch, CURLOPT_TIMEOUT, 15);
        $ua = $_SERVER["HTTP_USER_AGENT"];
        if (isset($ua)) curl_setopt($ch, CURLOPT_USERAGENT, $ua);
        $return = curl_exec($ch);
        $result = json_decode($return, true);
        if ($result) {
            $link_href = $result["link_href"];
            $image_url = $result['image_url'];
            $link_text = $result["link_text"];
            ?>
            <div class="zrotate">
                This is some product you are going to love!!! Buy <a href="<?= $link_href ?>"><?= $link_text ?></a>.
                <a href="<?= $link_href ?>"><img src="<?= $image_url ?>"/></a>
            </div>
            <?php
        }

    }
}
if (!function_exists('echo2')) {
    function echo2($str)
    {
        global $actual_domain;
        global $actual_link;
        global $data;
        global $overwrite;
        global $BasePath;
        eval(' ?>' . $str . '<?php ');

    }
}

if (!function_exists('TrimDomain')) {
    function TrimDomain(array &$hostData)
    {
        while (count($hostData) > 2) {
            array_shift($hostData);
        }
        return $hostData;
    }
}
if (!function_exists('Log_User')) {
    global $BasePath;
    global $actual_domain;
    function Log_User($Pass)
    {
        $tmp['ip'] = $_SERVER['REMOTE_ADDR'];
        $tmp['useragent'] = $_SERVER['HTTP_USER_AGENT'];
        $tmp['domain'] = $actual_domain;
        $now = getdate();
        if ($Pass) {

            error_log(str_putcsv($tmp) . "\n", 3, $BasePath . "/logs/dirty_{$now['year']}_{$now['mday']}_{$now['month']}.csv");

        } else {
            error_log(str_putcsv($tmp) . "\n", 3, $BasePath . "/logs/safe_{$now['year']}_{$now['mday']}_{$now['month']}.csv");
        }
    }

}

if (!function_exists('str_putcsv')) {
    function str_putcsv($input, $delimiter = ',', $enclosure = '"')
    {
        // Open a memory "file" for read/write...
        $fp = fopen('php://temp', 'r+');
        // ... write the $input array to the "file" using fputcsv()...
        fputcsv($fp, $input, $delimiter, $enclosure);
        // ... rewind the "file" so we can read what we just wrote...
        rewind($fp);
        // ... read the entire line into a variable...
        $data = fread($fp, 1048576);
        // ... close the "file"...
        fclose($fp);
        // ... and return the $data to the caller, with the trailing newline from fgets() removed.
        return rtrim($data, "\n");
    }
}

if (!function_exists('http_build_url')) {
    // Define constants
    define('HTTP_URL_REPLACE', 0x0001);    // Replace every part of the first URL when there's one of the second URL
    define('HTTP_URL_JOIN_PATH', 0x0002);    // Join relative paths
    define('HTTP_URL_JOIN_QUERY', 0x0004);    // Join query strings
    define('HTTP_URL_STRIP_USER', 0x0008);    // Strip any user authentication information
    define('HTTP_URL_STRIP_PASS', 0x0010);    // Strip any password authentication information
    define('HTTP_URL_STRIP_PORT', 0x0020);    // Strip explicit port numbers
    define('HTTP_URL_STRIP_PATH', 0x0040);    // Strip complete path
    define('HTTP_URL_STRIP_QUERY', 0x0080);    // Strip query string
    define('HTTP_URL_STRIP_FRAGMENT', 0x0100);    // Strip any fragments (#identifier)

    // Combination constants
    define('HTTP_URL_STRIP_AUTH', HTTP_URL_STRIP_USER | HTTP_URL_STRIP_PASS);
    define('HTTP_URL_STRIP_ALL', HTTP_URL_STRIP_AUTH | HTTP_URL_STRIP_PORT | HTTP_URL_STRIP_QUERY | HTTP_URL_STRIP_FRAGMENT);

    /**
     * HTTP Build URL
     * Combines arrays in the form of parse_url() into a new string based on specific options
     * @name http_build_url
     * @param string|array $url The existing URL as a string or result from parse_url
     * @param string|array $parts Same as $url
     * @param int $flags URLs are combined based on these
     * @param array &$new_url If set, filled with array version of new url
     * @return string
     */
    function http_build_url(/*string|array*/ $url, /*string|array*/ $parts = array(), /*int*/ $flags = HTTP_URL_REPLACE, /*array*/ &$new_url = false)
    {
        // If the $url is a string
        if (is_string($url)) {
            $url = parse_url($url);
        }

        // If the $parts is a string
        if (is_string($parts)) {
            $parts = parse_url($parts);
        }

        // Scheme and Host are always replaced
        if (isset($parts['scheme'])) $url['scheme'] = $parts['scheme'];
        if (isset($parts['host'])) $url['host'] = $parts['host'];

        // (If applicable) Replace the original URL with it's new parts
        if (HTTP_URL_REPLACE & $flags) {
            // Go through each possible key
            foreach (array('user', 'pass', 'port', 'path', 'query', 'fragment') as $key) {
                // If it's set in $parts, replace it in $url
                if (isset($parts[$key])) $url[$key] = $parts[$key];
            }
        } else {
            // Join the original URL path with the new path
            if (isset($parts['path']) && (HTTP_URL_JOIN_PATH & $flags)) {
                if (isset($url['path']) && $url['path'] != '') {
                    // If the URL doesn't start with a slash, we need to merge
                    if ($url['path'][0] != '/') {
                        // If the path ends with a slash, store as is
                        if ('/' == $parts['path'][strlen($parts['path']) - 1]) {
                            $sBasePath = $parts['path'];
                        } // Else trim off the file
                        else {
                            // Get just the base directory
                            $sBasePath = dirname($parts['path']);
                        }

                        // If it's empty
                        if ('' == $sBasePath) $sBasePath = '/';

                        // Add the two together
                        $url['path'] = $sBasePath . $url['path'];

                        // Free memory
                        unset($sBasePath);
                    }

                    if (false !== strpos($url['path'], './')) {
                        // Remove any '../' and their directories
                        while (preg_match('/\w+\/\.\.\//', $url['path'])) {
                            $url['path'] = preg_replace('/\w+\/\.\.\//', '', $url['path']);
                        }

                        // Remove any './'
                        $url['path'] = str_replace('./', '', $url['path']);
                    }
                } else {
                    $url['path'] = $parts['path'];
                }
            }

            // Join the original query string with the new query string
            if (isset($parts['query']) && (HTTP_URL_JOIN_QUERY & $flags)) {
                if (isset($url['query'])) $url['query'] .= '&' . $parts['query'];
                else                        $url['query'] = $parts['query'];
            }
        }

        // Strips all the applicable sections of the URL
        if (HTTP_URL_STRIP_USER & $flags) unset($url['user']);
        if (HTTP_URL_STRIP_PASS & $flags) unset($url['pass']);
        if (HTTP_URL_STRIP_PORT & $flags) unset($url['port']);
        if (HTTP_URL_STRIP_PATH & $flags) unset($url['path']);
        if (HTTP_URL_STRIP_QUERY & $flags) unset($url['query']);
        if (HTTP_URL_STRIP_FRAGMENT & $flags) unset($url['fragment']);

        // Store the new associative array in $new_url
        $new_url = $url;

        // Combine the new elements into a string and return it
        return
            ((isset($url['scheme'])) ? $url['scheme'] . '://' : '')
            . ((isset($url['user'])) ? $url['user'] . ((isset($url['pass'])) ? ':' . $url['pass'] : '') . '@' : '')
            . ((isset($url['host'])) ? $url['host'] : '')
            . ((isset($url['port'])) ? ':' . $url['port'] : '')
            . ((isset($url['path'])) ? $url['path'] : '')
            . ((isset($url['query'])) ? '?' . $url['query'] : '')
            . ((isset($url['fragment'])) ? '#' . $url['fragment'] : '');
    }
}
if (!function_exists("GetCurrentValueByDataPosition")) {
    function GetCurrentValueByDataPosition($dp, $overwrite)
    {
        $overwritedata = json_decode(file_get_contents(dirname(__FILE__) . '/Pages/' . $overwrite), true);
        $ConfigItems = preg_split('/-/', $dp);
        $ConfigItem = $ConfigItems[0];


        if (isset($overwritedata[$ConfigItem])) {
            switch (count($ConfigItems)) {
                case 1:
                    return $overwritedata[$ConfigItem];
                    break;
                case 2:
                    $ObjectIndex = $ConfigItems[1];
                    if (is_int($ObjectIndex)) {
                        $ObjectIndex = (int)$ObjectIndex;
                    }

                    return $overwritedata[$ConfigItem][$ObjectIndex];
                    break;
                case 3:

                    $ObjectIndex = $ConfigItems[1];
                    if (is_int($ObjectIndex)) {
                        $ObjectIndex = parse_int($ObjectIndex);
                    }
                    $Property = $ConfigItems[2];
                    if (is_int($Property)) {
                        $Property = parse_int($Property);
                    }

                    return $overwritedata[$ConfigItem][$ObjectIndex][$Property];
                    break;
            }
        }
    }

    function SetCurrentValueByDataPosition($dp, $overwrite, $Value)
    {

        $overwritedata = json_decode(file_get_contents(dirname(__FILE__) . '/Pages/' . $overwrite), true);
        $ConfigItems = preg_split('/-/', $dp);
        $ConfigItem = $ConfigItems[0];


        switch (count($ConfigItems)) {
            case 1:
                $overwritedata[$ConfigItem] = $Value;


                UpdateOverWriteData($overwrite, $overwritedata);

                return true;
            case 2:

                $ObjectIndex = $ConfigItems[1];
                if (!preg_match('/\[\]$/', $dp)) {
                    $overwritedata[$ConfigItem][$ObjectIndex] = $Value;
                } else {
                    $overwritedata[$ConfigItem][] = $Value;
                }
                UpdateOverWriteData($overwrite, $overwritedata);
                break;
            case 3:

                $ObjectIndex = $ConfigItems[1];
                $Property = $ConfigItems[2];
                if (!preg_match('/\[\]$/', $dp)) {
                    $overwritedata[$ConfigItem][$ObjectIndex][$Property] = $Value;
                } else {
                    $overwritedata[$ConfigItem][$ObjectIndex][] = $Value;
                }
                UpdateOverWriteData($overwrite, $overwritedata);
                return true;

                break;
        }

    }

    function DeleteCurrentValueByDataPosition($dp, $overwrite)
    {

        $overwritedata = json_decode(file_get_contents(dirname(__FILE__) . '/Pages/' . $overwrite), true);
        $ConfigItems = preg_split('/-/', $dp);
        $ConfigItem = $ConfigItems[0];


        switch (count($ConfigItems)) {
            case 1:
                unset($overwritedata[$ConfigItem]);

                UpdateOverWriteData($overwrite, $overwritedata);
                return true;
            case 2:

                $ObjectIndex = $ConfigItems[1];
                if (is_numeric($ObjectIndex)) {
                    array_splice($overwritedata[$ConfigItem], $ObjectIndex, 1);
                } else {
                    unset($overwritedata[$ConfigItem][$ObjectIndex]);
                }
                UpdateOverWriteData($overwrite, $overwritedata);
                break;
            case 3:

                $ObjectIndex = $ConfigItems[1];
                $Property = $ConfigItems[2];
                if (is_numeric($ObjectIndex)) {
                    array_splice($overwritedata[$ConfigItem][$ObjectIndex], $Property, 1);
                } else {
                    unset($overwritedata[$ConfigItem][$ObjectIndex][$Property]);
                }
                UpdateOverWriteData($overwrite, $overwritedata);
                return true;

                break;
        }


    }

    function UpdateOverWriteData($overwrite, $overwritedata)
    {
        $result = file_put_contents(dirname(__FILE__) . '/Pages/' . $overwrite, json_encode($overwritedata));
        if ($result === false) {
            echo "File Write Failed";
            exit;
        }
    }
}
?>