<?php

#
#  VGWhoIs (ViaThinkSoft Global WhoIs, a fork of generic Whois / gwhois)
#  Common functions in PHP
#
#  (c) 2011-2024 by Daniel Marschall, ViaThinkSoft <info@daniel-marschall.de>
#
#  License: https://www.gnu.org/licenses/gpl-2.0.html (GPL version 2)
#

include_once __DIR__ . '/ipv4_functions.inc.php';
include_once __DIR__ . '/ipv6_functions.inc.php';
include_once __DIR__ . '/grep_functions.inc.php';
include_once __DIR__ . '/gwi_functions.inc.php';

function file_age($filename) {
	$m = file_exists($filename) ? filemtime($filename) : 0;
	return time()-$m;
}

function human_timediff($t) {
	if ($t < 60) {
		$e = 'seconds';
	} else if ($t < 60*60) {
		$t /= 60;
		$e = 'minutes';
	} else if ($t < 24*60*60) {
		$t /= 60*60;
		$e = 'hours';
	} else if ($t < 30*24*60*60) {
		$t /= 24*60*60;
		$e = 'days';
	} else if ($t < 365*24*60*60) {
		$t /= 30*24*60*60;
		$e = 'months';
	} else {
		$t /= 365*24*60*60;
		$e = 'years';
	}
	$t = floor($t);
	return "$t $e";
}

# http://www.phpeasycode.com/whois/
# TODO: code duplicate in maintenance/pattern-generator/generate_newgtld
function QueryWhoisServer($whoisserver, $domain, $port=43, $timeout=10) {
	$fp = @fsockopen($whoisserver, $port, $errno, $errstr, $timeout);
	if (!$fp) die("Socket Error " . $errno . " - " . $errstr);
	// if ($whoisserver == "whois.verisign-grs.com") $domain = "=$domain"; // whois.verisign-grs.com requires the equals sign ("=") or it returns any result containing the searched string.
	fputs($fp, $domain . "\r\n");
	$out = "";
	while(!feof($fp)){
		$out .= fgets($fp);
	}
	fclose($fp);

	$res = "";
	if ((strpos(strtolower($out), "error") === FALSE) && (strpos(strtolower($out), "not allocated") === FALSE)) {
		$rows = explode("\n", $out);
		foreach($rows as $row) {
			$row = trim($row);
			if (($row != '') && ($row[0] != '#') && ($row[0] != '%')) {
				$res .= "$row\n";
			}
		}
	}
	return $res;
}

# TODO: rename (without "gwitc")
function gwitc_is_port_open($server, $default_port, $timeout=3) {
	// TODO: "whois.namecoin.us" will always answer to a port request, because the domain parking service is shit

	$x = explode(':', $server, 2);
	$host = $x[0];
	$port = isset($x[1]) ? $x[1] : $default_port;

	// First try with TOR
#	$cmd = "vtor -- nc -zw$timeout $host $port 2>/dev/null";
#	exec($cmd, $out, $code);
#	if ($code == 0) return true;

	// Try without TOR
	$cmd = "nc -zw$timeout $host $port 2>/dev/null";
	exec($cmd, $out, $code);
	return ($code == 0);
}

function getAllFiles($directory, $recursive = true, $include_dirs = false, $include_files = true) {
	$result = array();
	$handle = opendir($directory);
	if (substr($directory, -1) == '/') $directory = substr($directory, 0, strlen($directory)-1);
	if ($include_dirs) {
		$result[] = $directory;
	}
	while ($datei = readdir($handle)) {
		if (($datei != '.') && ($datei != '..')) {
			$file = $directory.'/'.$datei;
			if (is_dir($file)) {
				if ($include_dirs && !$recursive) {
					$result[] = $file;
				}
				if ($recursive) {
					$result = array_merge($result, getAllFiles($file, $recursive, $include_dirs, $include_files));
				}
			} else {
				if ($include_files) $result[] = $file;
			}
		}
	}
	closedir($handle);
	return $result;
}

// TOR capable
function file_get_contents2($url, $postvalues='', $headers=array()) {
        # exec ("wget -N -O - -- ".escapeshellarg($url), $out);

        $add_cmd = '';
        foreach ($headers as $name => $h) {
		if (is_numeric($name)) {
	                $add_cmd .= "-H ".escapeshellarg($h)." ";
		} else {
	                $add_cmd .= "-H ".escapeshellarg($name.': '.$h)." ";
		}
        }

        if ($postvalues != '') {
                $add_cmd .= "-d ".escapeshellarg($postvalues)." ";
        }

        exec("curl --cookie ~/.cookiejar --cookie-jar ~/.cookiejar -s -k -L -A 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0' $add_cmd".escapeshellarg($url), $out);

        return implode("\n", $out);
}

function make_tabs($text, $abstand = 4) {
	$encoding = @ini_get('default_charset');
	if ($encoding === false) $encoding = null;
	$ary = explode("\n", $text);
	$longest = 0;
	foreach ($ary as $a) {
		$bry = explode(':', $a, 2);
		if (count($bry) < 2) continue;
		$c = !is_null($encoding) ? mb_strlen($bry[0], $encoding) : strlen($bry[0]);
		if ($c > $longest) $longest = $c;
	}
	foreach ($ary as $n => $a) {
		$bry = explode(':', $a, 2);
		if (count($bry) < 2) continue;
		$c_ = !is_null($encoding) ? mb_strlen($bry[0], $encoding) : strlen($bry[0]);
		$rep = $longest - $c_ + $abstand;
		if ($rep < 1) {
			$wh = '';
		} else {
			$wh = str_repeat(' ', $rep);
		}
		$ary[$n] = $bry[0].':'.$wh.trim($bry[1]);
	}
	$x = implode("\n", $ary);
	return $x;
}

/**
 * Converts tabs to the appropriate amount of spaces while preserving formatting
 *
 * @author      Aidan Lister <aidan@php.net>
 * @version     1.2.0
 * @link        http://aidanlister.com/repos/v/function.tab2space.php
 * @param       string    $text     The text to convert
 * @param       int       $spaces   Number of spaces per tab column
 * @param       boolean   $html     Output as HTML or not
 * @return      string    The text with tabs replaced
 */
function tab2space($text, $spaces = 4, $html = false) {
	// Snippet from PHP Share: http://www.phpshare.org/scripts/Convert-Tabs-to-Spaces
	// Modified by Daniel Marschall: Added $html param

	// Explode the text into an array of single lines
	$lines = explode("\n", $text);

	// Loop through each line
	foreach ($lines as $line) {
		// Break out of the loop when there are no more tabs to replace
		while (false !== $tab_pos = strpos($line, "\t")) {
			// Break the string apart, insert spaces then concatenate
			$start = substr($line, 0, $tab_pos);
			$tab = str_repeat($html ? '&nbsp;' : '', $spaces - $tab_pos % $spaces);
			$end = substr($line, $tab_pos + 1);
			$line = $start . $tab . $end;
		}

		$result[] = $line;
	}

	return implode("\n", $result);
}

function trim_each_line($x) {
	$res = '';
	foreach (explode("\n", $x) as $y) {
		$res .= trim($y)."\n";
	}
	return $res;
}

function generateRandomString($length = 10) {
	$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
	$randomString = '';
	for ($i = 0; $i < $length; $i++) {
		$randomString .= $characters[rand(0, strlen($characters) - 1)];
	}
	return $randomString;
}

# http://stackoverflow.com/a/9361531
function _uniord($c) {
	if (ord($c[0]) >=0 && ord($c[0]) <= 127)
		return ord($c[0]);
	if (ord($c[0]) >= 192 && ord($c[0]) <= 223)
		return (ord($c[0])-192)*64 + (ord($c[1])-128);
	if (ord($c[0]) >= 224 && ord($c[0]) <= 239)
		return (ord($c[0])-224)*4096 + (ord($c[1])-128)*64 + (ord($c[2])-128);
	if (ord($c[0]) >= 240 && ord($c[0]) <= 247)
		return (ord($c[0])-240)*262144 + (ord($c[1])-128)*4096 + (ord($c[2])-128)*64 + (ord($c[3])-128);
	if (ord($c[0]) >= 248 && ord($c[0]) <= 251)
		return (ord($c[0])-248)*16777216 + (ord($c[1])-128)*262144 + (ord($c[2])-128)*4096 + (ord($c[3])-128)*64 + (ord($c[4])-128);
	if (ord($c[0]) >= 252 && ord($c[0]) <= 253)
		return (ord($c[0])-252)*1073741824 + (ord($c[1])-128)*16777216 + (ord($c[2])-128)*262144 + (ord($c[3])-128)*4096 + (ord($c[4])-128)*64 + (ord($c[5])-128);
	if (ord($c[0]) >= 254 && ord($c[0]) <= 255)    //  error
		return FALSE;
	return 0;
}

# urn:OID:2.0999 -> .2.999
function normalize_oid($oid, $leading_dot=true) {
	# remove urn:oid: and oid:
	$oid = preg_replace('@^(urn:oid:|oid:|)@i', '', $oid);

	# add leading dot if it does not already exist
	$oid = preg_replace('@^\.@', '', $oid);
	$oid = '.' . $oid;

	# remove leading zeros (requires leading dot)
	$oid = preg_replace('@\.0*([1-9])@', '.$1', $oid);

	if (!$leading_dot) {
		$oid = preg_replace('@^\\.@s', '', $oid);
	}

	return $oid;
}

function generateRandomToken($haystack, $length = 20) {
	do {
		$t = generateRandomString($length);
	} while (strpos($haystack, $t) !== false);
	return $t;
}

function github_latest_commit($author, $repo) {
	$cont = file_get_contents2("https://api.github.com/repos/$author/$repo/commits");
	if ($cont === false) return false;
	$json = json_decode($cont, true);
	if ($json === false) return false;
	return $json[0]['sha'] ?? false;
}
