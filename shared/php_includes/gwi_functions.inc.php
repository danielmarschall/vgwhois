<?php

#
#  VGWhoIs (ViaThinkSoft Global WhoIs, a fork of generic Whois / gwhois)
#  Common functions in PHP
#
#  (c) 2013-2024 by Daniel Marschall, ViaThinkSoft <info@daniel-marschall.de>
#
#  License: https://www.gnu.org/licenses/gpl-2.0.html (GPL version 2)
#

function getpatternfiles() {
	$out = array();

	$files = glob(__DIR__ . '/../../main/pattern/'.'*');
	foreach ($files as &$file) {
		if (preg_match('@^\.@',     $file)) continue;

		$out[] = $file;
	}

	return $out;
}

function get_united_pattern() {
	$cont = '';

	$files = getpatternfiles();
	foreach ($files as &$file) {
		$cont .= file_get_contents($file)."\n\n";
	}

	return $cont;
}

function cached_file($url, $cache_dir, $max_age = /* 24*60*60 */ 86400) {
	$opts = [
	    "http" => [
	        "method" => "GET",
	        "header" => "User-Agent: Google Chrome Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36.\r\n"
	    ]
	];
	$context = stream_context_create($opts);

	$cachefile = $cache_dir . '/' . sha1($url) . '.cache';
	if (!is_dir($cache_dir)) mkdir($cache_dir, 0755, true);
	if (file_age($cachefile) > $max_age) {
		$cont = file_get_contents($url, false, $context);
		if ($cont !== false) file_put_contents($cachefile, $cont);
	} else {
		$cont = file_get_contents($cachefile);
	}

	if ($cont === false) {
		throw new Exception("Failed to get contents from $url");
	}

	return $cont;
}
