<?php

#
#  generic Whois - Maintenance Framework Common Functions
#
#  (c) 2013-2015 Daniel Marschall, ViaThinkSoft [www.viathinksoft.de]
#
#  Distribution, usage etc. pp. regulated by the current version of GPL.
#
#
#  Version 2015-05-06
#

function getpatternfiles() {
	$out = array();

	# NEW FILES
	$files = glob(__DIR__ . '/../../main/pattern/'.'*');
	foreach ($files as &$file) {
		# see /usr/bin/gwhois
		if (preg_match('@\.dpkg-@', $file)) continue;
		if (preg_match('@\.orig$@', $file)) continue;
		if (preg_match('@\.bak$@',  $file)) continue;
		if (preg_match('@\.save$@', $file)) continue;
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
		$cont = file_get_contents($url, 0, $context);
		file_put_contents($cachefile, $cont);
	} else {
		$cont = file_get_contents($cachefile);
	}

	if ($cont === false) {
		throw new Exception("Failed to get contents from $url");
	}

	return $cont;
}
