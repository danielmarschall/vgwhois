<?php

#
#  generic Whois - Automatic Pattern Generator configuration
#
#  (c) 2012-2018 Daniel Marschall, ViaThinkSoft [www.viathinksoft.de]
#
#  Distribution, usage etc. pp. regulated by the current version of GPL.
#
#
#  Version 2018-10-26
#

function parse_config($file) {
	if (!file_exists($file)) return false;

	$count = 0;

	$cont = file($file);
	foreach ($cont as $c) {
		$c = trim($c);

		if ($c == '') continue;
		if ($c[0] == '#') continue;

		$c = preg_replace('@(.+)\\s#.+$@U', '\\1', $c);

		$ary = explode('=', $c, 2);
		$name = trim($ary[0]);
		$val = trim($ary[1]);

		// true/false does not work for bash, so we do not accept it here either
		/*
		if (strtolower($val) === 'no') $val = false;
		if (strtolower($val) === 'false') $val = false;
		if (strtolower($val) === 'yes') $val = true;
		if (strtolower($val) === 'true') $val = true;
		*/

		$val = str_strip_quotes($val);

		define($name, $val);
		$count++;
	}

	return $count;
}

function str_strip_quotes($x) {
	if (((substr($x,0,1) == '"') && (substr($x,-1,1) == '"')) ||
	    ((substr($x,0,1) == "'") && (substr($x,-1,1) == "'"))) {
		return substr($x,1,strlen($x)-2);
	} else {
		return $x;
	}
}

