<?php

#
#  Grep Functions for PHP
#
#  (c) 2012-2013 Daniel Marschall, ViaThinkSoft [www.viathinksoft.de]
#
#  Distribution, usage etc. pp. regulated by the current version of GPL.
#
#
#  Version 2013-03-08
#

# TODO: if console available, use it

// "grep"
function grep(&$array, $substr) {
	if (!is_array($array)) return false;
	$ret = array();
	foreach ($array as &$a) {
		if (strpos($a, $substr) !== false) $ret[] = $a;
	}
	return $ret;
}

// "grep -v"
function antigrep(&$array, $substr) {
	if (!is_array($array)) return false;
	$ret = array();
	foreach ($array as &$a) {
		if (strpos($a, $substr) === false) $ret[] = $a;
	}
	return $ret;
}

?>
