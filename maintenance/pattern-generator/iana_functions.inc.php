<?php

#
#  generic Whois - Automatic Pattern Generator: TLD
#
#  (c) 2012 Daniel Marschall, ViaThinkSoft [www.viathinksoft.de]
#
#  Distribution, usage etc. pp. regulated by the current version of GPL.
#
#
#  Version 2014-04-31
#

require_once __DIR__ . '/config.inc.php';

define('IANA_CACHE_DIR', __DIR__ . '/../.cache/pattern-generator/iana');
define('IANA_TLD_CACHE', IANA_CACHE_DIR . '/tlds-alpha-by-domain.txt');

function get_iana_tld_data() {
	if ((USE_CACHE) && (file_exists(IANA_TLD_CACHE))) {
		@mkdir(dirname(IANA_TLD_CACHE), 0777, true);
		return file(IANA_TLD_CACHE, FILE_IGNORE_NEW_LINES);
	} else {
		return file(IANA_TLD_REGISTRY, FILE_IGNORE_NEW_LINES);
	}
}
