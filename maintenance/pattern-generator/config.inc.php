<?php

#
#  generic Whois - Automatic Pattern Generator configuration
#
#  (c) 2012-2015 Daniel Marschall, ViaThinkSoft [www.viathinksoft.de]
#
#  Distribution, usage etc. pp. regulated by the current version of GPL.
#
#
#  Version 2015-04-17
#

require_once __DIR__ . '/../../shared/php_includes/config_functions.inc.php';
parse_config(__DIR__ . '/../config/gwhois-pattern-update.conf');
parse_config(__DIR__ . '/../config/urls.conf');

define('PATTERN_DIR',          __DIR__ . '/../../main/pattern');
define('DOMAINS_PATTERN_FILE', PATTERN_DIR.'/domains');
define('CACHE_FILE_DIR',       __DIR__ . '/../.cache/web');
define('RIRSTATS_CACHE_DIR',   __DIR__ . '/../.cache/pattern-generator/rirstats');
