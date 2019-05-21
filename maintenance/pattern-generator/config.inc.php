<?php

#
#  VGWhoIs (ViaThinkSoft Global WhoIs, a fork of generic Whois / gwhois)
#  Maintenance / Developer utilities
#
#  (c) 2012-2019 by Daniel Marschall, ViaThinkSoft <info@daniel-marschall.de>
#
#  License: https://www.gnu.org/licenses/gpl-2.0.html (GPL version 2)
#

require_once __DIR__ . '/../../shared/php_includes/config_functions.inc.php';
parse_config(__DIR__ . '/../config/vgwhois-pattern-update.conf');
parse_config(__DIR__ . '/../config/urls.conf');

define('PATTERN_DIR',          __DIR__ . '/../../main/pattern');
define('DOMAINS_PATTERN_FILE', PATTERN_DIR.'/domains');
define('CACHE_FILE_DIR',       __DIR__ . '/../.cache/web');
define('RIRSTATS_CACHE_DIR',   __DIR__ . '/../.cache/pattern-generator/rirstats');
