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
parse_config(__DIR__.'/../config/qa-monitor.conf');
parse_config(__DIR__.'/../config/urls.conf');

$anormale_whois=explode(' ', EXCLUDE_WHOIS);

define('WHOISPING_DB',     __DIR__ . '/../.cache/whois-server-ping/whoisping.db');
define('DEAD_SERVER_LIST', __DIR__ . '/../config/dead-servers.list');
