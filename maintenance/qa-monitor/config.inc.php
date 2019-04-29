<?php

#
#  VWhois (ViaThinkSoft WHOIS, a fork of generic Whois / gwhois)
#  Maintenance / Developer utilities
#
#  (c) 2012-2019 by Daniel Marschall, ViaThinkSoft <info@daniel-marschall.de>
#
#  License: https://www.gnu.org/licenses/gpl-2.0.html (GPL version 2)
#

require_once __DIR__ . '/../../shared/php_includes/config_functions.inc.php';
parse_config(__DIR__.'/../config/qa-monitor.conf');
parse_config(__DIR__.'/../config/urls.conf');

$anormale_whois=explode(' ', EXCLUDE_WHOIS);

define('WHOISPING_DB',     __DIR__ . '/../.cache/whois-server-ping/whoisping.db');
define('DEAD_SERVER_LIST', __DIR__ . '/../config/dead-servers.list');
