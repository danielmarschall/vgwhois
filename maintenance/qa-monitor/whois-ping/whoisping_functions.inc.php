<?php

#
#  generic Whois - Whois Server Ping Testing Suite
#
#  (c) 2013-2014 Daniel Marschall, ViaThinkSoft [www.viathinksoft.de]
#
#  Distribution, usage etc. pp. regulated by the current version of GPL.
#
#
#  Version 2014-11-19
#

# FUT: sqlinj und cmdinj beheben

function gwitc_initdb($db) {
	# "CREATE TABLE IF NOT EXISTS" does not work with my version of PHP/SQLite
	$stm = "CREATE TABLE IF NOT EXISTS gwi_tc_whois_ping (
		id INTEGER PRIMARY KEY,
		server TEXT UNIQUE,
		fails INTEGER,
		lastcheck INTEGER,
		lastsucc INTEGER,
		firstfail INTEGER,
		lastfail INTEGER,
		reborn INTEGER
	)";
	$db->exec($stm);
}

function gwitc_checkage_succ($db, $server) {
	$stm = "SELECT lastsucc FROM gwi_tc_whois_ping WHERE server = '$server'";
	$result = $db->query($stm);
	if (!$result) die("Cannot execute query.");
	$row = $result->fetchArray(SQLITE3_ASSOC);
	$ts = (int)$row['lastsucc'];
	$now = time();

	return ($now-$ts);
}

function gwitc_checkage_check($db, $server) {
	$stm = "SELECT lastcheck FROM gwi_tc_whois_ping WHERE server = '$server'";
	$result = $db->query($stm);
	if (!$result) die("Cannot execute query.");
	$row = $result->fetchArray(SQLITE3_ASSOC);
	$ts = (int)$row['lastcheck'];
	$now = time();

	return ($now-$ts);
}

function gwitc_reborn_val($db, $server) {
	$stm = "SELECT reborn FROM gwi_tc_whois_ping WHERE server = '$server'";
	$result = $db->query($stm);
	if (!$result) die("Cannot execute query.");
	$row = $result->fetchArray(SQLITE3_ASSOC);
	return (int)$row['reborn'];
}

function gwitc_fail_duration($db, $server) {
	$stm = "SELECT firstfail,lastsucc,lastfail FROM gwi_tc_whois_ping WHERE server = '$server'";
	$result = $db->query($stm);
	if (!$result) die("Cannot execute query.");
	$row = $result->fetchArray(SQLITE3_ASSOC);
	$lastsucc = (int)$row['lastsucc'];
	$firstfail = (int)$row['firstfail'];
	$lastfail = (int)$row['lastfail'];

	if ($firstfail == 0) return 0;
	if ($lastsucc > $lastfail) return 0;

	return ($lastfail-max($lastsucc,$firstfail));
}

function gwitc_first_fail($db, $server) {
	$stm = "SELECT firstfail,lastsucc FROM gwi_tc_whois_ping WHERE server = '$server'";
	$result = $db->query($stm);
	if (!$result) die("Cannot execute query.");
	$row = $result->fetchArray(SQLITE3_ASSOC);
	$lastsucc = (int)$row['lastsucc'];
	$firstfail = (int)$row['firstfail'];

	if ($firstfail == 0) return 0;

	return max($firstfail,$lastsucc);
}

function gwitc_set_reborn($db, $server, $val) {
	$stm = "SELECT fails,lastsucc,firstfail FROM gwi_tc_whois_ping WHERE server = '$server'";
	$result = $db->query($stm);
	if (!$result) die("Cannot execute query.");
	$row = $result->fetchArray(SQLITE3_ASSOC);
	$fails = 0; // (int)$row['fails'];
	$ts = time();
	$lastsucc = $ts; // (int)$row['lastsucc'];
	$firstfail = 0; // (int)$row['firstfail'];
	$stm = "REPLACE INTO gwi_tc_whois_ping (server,fails,lastcheck,lastsucc,lastfail,firstfail,reborn) VALUES ('$server', $fails, $ts, $lastsucc, $ts, $firstfail, $val)";
	$ok = $db->exec($stm);
	if (!$ok) die("Cannot execute query.");

	return $fails;
}

function gwitc_incr_failcounter($db, $server) {
	$stm = "SELECT fails,lastsucc,firstfail FROM gwi_tc_whois_ping WHERE server = '$server'";
	$result = $db->query($stm);
	if (!$result) die("Cannot execute query.");
	$row = $result->fetchArray(SQLITE3_ASSOC);
	$fails = (int)$row['fails'];
	$lastsucc = (int)$row['lastsucc'];

	$fails++;
	$ts = time();
	$firstfail = ($fails == 1) ? $ts : (int)$row['firstfail'];
	$reborn = 0; // wenn er failed ist, kann er nicht reborned sein

	$stm = "REPLACE INTO gwi_tc_whois_ping (server,fails,lastcheck,lastsucc,lastfail,firstfail,reborn) VALUES ('$server', $fails, $ts, $lastsucc, $ts, $firstfail, $reborn)";
	$ok = $db->exec($stm);
	if (!$ok) die("Cannot execute query.");

	return $fails;
}

function gwitc_reset_failcounter($db, $server) {
	$stm = "SELECT lastfail,reborn FROM gwi_tc_whois_ping WHERE server = '$server'";
	$result = $db->query($stm);
	if (!$result) die("Cannot execute query.");
	$row = $result->fetchArray(SQLITE3_ASSOC);
	$lastfail = (int)$row['lastfail'];
	$ts = time();
	$reborn = (int)$row['reborn'];

	$stm = "REPLACE INTO gwi_tc_whois_ping (server,fails,lastcheck,lastsucc,lastfail,firstfail,reborn) VALUES ('$server', 0, $ts, $ts, $lastfail, 0, $reborn)";
	$ok = $db->exec($stm);
	if (!$ok) die("Cannot execute query.");
}

function gwitc_list_whois_servers($patternfile) {
	$out = array();
	$cont = file($patternfile);
	foreach ($cont as &$x) {
		$x = trim($x);
		if ($x == '') continue;
		if ($x[0] == '#') continue;
		if ((preg_match('@^:whois\|(.+)\|@isU', $x.'|', $m)) || (preg_match('@whois::(.+):@isU', $x.':', $m))) {
			$out[] = $m[1];
		}
	}
	$out = array_unique($out);
	return $out;
}
