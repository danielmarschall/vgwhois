<?php

#
#  VGWhoIs (ViaThinkSoft Global WhoIs, a fork of generic Whois / gwhois)
#  Maintenance / Developer utilities
#
#  (c) 2012-2019 by Daniel Marschall, ViaThinkSoft <info@daniel-marschall.de>
#
#  License: https://www.gnu.org/licenses/gpl-2.0.html (GPL version 2)
#

$rirs = array('afrinic', 'apnic', 'arin', 'lacnic', 'ripencc');
# IANA is not a "real" RIR - to enable, please add "iana" manually:
# $rirs[] = 'iana';

// Extended format also has "reserved" and "available" resources!
// I have contacted the NRO EC in Apr 2012 to suggest that the other RIRs also use that extended format,
// so that the statistics can also show available and reserved blocks
// APNIC    supports extended RIR statistics exchange format since 2008-02-14 .
// RIPE NCC supports extended RIR statistics exchange format since 2012-05-23 .
// LACNIC   supports extended RIR statistics exchange format since 2012-06-28 .
// AfriNIC  supports extended RIR statistics exchange format since 2012-10-02 .
// ARIN     supports extended RIR statistics exchange format since 2013-03-05 . (First publication 2013-02-16 , revoked due to problems )
$supports_extended_rirstat = array();
$supports_extended_rirstat['afrinic'] = true;
$supports_extended_rirstat['apnic']   = true;
$supports_extended_rirstat['arin']    = true; // must always be true, since they discontinued the old stats
$supports_extended_rirstat['lacnic']  = true;
$supports_extended_rirstat['ripencc'] = true;
$supports_extended_rirstat['iana']    = false;

$rir_whois_server = array();
$rir_whois_server['afrinic'] = 'whois.afrinic.net';
$rir_whois_server['apnic']   = 'whois.apnic.net';
$rir_whois_server['arin']    = 'whois.arin.net';
$rir_whois_server['lacnic']  = 'whois.lacnic.net';
$rir_whois_server['ripencc'] = 'whois.ripe.net';
$rir_whois_server['iana']    = 'whois.iana.org';

$rir_domain = array();
$rir_domain['afrinic'] = 'afrinic.net';
$rir_domain['apnic']   = 'apnic.net';
$rir_domain['arin']    = 'arin.net';
$rir_domain['lacnic']  = 'lacnic.net';
$rir_domain['ripencc'] = 'ripe.net';
$rir_domain['iana']    = 'iana.org';

// If the RIR offers and extended format, use it instead!
// Alternative address: ftp://ftp.iana.org/pub/mirror/rirstats/
$rirstat_urls = array();
$rirstat_urls['afrinic'] = 'ftp://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest';
$rirstat_urls['apnic']   = 'ftp://ftp.apnic.net/pub/stats/apnic/delegated-apnic-extended-latest';
$rirstat_urls['arin']    = 'ftp://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest';
$rirstat_urls['lacnic']  = 'ftp://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest';
$rirstat_urls['ripencc'] = 'ftp://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest';
$rirstat_urls['iana']    = 'ftp://ftp.apnic.net/pub/stats/iana/delegated-iana-latest'; # This is a service by apnic.net . IANA is not running a public service, NRO EC resolution needed

$ipv4_additional_params = array();
$ipv4_additional_params['afrinic'] = '';
$ipv4_additional_params['apnic']   = '';
$ipv4_additional_params['arin']    = 'n ';
$ipv4_additional_params['lacnic']  = '';
$ipv4_additional_params['ripencc'] = '';
$ipv4_additional_params['iana']    = '';

$ipv6_additional_params = array();
$ipv6_additional_params['afrinic'] = '';
$ipv6_additional_params['apnic']   = '';
$ipv6_additional_params['arin']    = 'n ';
$ipv6_additional_params['lacnic']  = '';
$ipv6_additional_params['ripencc'] = '';
$ipv6_additional_params['iana']    = '';

$asn_additional_params = array();
$asn_additional_params['afrinic'] = '';
$asn_additional_params['apnic']   = '';
$asn_additional_params['arin']    = 'a ';
$asn_additional_params['lacnic']  = '';
$asn_additional_params['ripencc'] = '';
$asn_additional_params['iana']    = '';

$tld_additional_params = array();
$tld_additional_params['afrinic'] = '';
$tld_additional_params['apnic']   = '';
$tld_additional_params['arin']    = 'z '; # ???
$tld_additional_params['lacnic']  = '';
$tld_additional_params['ripencc'] = '';
$tld_additional_params['iana']    = '';

// Output unfiltered results for ARIN
if ((defined('ENABLE_UNFILTERED_ARIN_OUTPUT')) && (ENABLE_UNFILTERED_ARIN_OUTPUT)) {
	$ipv6_additional_params['arin'] .= '+ ';
	$ipv4_additional_params['arin'] .= '+ ';
	$asn_additional_params['arin']  .= '+ ';
}

// Output unfiltered results for RIPE
if ((defined('ENABLE_UNFILTERED_RIPE_OUTPUT')) && (ENABLE_UNFILTERED_RIPE_OUTPUT)) {
	$ipv6_additional_params['ripencc'] .= '-B ';
	$ipv4_additional_params['ripencc'] .= '-B ';
	$asn_additional_params['ripencc']  .= '-B ';
}
