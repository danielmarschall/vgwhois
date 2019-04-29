#
#  VWhois (ViaThinkSoft WHOIS, a fork of generic Whois / gwhois)
#  Main program
#
#  (c) 2010-2019 by Daniel Marschall, ViaThinkSoft <info@daniel-marschall.de>
#  based on the code (c) 1998-2010 by Juliane Holzt <debian@kju.de>
#  Some early parts by Lutz Donnerhacke <Lutz.Donnerhacke@Jena.Thur.de>
#
#  License: https://www.gnu.org/licenses/gpl-2.0.html (GPL version 2)
#

package GWhoIs::Utils;

use warnings;
use strict;

use Encode;

# $result = GWhoIs::Utils::lynxsource($url)
sub GWhoIs::Utils::lynxsource {
	my ($url) = @_;
	$url = quotemeta($url);
# LYNX sometimes hangs in combination with TOR
#	return qx{lynx -connect_timeout=10 -source $url};
	return qx{curl --user-agent "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0" --silent --max-time 10 $url};
}

# $line = htmlpre($line);
sub GWhoIs::Utils::htmlpre {
	my ($line) = @_;
	$line =~ s|\n|<br>|g;
	$line =~ s| |&nbsp;|g;
	return $line;
}

# $rendered = GWhoIs::Utils::render_html($html);
sub GWhoIs::Utils::render_html {
	my ($html) = @_;

	return '' if !defined $html;

	$html =~ s|<!--.*?-->||gsi;

	$html =~ s|<pre>(.*?)</pre>|GWhoIs::Utils::htmlpre($1)|gsei;
	$html =~ s|<textarea>(.*?)</textarea>|GWhoIs::Utils::htmlpre($1)|gsei;

	$html =~ s|\n| |g;

	$html =~ s|<p\s*/{0,1}\s*>|\n|gsi;
	$html =~ s|<p\s.*?>|\n|gsi;

	$html =~ s|<tr\s*/{0,1}\s*>|\n|gsi;
	$html =~ s|<tr\s.*?>|\n|gsi;
	$html =~ s|<td>| |gsi;

	$html =~ s|<script.*?</script>||gsi;
	$html =~ s|<style.*?</style>||gsi;

	$html =~ s| \t| |gsi;
	$html =~ s|\s*\n\s*\n|\n|gsi;
	$html =~ s|^\s*||gm;

	$html =~ s|&nbsp;| |gsi;
	$html =~ s|<br\s*/{0,1}\s*>|\n|gsi;
	$html =~ s|<br\s.*?>|\n|gsi;
	$html =~ s|\<.*?\>||gsi;

	return($html);
}


sub GWhoIs::Utils::trim($) {
	# Source: http://www.somacon.com/p114.php
	my $string = shift;
	$string =~ s/^\s+//;
	$string =~ s/\s+$//;
	return $string; # TODO: ein push faende ich besser
}

sub GWhoIs::Utils::is_uc($) {
	my $str = shift;

	my $char;
	foreach $char (split //, $str) {
		return 1 if (ord($char) > 255);
	}

	return 0;
}

sub GWhoIs::Utils::is_ascii($) {
	my $str = shift;

	my $char;
	foreach $char (split //, $str) {
		return 0 if (ord($char) >= 128);
	}

	return 1;
}

sub GWhoIs::Utils::is_utf8($) {
	my $str = shift;

	my $s = eval { Encode::decode('utf8', $str, Encode::FB_CROAK) };
	return defined($s);

	# This procedure does not work :-( GWhoIs::Utils::is_utf8 and valid are true even if they should not...
	# return 1 if utf8::GWhoIs::Utils::is_utf8($str);
	# return 0 if GWhoIs::Utils::is_uc($str);
	# return 1 if (Encode::Detect::Detector::detect($str) eq "UTF-8");
	# return utf8::valid($str);
}

sub GWhoIs::Utils::enforce_utf8($) {
	my $str = shift;

	if (GWhoIs::Utils::is_uc($str)) {
		$str =~ s/^\x{FEFF}//;
		utf8::encode($str);
	}
	elsif (!GWhoIs::Utils::is_utf8($str)) {
		$str =~ s/^\xEF\xBB\xBF//;
		utf8::encode($str);
	}

	return $str;
}

# ($protocol, $hostname) = GWhoIs::Utils::splitProtocolHost($url)
sub GWhoIs::Utils::splitProtocolHost($) {
	my $url = shift;

	my ($protocol, $hostname) = $url =~ /(https{0,1}):\/\/([^\/]+)/;

	return ($protocol, $hostname);
}

1;

