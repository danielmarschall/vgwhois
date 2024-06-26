#
#  VGWhoIs (ViaThinkSoft Global WhoIs, a fork of generic Whois / gwhois)
#  Main program
#
#  (c) 2010-2022 by Daniel Marschall, ViaThinkSoft <info@daniel-marschall.de>
#  based on the code (c) 1998-2010 by Juliane Holzt <debian@kju.de>
#  Some early parts by Lutz Donnerhacke <Lutz.Donnerhacke@Jena.Thur.de>
#
#  License: https://www.gnu.org/licenses/gpl-2.0.html (GPL version 2)
#

package VGWhoIs::Utils;

use warnings;
use strict;

use Encode;

# $result = VGWhoIs::Utils::lynxsource($url)
sub VGWhoIs::Utils::lynxsource {
	my ($url) = @_;
	$url = quotemeta($url);
# LYNX sometimes hangs in combination with TOR
#	return qx{lynx -connect_timeout=10 -source $url};
	return qx{curl --insecure --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36" --silent --max-time 10 $url};
}

sub VGWhoIs::Utils::lynxrender {
	my ($url) = @_;
	$url = quotemeta($url);

	use File::Basename;
	my $script_dir = undef;
	if(-l __FILE__) {
		$script_dir = dirname(readlink(__FILE__));
	} else {
		$script_dir = dirname(__FILE__);
	}
	$script_dir = quotemeta($script_dir);

	my $result = qx{lynx -cfg $script_dir/../lynx.cfg -dump -connect_timeout=10 $url 2>&1};
	$result .= "FAILED with exit code $?\n\n" if $?;
	return $result;
}

# $line = htmlpre($line);
sub VGWhoIs::Utils::htmlpre {
	my ($line) = @_;
	$line =~ s|\n|<br>|g;
	$line =~ s| |&nbsp;|g;
	return $line;
}

# $rendered = VGWhoIs::Utils::render_html($html);
sub VGWhoIs::Utils::render_html {
	my ($html) = @_;

	return '' if !defined $html;

	$html =~ s|<!--.*?-->||gsi;

	$html =~ s|<pre>(.*?)</pre>|VGWhoIs::Utils::htmlpre($1)|gsei;
	$html =~ s|<textarea>(.*?)</textarea>|VGWhoIs::Utils::htmlpre($1)|gsei;

	#TODO: big problem here: if the output is "content-type: text/plain", then we must not call render_html!!!
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


sub VGWhoIs::Utils::trim($) {
	# Source: http://www.somacon.com/p114.php
	my $string = shift;
	$string =~ s/^\s+//;
	$string =~ s/\s+$//;
	return $string; # TODO: ein push faende ich besser
}

sub VGWhoIs::Utils::is_uc($) {
	my $str = shift;

	my $char;
	foreach $char (split //, $str) {
		return 1 if (ord($char) > 255);
	}

	return 0;
}

sub VGWhoIs::Utils::is_ascii($) {
	my $str = shift;

	my $char;
	foreach $char (split //, $str) {
		return 0 if (ord($char) >= 128);
	}

	return 1;
}

sub VGWhoIs::Utils::is_utf8($) {
	my $str = shift;

	my $s = eval { Encode::decode('utf8', $str, Encode::FB_CROAK) };
	return defined($s);

	# This procedure does not work :-( VGWhoIs::Utils::is_utf8 and valid are true even if they should not...
	# return 1 if utf8::VGWhoIs::Utils::is_utf8($str);
	# return 0 if VGWhoIs::Utils::is_uc($str);
	# return 1 if (Encode::Detect::Detector::detect($str) eq "UTF-8");
	# return utf8::valid($str);
}

sub VGWhoIs::Utils::enforce_utf8($) {
	my $str = shift;

	if (VGWhoIs::Utils::is_uc($str)) {
		$str =~ s/^\x{FEFF}//;
		utf8::encode($str);
	}
	elsif (!VGWhoIs::Utils::is_utf8($str)) {
		$str =~ s/^\xEF\xBB\xBF//;
		utf8::encode($str);
	}

	return $str;
}

# ($protocol, $hostname) = VGWhoIs::Utils::splitProtocolHost($url)
sub VGWhoIs::Utils::splitProtocolHost($) {
	my $url = shift;

	my ($protocol, $hostname) = $url =~ /(https{0,1}):\/\/([^\/]+)/;

	return ($protocol, $hostname);
}

1;

