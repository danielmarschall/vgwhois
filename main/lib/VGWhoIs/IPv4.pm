#
#  VGWhoIs (ViaThinkSoft Global WhoIs, a fork of generic Whois / gwhois)
#  Main program
#
#  (c) 2010-2019 by Daniel Marschall, ViaThinkSoft <info@daniel-marschall.de>
#  based on the code (c) 1998-2010 by Juliane Holzt <debian@kju.de>
#  Some early parts by Lutz Donnerhacke <Lutz.Donnerhacke@Jena.Thur.de>
#
#  License: https://www.gnu.org/licenses/gpl-2.0.html (GPL version 2)
#

package VGWhoIs::IPv4;

use warnings;
use strict;

# install with "cpan Net::IP" or "aptitude install libnet-ip-perl"
use Net::IP;

# %v4pattern = VGWhoIs::IPv4::getpatternv4()
sub VGWhoIs::IPv4::getpatternv4 {
	my (%pattern);
	my ($method,$host,$additional,$cline,$line,$rehost,$readditional);

	foreach my $patternfile (VGWhoIs::Core::getpatternfiles()) {
		open(PATTERN,"<$patternfile") || die "Cannot open $patternfile. STOP.\n";

		while ( defined($line = <PATTERN>) ) {
			# chomp $line;
			$line = VGWhoIs::Utils::trim($line);

			if ( $line =~ /^#/ ) {                       # comment
			} elsif ( ($cline) = $line =~ /^:(.*)$/ ) {  # method declaration
				($method,$host,$additional) = split(/\|/,$cline,3);
				$method=''     if !defined $method;
				$host=''       if !defined $host;
				$additional='' if !defined $additional;
			} elsif (( $line =~ /^=/ ) && ($line !~ /:/)) { # do not read IPv6 lines (containing ':')
				($rehost,$readditional) = VGWhoIs::Core::methodpatternregex('',$host,$additional,$line);

				# Store the IP inside the CIDR as integer-notation. So, the pattern "001.2.3.4" will be recognized as "1.2.3.4" too.
				($line) = $line =~ /^=(.*)$/;           # remove leading "="
				my ($ipv4,$bits) = split(/\//,$line,2); # split into IP address and CIDR
				$ipv4 = Net::IP::ip_expand_address($ipv4, 4);    # Expand the IP address in case it uses shortened syntax or something
				$bits = 32 if ($bits eq '');            # if no CIDR was found, assume it is a single IPv4 address
				my ($ipa,$ipb,$ipc,$ipd) = split(/\./,$ipv4,4);
				$ipa=0 if (!defined $ipa);
				$ipb=0 if (!defined $ipb);
				$ipc=0 if (!defined $ipc);
				$ipd=0 if (!defined $ipd);
				my $ip = $ipa<<24|$ipb<<16|$ipc<<8|$ipd;

				my $cidr = "$ip/$bits";

				$pattern{$cidr}{'method'} = $method;
				$pattern{$cidr}{'host'}   = $rehost;
				$pattern{$cidr}{'add'}    = $readditional;
			}
		}
	}
	return (%pattern); # TODO: might be undefined
}

# ($method, $host, $additional) = VGWhoIs::IPv4::getmethodv4($ipa, $ipb, $ipc, $ipd);
sub VGWhoIs::IPv4::getmethodv4 {
	my ($ipa, $ipb, $ipc, $ipd) = @_;
	my ($ip, $bits, $netmask, $method, $host, $additional, %pattern);

	$ip      = $ipa<<24 | $ipb<<16 | $ipc<<8 | $ipd;
	$netmask = 256**4-1;
	%pattern = VGWhoIs::IPv4::getpatternv4();
	$method  = '';

	for ($bits=32; $bits>=0 && $method eq ''; $bits--) {
		$ip        = $ip & $netmask;
		$netmask <<= 1;

		my $cidr = "$ip/$bits";

		$method     = $pattern{$cidr}{'method'} if defined $pattern{$cidr}{'method'};
		$host       = $pattern{$cidr}{'host'}   if defined $pattern{$cidr}{'host'};
		$additional = $pattern{$cidr}{'add'}    if defined $pattern{$cidr}{'add'};
	}

	$host = $VGWhoIs::Core::mirror{$method.$host} if defined $VGWhoIs::Core::mirror{$method.$host};
	return ($method,$host,$additional); # TODO: might be undefined (+ everywhere else)
}

1;

