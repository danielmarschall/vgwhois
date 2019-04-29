package GWhoIs::IPv6;

use warnings;
use strict;

# install with "cpan Net::IP" or "aptitude install libnet-ip-perl"
use Net::IP;

# at Debian: install with "aptitude install libmath-bigint-gmp-perl"
use Math::BigInt;

# %v6pattern = GWhoIs::IPv6::getpatternv6()
sub GWhoIs::IPv6::getpatternv6 {
	my (%pattern);
	my ($method,$host,$additional,$cline,$line,$rehost,$readditional);

	foreach my $patternfile (GWhoIs::Core::getpatternfiles()) {
		open(PATTERN,"<$patternfile") || die "Cannot open $patternfile. STOP.\n";

		while ( defined($line = <PATTERN>) ) {
			# chomp $line;
			$line = GWhoIs::Utils::trim($line);

			if ( $line =~ /^#/ ) {                       # comment
			} elsif ( ($cline) = $line =~ /^:(.*)$/ ) {  # method declaration
				($method,$host,$additional) = split(/\|/,$cline,3);
				$method=''     if !defined $method;
				$host=''       if !defined $host;
				$additional='' if !defined $additional;
			} elsif (( $line =~ /^=/ ) && ($line =~ /:/)) { # do not read IPv4 lines (not containing ':')
				($rehost,$readditional) = GWhoIs::Core::methodpatternregex('',$host,$additional,$line);

				# Store the IP inside the CIDR as integer-notation.
				($line) = $line =~ /^=(.*)$/;           # remove leading "="
				my ($ipv6,$bits) = split(/\//,$line,2); # split into IP address and CIDR
				$ipv6 = Net::IP::ip_expand_address($ipv6, 6);    # Expand the IP address in case it uses nested syntax or something
				$bits = 128 if ($bits eq '');           # if no CIDR was found, assume it is a single IPv6 address
				my ($ipa,$ipb,$ipc,$ipd,$ipe,$ipf,$ipg,$iph) = split(/:/,$ipv6,8);
				$ipa = defined $ipa ? Math::BigInt->new(hex($ipa)) : 0;
				$ipb = defined $ipb ? Math::BigInt->new(hex($ipb)) : 0;
				$ipc = defined $ipc ? Math::BigInt->new(hex($ipc)) : 0;
				$ipd = defined $ipd ? Math::BigInt->new(hex($ipd)) : 0;
				$ipe = defined $ipe ? Math::BigInt->new(hex($ipe)) : 0;
				$ipf = defined $ipf ? Math::BigInt->new(hex($ipf)) : 0;
				$ipg = defined $ipg ? Math::BigInt->new(hex($ipg)) : 0;
				$iph = defined $iph ? Math::BigInt->new(hex($iph)) : 0;
				my $ip = $ipa<<112|$ipb<<96|$ipc<<80|$ipd<<64|$ipe<<48|$ipf<<32|$ipg<<16|$iph;

				my $cidr = "$ip/$bits";

				$pattern{$cidr}{'method'} = $method;
				$pattern{$cidr}{'host'}   = $rehost;
				$pattern{$cidr}{'add'}    = $readditional;
			}
		}
	}
	return (%pattern);
}


# ($method, $host, $additional) = GWhoIs::IPv6::getmethodv6($ipv6);
sub GWhoIs::IPv6::getmethodv6 {
	my ($ipv6) = @_;
	$ipv6 = Net::IP::ip_expand_address($ipv6, 6);
	my ($ipa,$ipb,$ipc,$ipd,$ipe,$ipf,$ipg,$iph) = split(/:/,$ipv6,8);

	$ipa = defined $ipa ? Math::BigInt->new(hex($ipa)) : 0;
	$ipb = defined $ipb ? Math::BigInt->new(hex($ipb)) : 0;
	$ipc = defined $ipc ? Math::BigInt->new(hex($ipc)) : 0;
	$ipd = defined $ipd ? Math::BigInt->new(hex($ipd)) : 0;
	$ipe = defined $ipe ? Math::BigInt->new(hex($ipe)) : 0;
	$ipf = defined $ipf ? Math::BigInt->new(hex($ipf)) : 0;
	$ipg = defined $ipg ? Math::BigInt->new(hex($ipg)) : 0;
	$iph = defined $iph ? Math::BigInt->new(hex($iph)) : 0;

	my ($ip, $bits, $netmask, $method, $host, $additional, %pattern);

	$ip      = $ipa<<112|$ipb<<96|$ipc<<80|$ipd<<64|$ipe<<48|$ipf<<32|$ipg<<16|$iph;
	$netmask = Math::BigInt->new(65536)**8-1;
	%pattern = GWhoIs::IPv6::getpatternv6();
	$method  = '';

	for ($bits=128; $bits>=0 && $method eq ''; $bits--) {
		$ip        = $ip & $netmask;
		$netmask <<= 1;

		my $cidr = "$ip/$bits";

		$method     = $pattern{$cidr}{'method'} if defined $pattern{$cidr}{'method'};
		$host       = $pattern{$cidr}{'host'}   if defined $pattern{$cidr}{'host'};
		$additional = $pattern{$cidr}{'add'}    if defined $pattern{$cidr}{'add'};
	}

	$host = $GWhoIs::Core::mirror{$method.$host} if defined $GWhoIs::Core::mirror{$method.$host};
	return ($method,$host,$additional);
}

1;

