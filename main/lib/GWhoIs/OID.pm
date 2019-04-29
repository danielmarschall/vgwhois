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

package GWhoIs::OID;

use warnings;
use strict;

# urn:OID:2.0999 -> .2.999
sub GWhoIs::OID::normalize_oid($) {
	my $string = shift;

	# remove urn:oid: and oid:
	$string =~ s/^(urn:oid:|oid:|)//i;

	# add leading dot if it does not already exist
	$string =~ s/^\.//;
	$string = '.' . $string;

	# remove leading zeros (requires leading dot)
	$string =~ s/\.0*([1-9])/.$1/g;

	return $string;
}

# %oidpattern = GWhoIs::OID::getpatternoid()
sub GWhoIs::OID::getpatternoid {
	my (%pattern);
	my ($method,$host,$additional,$cline,$line);

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
			} elsif ( $line =~ /^(urn:){0,1}oid:/i ) {
				$line = GWhoIs::OID::normalize_oid($line);

				$pattern{$line}{'method'} = $method;
				$pattern{$line}{'host'}   = $host;
				$pattern{$line}{'add'}    = $additional;
			}
		}
	}
	return (%pattern);
}


# ($method, $host, $additional) = GWhoIs::OID::getmethodoid(@oid);
sub GWhoIs::OID::getmethodoid {
	my @arcs = @_;

	my $method = '';
	my $host = '';
	my $additional = '';

	my %pattern = GWhoIs::OID::getpatternoid();

	my $complete_oid = '';
	foreach my $arc (@arcs) {
		$complete_oid .= '.' if ($complete_oid ne '.');
		$complete_oid .= $arc;

		$complete_oid = GWhoIs::OID::normalize_oid($complete_oid);

		$method     = $pattern{$complete_oid}{'method'} if defined $pattern{$complete_oid}{'method'};
		$host       = $pattern{$complete_oid}{'host'}   if defined $pattern{$complete_oid}{'host'};
		$additional = $pattern{$complete_oid}{'add'}    if defined $pattern{$complete_oid}{'add'};
	}

	$host = $GWhoIs::Core::mirror{$method.$host} if defined $GWhoIs::Core::mirror{$method.$host};

	$host             =~ s/~oid~/$complete_oid/;
	$additional       =~ s/~oid~/$complete_oid/;

	return ($method,$host,$additional);
}

1;

