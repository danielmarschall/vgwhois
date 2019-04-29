package GWhoIs::Core;

use warnings;
use strict;

use LWP::Simple;

use FindBin;
use lib "$FindBin::RealBin/../";
use GWhoIs::Utils;

use List::Util 'max';

$GWhoIs::Core::confdir = "$FindBin::RealBin/pattern/";

# DM 11.09.2017: There is a weird bug: If I use TOR in combination with LWP on a Gopher protocol, I get error 500.
$GWhoIs::Core::useLWP = 0;

$GWhoIs::Core::antispam = 1; # default: on
$GWhoIs::Core::step = 1;

# Wieso muss das nicht deklariert werden? (Fehlermeldung "useless use")
#%GWhoIs::Core::mirror;

# ($result, $exitcode) = GWhoIs::Core::getsource($url)
sub GWhoIs::Core::getsource {
	my ($url) = @_;
	my $text = $GWhoIs::Core::useLWP ? LWP::Simple::get($url) : GWhoIs::Utils::lynxsource($url);
	my $exitcode = defined($text) ? 0 : 1; # TODO: a better way to detect an error
	return ($text, $exitcode);
}

# ($result, $exitcode) = GWhoIs::Core::whoisaccess($host,$port,$query)
sub GWhoIs::Core::whoisaccess {
	my ($host,$port,$query) = @_;

	$query =~ s/ /%20/g;

	my ($result, $exitcode) = GWhoIs::Core::getsource("gopher://$host:$port/0$query");
	if ($exitcode) {
		$result .= "Query to whois server failed.\n";
	}
	$result =~ s/\x0D//g; # remove CR from output

	return ($result, $exitcode);
}

# ($result, $exitcode) = GWhoIs::Core::inicwhoisaccess($host,$port,$query)
sub GWhoIs::Core::inicwhoisaccess { # todo: mehr als 1 redirect möglich, z.b. bei rwhois??
#TODO: hier auch $mirror unterstützung?
	my ($host,$port,$query) = @_;
	my ($queryresult, $result);
	my $exitcode;

	($queryresult, $exitcode) = GWhoIs::Core::whoisaccess($host,$port,"=$query");

	# Result von NSI-Registry auf relevanten Part absuchen
	if ( $queryresult =~ /Name:\s+$query\s/mi ) {
		$result = "-- From: $host:$port\n\n";
		($host) = $queryresult =~
			/Name:\s+$query\s.*?Whois Server:\s+(.*?)\s/si;

		my $relresult;
#		my ($relresult) = $queryresult =~
#			/[\r\n]([^\r\n]+\S+\sName:\s+$query\s.*?Expiration Date:[^\r\n]+)[\r\n]/si;
#		$relresult = "(Redirect to $host:$port)" if !defined $relresult;
		$relresult = $queryresult;

		$result .= "$relresult\n\n-- End --\n\n";

		# $port = 43;
		my ($host2, $port) = $host =~ /^(.*):(.*)$/;
		$port = 43     if !defined $port;
		$host = $host2 if  defined $host2;

		# print $GWhoIs::Core::step++,". Step: Querying $host:$port with whois.\n\n"; # todo "rwhois"?
		$result .= ($GWhoIs::Core::step++).". Step: Querying $host:$port with whois.\n\n"; # todo "rwhois"?

		$result .= "-- From: $host:$port\n\n";
		# TODO: beim referal whois ist die query ist nicht trimmed. scheint aber nix auszumachen
		my ($loc_text, $loc_exitcode) = GWhoIs::Core::whoisaccess($host,$port,$query);

		$exitcode = max($exitcode, $loc_exitcode);
		$result .= $loc_text;
	} else {
		$result = "-- From: $host:$port\n\n$queryresult-- End --\n";
	}

	return ($result, $exitcode);
}

# ($result, $exitcode) = GWhoIs::Core::wwwsgrep($url,$match)
sub GWhoIs::Core::wwwsgrep {
	my ($url,$match) = @_;
	my ($result, $line, $exitcode) = ('', '', 0);

	($line, $exitcode) = GWhoIs::Core::getsource($url);
	if (!$exitcode) {
		$line =~ s/\n/ /g;
		if ($line =~ $match) {
			($result) = $line =~ /$match/s;
		}
	}
	return ($result, $exitcode);
}

# ($host, $additional) = GWhoIs::Core::methodpatternregex($query,$host,$additional,$queryline);
sub GWhoIs::Core::methodpatternregex {
	my ($query,$host,$additional,$line) = @_;

	my ($namewotld,$tld) = $query =~ /^([^\.]*)\.(.*)$/;
# TODO: !defined
	my ($p1,$p2,$p3,$p4,$p5,$p6,$p7,$p8,$p9) = $query =~ $line;
# TODO: !defined
	my ($ucq) = uc($query);

	$host       =~ s/~query~/$query/;
	$host       =~ s/~ucquery~/$ucq/;
	$host       =~ s/~namewotld~/$namewotld/;
	$host       =~ s/~tld~/$tld/;
	$host       =~ s/~1~/$p1/;
	$host       =~ s/~2~/$p2/;
	$host       =~ s/~2~/$p3/;
	$host       =~ s/~2~/$p4/;
	$host       =~ s/~2~/$p5/;
	$host       =~ s/~2~/$p6/;
	$host       =~ s/~2~/$p7/;
	$host       =~ s/~2~/$p8/;
	$host       =~ s/~2~/$p9/;

	$additional =~ s/~query~/$query/;
	$additional =~ s/~ucquery~/$ucq/;
	$additional =~ s/~namewotld~/$namewotld/;
	$additional =~ s/~tld~/$tld/;
	$additional =~ s/~1~/$p1/;
	$additional =~ s/~2~/$p2/;

	return ($host,$additional);
}

# @patternfiles = GWhoIs::Core::getpatternfiles()
sub GWhoIs::Core::getpatternfiles {
	my (@files, @files_new);

	opendir(DIR, $GWhoIs::Core::confdir);
	@files_new = sort(readdir(DIR));
	closedir(DIR);

	@files_new = grep {
			    ($_ !~ /^\./)
			 && ($_ !~ /\.dpkg-/)
			 && ($_ !~ /\.orig$/)
			 && ($_ !~ /\.bak$/)
			 && ($_ !~ /\.save$/)
			 && ($_ !~ /^\./)
			} @files_new;
	@files_new = map { "$GWhoIs::Core::confdir/$_" } @files_new;

	@files = grep { -f } (@files_new);

	return (@files);
}

# ($method, $host, $additional) = GWhoIs::Core::getmethodother($query);
sub GWhoIs::Core::getmethodother {
	my ($query) = @_;
	my $found = 0;
	my ($line,$cline,$method,$host,$additional);
	my ($rang_prefix, $rang_beginning, $rang_ending);
	my ($rang_actual_prefix, $rang_number);

	# Process file until we found a match
	foreach my $patternfile (GWhoIs::Core::getpatternfiles()) {
		open(PATTERN,"<$patternfile") || die "Cannot open $patternfile. STOP.\n";

		while ( defined($line = <PATTERN>) && (!$found) ) {
			# chomp $line;
			$line = GWhoIs::Utils::trim($line);

			if ( $line =~ /^#/ ) {                       # comment
			} elsif ( ($cline) = $line =~ /^:(.*)$/ ) {  # method declaration
				($method,$host,$additional) = split(/\|/,$cline,3);
				$method=''     if !defined $method;
				$host=''       if !defined $host;
				$additional='' if !defined $additional;

			} elsif ( $line =~ /^\*/ && (($rang_actual_prefix, $rang_number) = $query =~ /^([^0-9]+)([0-9]+)$/) ) {
				# e.g. for parsing ASNs

				if (($rang_prefix, $rang_beginning) = $line =~ /^\*([^0-9]+):([0-9]+)$/) {
					# Single number
					$rang_ending = $rang_beginning
				} else {
					# Range
					($rang_prefix, $rang_beginning, $rang_ending) = $line =~ /^\*([^0-9]+):([0-9]+)-([0-9]+)$/;
					next if !defined $rang_prefix;
					next if !defined $rang_beginning;
					next if !defined $rang_ending;
				}

				if ((lc($rang_prefix) eq lc($rang_actual_prefix))
				  && ($rang_number >= $rang_beginning)
				  && ($rang_number <= $rang_ending)) {
					$found = 1;
					# ($host,$additional) = GWhoIs::Core::methodpatternregex($query,$host,$additional,$line);
				}
			} elsif ( $line ne '' && $line =~ /^[^\*]/ && $query =~ /$line/i ) {
				# Regex
				$found = 1;
				($host,$additional) = GWhoIs::Core::methodpatternregex($query,$host,$additional,$line);
			}
		}
	}
	if (!$found) {
		return ('','','')
	}

	$host = $GWhoIs::Core::mirror{$method.$host} if defined $GWhoIs::Core::mirror{$method.$host};
	return ($method,$host,$additional);
}

# ($resulttext, $exitcode) = GWhoIs::Core::redirectwhois($query,$host,$port)
sub GWhoIs::Core::redirectwhois {
	my ($query,$host,$port) = @_; # todo: anstelle $port lieber ein $additional zulassen?
	$port = 43 if !defined $port;

	# check for query modifier (if any)
	my ($modmethod, $modhost, $modadditional) = GWhoIs::Core::getmethodother("redirect:$host(:$port){0,1}");

	return GWhoIs::Core::doquery($query,$modmethod,$modhost,$modadditional)
		if ( $modmethod ne 'none');

	return GWhoIs::Core::doquery($query, 'whois', "$host:$port");
}

# ($resulttext, $exitcode) = GWhoIs::Core::doquery($query,$method,$host,$additional);
sub GWhoIs::Core::doquery {
	my ($query,$method,$host,$additional,$inside_multiple) = @_;
	my $result = '';
	my $exitcode = 0;

	$query = ''          if !defined $query;
	$method = ''         if !defined $method;
	$host = ''           if !defined $host;
	$additional = ''     if !defined $additional;
	$inside_multiple = 0 if !defined $inside_multiple;

	if ($method eq 'multiple') {
		my $triple;
		# do not match "::::", e.g. used by notice
		my @triple_split = split(/(?<!:):::(?!:)/, $additional);
		my $count = 0;
		foreach $triple (@triple_split) {
			($method,$host,$additional) = split(/::/, $triple);

			# We will not get the exact sequence of "prints" and "$result" outputs, but it is better than nothing.
			# If we would print everything, we would get the warning "print wide char" at nic.es
			# If we would save all output to $result without buffering the prints inside GWhoIs::Core::doquery(), the prints would not be in front of their section.
			my $output = '';
			open TOOUTPUT, '>', \$output or die "Can't open TOOUTPUT: $!"; # TODO: exitcode
			my $orig_select = select(TOOUTPUT);

			my ($loc_text, $loc_exitcode) = GWhoIs::Core::doquery($query, $method, $host, $additional, 1);
			$exitcode = max($exitcode, $loc_exitcode);

			$output .= GWhoIs::Utils::trim($loc_text);
			$output .= "\n\n------\n\n" if $count < $#triple_split;
			select($orig_select);
			$result .= $output;

			$count += 1;
		}

		# done
		$method = '';
	}

# TODO: usage of methods. delete unused ones!
# wwwgreplv -> removed
# whoisjp: not in pattern
# whoisarin: not in pattern
# inicwhois: in use

	elsif ($method eq 'wwwsgrep') {
		my ($protocol, $hostname) = GWhoIs::Utils::splitProtocolHost($host);

		print "Querying $hostname with $protocol.\n\n";

		my ($loc_text, $loc_exitcode) = GWhoIs::Core::wwwsgrep($host,$additional);
		$exitcode = max($exitcode, $loc_exitcode);
		if ($loc_exitcode) {
			$result .= "Query to web server failed.\n";
		} else {
			if ($loc_text ne '') {
				$result = "Match found:\n$loc_text\n";
			} else {
				$result = "No match found. This probably means that this domain does not exist.\n";
			}
		}
	}

	elsif ($method =~ /^whois(|jp|arin)$/) {
		my ($parameter,$outquery,$prefix) = ('', '', '');

		my $port       = 43;
		my $noipprefix = '';
		my $ipprefix   = '';
		my $trailer    = '';
		my $strip      = '';

		$additional = '' if !defined $additional;

		foreach $parameter (split('\|', $additional)) {
			$trailer    = $1 if ( $parameter =~ /trailer=(.*)/ );
			$strip      = $1 if ( $parameter =~ /strip=(.*)/ );
			$prefix     = $1 if ( $parameter =~ /prefix=(.*)/ );
		}

		$port = $1 if ( $host =~ /.+:(\d+)/ );
		$host =~ s/:(\d+)//g;

		print "Querying $host:$port with whois.\n"; # todo "rwhois"?

		$outquery = $prefix . $query . $trailer . "\n";
		$outquery =~ s/$strip//g if ( $strip ne '' );

		my $loc_exitcode;
		($result, $loc_exitcode) = GWhoIs::Core::whoisaccess($host,$port,$outquery);
		$exitcode = max($exitcode, $loc_exitcode);

		# TODO rwhois:// implementierung ok?
		if ( $result =~ /ReferralServer: whois:\/\/(.*):43/mi || $result =~ /ReferralServer: whois:\/\/(.*)/mi ) {
			($result, $loc_exitcode) = GWhoIs::Core::redirectwhois($query,$1);
			$host = ''; #TODO???
			$exitcode = max($exitcode, $loc_exitcode);
		} elsif ( $result =~ /ReferralServer: r{0,1}whois:\/\/([^:]*):(\d+)/mi ) {
#			($result, $loc_exitcode) = GWhoIs::Core::whoisaccess($1,$2,$query); # TODO rediretwhois ?
			($result, $loc_exitcode) = GWhoIs::Core::redirectwhois($query,$1,$2);
			$exitcode = max($exitcode, $loc_exitcode);
		} elsif ( $result =~ /ReferralServer: rwhois:\/\/(.*)/mi ) {
#			($result, $loc_exitcode) = GWhoIs::Core::whoisaccess($1,4321,$query); # TODO rediretwhois ?
			($result, $loc_exitcode) = GWhoIs::Core::redirectwhois($query,$1,4321);
			$exitcode = max($exitcode, $loc_exitcode);
		} elsif ( $result =~ /(refer|whois server):\s+(.*)/m ) {
			# "refer:" is sent by whois.iana.org (e.g. if you query test.de )
			($result, $loc_exitcode) = GWhoIs::Core::redirectwhois($query,$2);
			$host = ''; #TODO???
			$exitcode = max($exitcode, $loc_exitcode);
		}

		# TODO: http://tools.ietf.org/html/rfc1714#section-3.3.2
		#    %referral<SP><server>[:type]<SP>[authority area]

		print "\n";
	}

	elsif ($method eq 'inicwhois' ) {
		my $port = $additional || 43;
		$result = ($GWhoIs::Core::step++).". Step: Querying $host:$port with whois.\n\n"; #todo "rwhois"?
		$query .= "\n"; # ???

		my ($loc_text, $loc_exitcode) = GWhoIs::Core::inicwhoisaccess($host,$port,$query);
		$result .= $loc_text;
		$exitcode = max($exitcode, $loc_exitcode);
	}

	elsif ($method eq 'cgi') {
		my ($protocol, $hostname) = GWhoIs::Utils::splitProtocolHost($host);

		print "Querying $hostname ($protocol) with cgi.\n\n";
#!!
#		print "$host\n";

# TODO: lynx seems to be better in some ways!
#       For example, a website that outputs "text/plain" will be rendered correct in lynx!
#		$result = `lynx -connect_timeout=10 -dump "$host" 2>&1`;
#		$result .= "FAILED with exit code $?\n\n" if $?;

		# TODO: GWhoIs::Core::getsource ok? war vorher IMMER lynx
		my ($loc_text, $loc_exitcode) = GWhoIs::Core::getsource($host);

		$exitcode = max($exitcode, $loc_exitcode);
		if ($loc_exitcode) {
			$result .= "Query to web server failed.\n";
		} else {
			$result = GWhoIs::Utils::render_html($loc_text);
		}
	}

	elsif ($method eq 'cgipost') {
		my ($protocol, $hostname) = GWhoIs::Utils::splitProtocolHost($host);

		print "Querying $hostname ($protocol) with cgi.\n\n";
#!!
#		print "echo -e '$additional\n---' | lynx -connect_timeout=10 -dump -post_data '$host'\n";

# TODO: GWhoIs::Utils::render_html() better? TODO: lynx source?
# [Ma 22.07.2013] "echo -e" does not work... "-e" will shown to the output... However "\n" will still work if I remove -e ... weird.
#		$result = `echo -e "$additional\n---" | lynx -dump -post_data "$host" 2>&1`; # TODO escape
#		$result = `echo "$additional\n---" | lynx -dump -post_data "$host" 2>&1`; # TODO escape
		$result = `echo "$additional" | curl --silent -X POST --data-binary \@- "$host" | lynx -dump -stdin 2>&1`; # TODO escape
		my $loc_exitcode = $?;
		$exitcode = max($exitcode, $loc_exitcode);
		$result .= "FAILED with exit code $loc_exitcode\n\n" if $loc_exitcode;
	}

	elsif ($method eq 'cgipostcurl') {
		my ($protocol, $hostname) = GWhoIs::Utils::splitProtocolHost($host);

		print "Querying $hostname ($protocol) with cgi.\n\n";
#		print "$additional\n"; #!!
#		print "curl --max-time 10 --stderr /dev/null -e $host --data '$additional' $host | lynx -dump -stdin\n";

		# TODO: "set pipefail" doesn't work (insecure certificate will not cause the function to fail)
		$result = `curl --max-time 10 --insecure --stderr /dev/null -e "$host" --data "$additional" "$host" | lynx -dump -stdin 2>&1`; # TODO escape

		my $loc_exitcode = $?;
		$exitcode = max($exitcode, $loc_exitcode);
		$result .= "FAILED with exit code $loc_exitcode\n\n" if $loc_exitcode;
	}

	elsif ($method eq 'cgihttps') {
		my ($protocol, $hostname) = GWhoIs::Utils::splitProtocolHost($host);

		print "Querying $hostname ($protocol) with cgi.\n\n";
#		print "$additional\n"; #!!
#		print "curl --max-time 10 --stderr /dev/null $host | lynx -dump -stdin\n";
#		$result = `curl --max-time 10 --insecure --stderr /dev/null "$host" | lynx -dump -stdin 2>&1`;
		my $html = `curl --max-time 10 --insecure --stderr /dev/null "$host" 2>&1`; # TODO escape. why --insecure?
		my $loc_exitcode = $?;
		$exitcode = max($exitcode, $loc_exitcode);
		$html .= "FAILED with exit code $loc_exitcode\n\n" if $loc_exitcode;
		$result = GWhoIs::Utils::render_html($html);
	}

	elsif ($method eq 'notice') {
		if ($inside_multiple) {
			$result = "\n\nAdditional information for query '$query'.\n\n" . $additional . "\n\n";
		} else {
			$result = "\n\nNo lookup service available for your query '$query'.\n\ngwhois remarks: " . $additional . "\n\n";
		}
		# $exitcode = 0;
	}

	elsif ($method eq 'program') {
		my ($program) = GWhoIs::Utils::trim($host);
		$program =~ s/\$gwhois\$/$FindBin::RealBin/;
		print "Querying script $program\n\n";
		$result = `$program $additional "$query" 2>&1`;
		my $loc_exitcode = $?;
		$exitcode = max($exitcode, $loc_exitcode);
		$result .= "FAILED with exit code $loc_exitcode\n\n" if $loc_exitcode;
	}

	if ($host =~ /arin/) {
		my $loc_exitcode;
		if ($result =~ /Maintainer: RIPE/) {
			($result, $loc_exitcode) = GWhoIs::Core::redirectwhois($query,'whois.ripe.net');
			$exitcode = max($exitcode, $loc_exitcode);
		} elsif ($result =~ /Maintainer: AP/) {
			($result, $loc_exitcode) = GWhoIs::Core::redirectwhois($query,'whois.apnic.net');
			$exitcode = max($exitcode, $loc_exitcode);
		}
	}
	elsif ($host =~ /apnic/) {
		my $loc_exitcode;
		if ($result =~ /netname: AUNIC-AU/) {
			($result, $loc_exitcode) = GWhoIs::Core::redirectwhois($query,'whois.aunic.net');
			$exitcode = max($exitcode, $loc_exitcode);
		} elsif ($result =~ /netname: JPNIC-JP/) {
			($result, $loc_exitcode) = GWhoIs::Core::redirectwhois($query,'whois.nic.ad.jp');
			$exitcode = max($exitcode, $loc_exitcode);
		}
	}
	elsif ($host =~ /ripe/ && $result =~ /remarks:\s+whois -h (\S+)/) {
		my $loc_exitcode;
		($result, $loc_exitcode) = GWhoIs::Core::redirectwhois($query,$1);
		$exitcode = max($exitcode, $loc_exitcode);
	}
	# TODO: internic gibts doch gar nicht mehr, oder?
	elsif (($host =~ /internic/) && ($result =~ /No match for/) && ($query !~ /\.(arpa|com|edu|net|org)$/) ) {
		my ($result1, $loc_exitcode) = GWhoIs::Core::redirectwhois($query,'whois.ripe.net');
		$result = $result1 if $result1 !~ /No entries found/;
		$exitcode = max($exitcode, $loc_exitcode);
	}

	return ($result, $exitcode);
}

1;
