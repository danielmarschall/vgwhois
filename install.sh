#!/bin/bash

#
#  VWhois (ViaThinkSoft WHOIS, a fork of generic Whois / gwhois)
#  Installer / Uninstaller
#
#  (c) 2019 by Daniel Marschall, ViaThinkSoft <info@daniel-marschall.de>
#
#  License: https://www.gnu.org/licenses/gpl-2.0.html (GPL version 2)
#

DIR=$( dirname "$0" )
REAL_DIR=$( cd "$DIR" && pwd )

# --- STEP 0: Are we root?

if [[ $EUID > 0 ]]; then
	>&2 echo "You need to be root to execute this program."
	exit 1
fi

# --- STEP 1: Install required packages

# Required for the program itself:
#  - perl (used by gwhois main program. used by 6to4 and Teredo subprogram) 
#  - libwww-perl (cpan LWP::Simple; used by gwhois main program) 
#  - libnet-libidn-perl (cpan Net::LibIDN; used by gwhois main program) 
#  - (commented out) libencode-detect-perl (cpan Encode::Detect; used by gwhois main program)
#  - curl (used by some parts of the gwhois main program. used by pattern generator and subprograms) 
#  - lynx-cur (used by some parts of the gwhois main program) 
#  - libnet-ip-perl (cpan Net::IP; used for IPv6 interpretation by Teredo subprogram and gwhois main program) 
#  - libnet-dns-perl (cpan Net::DNS; used by Teredo subprogram) 
#  - libmath-bigint-gmp-perl (cpan Math::BigInt; used for IPv6 masking by gwhois main program) 
#  - php7.0-cli (used by subprograms and pattern-generator) 
#
# Required for the maintenance tools
#  - php7.0-gmp (used by IPv6 pattern generator) 
#  - netcat (used by the whois-ping maintainance program)
#  - php7.0-sqlite3 (used by the whois-ping maintainance program)
#
# TODO: how can be avoid the "php7.0" name? are there generic package names?
# TODO: How to make the installation of the packages fit to most distros?

apt-get update
apt-get install perl libwww-perl libnet-libidn-perl curl lynx-cur libnet-ip-perl libnet-dns-perl libmath-bigint-gmp-perl php7.0-cli php7.0-gmp netcat php7.0-sqlite3

# --- STEP 2: "Install" symlinks

if [ -L /usr/bin/gwhois ]; then
	rm /usr/bin/gwhois
fi
ln -s "$REAL_DIR"/main/gwhois /usr/bin/gwhois
echo "Symlink /usr/bin/gwhois created"

# ---

if [ -L /usr/sbin/gwhois-pattern-update ]; then
	rm /usr/sbin/gwhois-pattern-update
fi
ln -s "$REAL_DIR"/maintenance/pattern-generator/gwhois-pattern-update /usr/sbin/gwhois-pattern-update
echo "Symlink /usr/sbin/gwhois-pattern-update created"

# ---

if [ -L /usr/sbin/gwhois-qa-check ]; then
	rm /usr/sbin/gwhois-qa-check
fi
ln -s "$REAL_DIR"/maintenance/qa-monitor/run /usr/sbin/gwhois-qa-check
echo "Symlink /usr/sbin/gwhois-qa-check created"

# ---

if [ -L /usr/sbin/gwhois-update ]; then
	rm /usr/sbin/gwhois-update
fi
ln -s "$REAL_DIR"/update.sh /usr/sbin/gwhois-update
echo "Symlink /usr/sbin/gwhois-update created"

# ---

if [ -L /usr/share/man/man1/gwhois.1 ]; then
	rm /usr/share/man/man1/gwhois.1
fi
ln -s "$REAL_DIR"/man/man1/gwhois.1 /usr/share/man/man1/gwhois.1
echo "Symlink /usr/share/man/man1/gwhois.1 created"

