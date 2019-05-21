#!/bin/bash

#
#  VGWhoIs (ViaThinkSoft Global WhoIs, a fork of generic Whois / gwhois)
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
#  - perl (used by vgwhois main program. used by 6to4 and Teredo subprogram) 
#  - libwww-perl (cpan LWP::Simple; used by vgwhois main program) 
#  - libnet-libidn-perl (cpan Net::LibIDN; used by vgwhois main program) 
#  - (commented out) libencode-detect-perl (cpan Encode::Detect; used by vgwhois main program)
#  - curl (used by some parts of the vgwhois main program. used by pattern generator and subprograms) 
#  - lynx-cur (used by some parts of the vgwhois main program)
#  - libnet-ip-perl (cpan Net::IP; used for IPv6 interpretation by Teredo subprogram and vgwhois main program)
#  - libnet-dns-perl (cpan Net::DNS; used by Teredo subprogram)
#  - libmath-bigint-gmp-perl (cpan Math::BigInt; used for IPv6 masking by vgwhois main program)
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

if [ -L /usr/bin/vgwhois ]; then
	rm /usr/bin/vgwhois
fi
ln -s "$REAL_DIR"/main/vgwhois /usr/bin/vgwhois
echo "Symlink /usr/bin/vgwhois created"

# ---

if [ -L /usr/sbin/vgwhois-pattern-update ]; then
	rm /usr/sbin/vgwhois-pattern-update
fi
ln -s "$REAL_DIR"/maintenance/pattern-generator/vgwhois-pattern-update /usr/sbin/vgwhois-pattern-update
echo "Symlink /usr/sbin/vgwhois-pattern-update created"

# ---

if [ -L /usr/sbin/vgwhois-qa-check ]; then
	rm /usr/sbin/vgwhois-qa-check
fi
ln -s "$REAL_DIR"/maintenance/qa-monitor/run /usr/sbin/vgwhois-qa-check
echo "Symlink /usr/sbin/vgwhois-qa-check created"

# ---

if [ -L /usr/sbin/vgwhois-update ]; then
	rm /usr/sbin/vgwhois-update
fi
ln -s "$REAL_DIR"/update.sh /usr/sbin/vgwhois-update
echo "Symlink /usr/sbin/vgwhois-update created"

# ---

if [ -L /usr/share/man/man1/vgwhois.1 ]; then
	rm /usr/share/man/man1/vgwhois.1
fi
ln -s "$REAL_DIR"/man/man1/vgwhois.1 /usr/share/man/man1/vgwhois.1
echo "Symlink /usr/share/man/man1/vgwhois.1 created"

