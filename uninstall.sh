#!/bin/bash

#
#  VWhois (ViaThinkSoft WHOIS, a fork of generic Whois / gwhois)
#  Installer / Uninstaller
#
#  (c) 2019 by Daniel Marschall, ViaThinkSoft <info@daniel-marschall.de>
#
#  License: https://www.gnu.org/licenses/gpl-2.0.html (GPL version 2)
#

# --- STEP 0: Are we root?

if [[ $EUID > 0 ]]; then
	>&2 echo "You need to be root to execute this program."
	exit 1
fi

# --- STEP 1: Remove the "installed" symlinks

if [ -L /usr/bin/gwhois ]; then
	rm /usr/bin/gwhois
	echo "Symlink /usr/bin/gwhois removed"
fi

# ---

if [ -L /usr/sbin/gwhois-pattern-update ]; then
	rm /usr/sbin/gwhois-pattern-update
	echo "Symlink /usr/sbin/gwhois-pattern-update removed"
fi

# ---

if [ -L /usr/sbin/gwhois-qa-check ]; then
	rm /usr/sbin/gwhois-qa-check
	echo "Symlink /usr/sbin/gwhois-qa-check removed"
fi

# ---

if [ -L /usr/sbin/gwhois-update ]; then
	rm /usr/sbin/gwhois-update
	echo "Symlink /usr/sbin/gwhois-update removed"
fi

# ---

if [ -L /usr/share/man/man1/gwhois.1 ]; then
	rm /usr/share/man/man1/gwhois.1
	echo "Symlink /usr/share/man/man1/gwhois.1 removed"
fi
