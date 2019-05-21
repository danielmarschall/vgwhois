#!/bin/bash

#
#  VGWhoIs (ViaThinkSoft Global WhoIs, a fork of generic Whois / gwhois)
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

if [ -L /usr/bin/vgwhois ]; then
	rm /usr/bin/vgwhois
	echo "Symlink /usr/bin/vgwhois removed"
fi

# ---

if [ -L /usr/sbin/vgwhois-pattern-update ]; then
	rm /usr/sbin/vgwhois-pattern-update
	echo "Symlink /usr/sbin/vgwhois-pattern-update removed"
fi

# ---

if [ -L /usr/sbin/vgwhois-qa-check ]; then
	rm /usr/sbin/vgwhois-qa-check
	echo "Symlink /usr/sbin/vgwhois-qa-check removed"
fi

# ---

if [ -L /usr/sbin/vgwhois-update ]; then
	rm /usr/sbin/vgwhois-update
	echo "Symlink /usr/sbin/vgwhois-update removed"
fi

# ---

if [ -L /usr/share/man/man1/vgwhois.1 ]; then
	rm /usr/share/man/man1/vgwhois.1
	echo "Symlink /usr/share/man/man1/vgwhois.1 removed"
fi
