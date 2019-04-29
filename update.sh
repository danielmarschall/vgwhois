#!/bin/bash

#
#  VWhois (ViaThinkSoft WHOIS, a fork of generic Whois / gwhois)
#  Installer / Uninstaller
#
#  (c) 2019 by Daniel Marschall, ViaThinkSoft <info@daniel-marschall.de>
#
#  License: https://www.gnu.org/licenses/gpl-2.0.html (GPL version 2)
#

DIR=$( dirname $(realpath "$0" ) )

cd "$DIR"

if [ ! -d ".svn" ]; then
	echo "$DIR was not checked out via SVN. Please update manually."
	exit 1
fi

# TODO: check if svn is installed?
svn update

