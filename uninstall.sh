#!/bin/bash

# TODO: check if we may do this (root)

if [ -L /usr/bin/gwhois ]; then
	rm /usr/bin/gwhois
	echo "Symlink /usr/bin/gwhois removed"
fi

if [ -L /usr/sbin/gwhois-pattern-update ]; then
	rm /usr/sbin/gwhois-pattern-update
	echo "Symlink /usr/sbin/gwhois-pattern-update removed"
fi

if [ -L /usr/sbin/gwhois-qa-check ]; then
	rm /usr/sbin/gwhois-qa-check
	echo "Symlink /usr/sbin/gwhois-qa-check removed"
fi

if [ -L /usr/sbin/gwhois-update ]; then
	rm /usr/sbin/gwhois-update
	echo "Symlink /usr/sbin/gwhois-update removed"
fi

if [ -L /usr/share/man/man1/gwhois.1 ]; then
	rm /usr/share/man/man1/gwhois.1
	echo "Symlink /usr/share/man/man1/gwhois.1 removed"
fi
