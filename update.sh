#!/bin/bash

DIR=$( dirname $(realpath "$0" ) )

cd "$DIR"

if [ ! -d ".svn" ]; then
	echo "$DIR was not checked out via SVN. Please update manually."
	exit 1
fi

svn update

