#!/bin/bash

DIR=$( dirname "$0" )

cat "$DIR"/../main/pattern/domains | sort | uniq -c | grep -v ":whois" | grep -v ":notice" | grep -v "   1"
