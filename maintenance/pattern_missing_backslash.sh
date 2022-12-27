#!/bin/bash

DIR=$( dirname "$0" )

cat "$DIR"/../main/pattern/domains  | grep "^\."
