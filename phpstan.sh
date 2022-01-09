#!/bin/bash

DIR=$( dirname "$0" )

cd "$DIR"

# There are several PHP scripts which run in CLI and don't have file extensions
# To check them with PHPstan, we need to temporarily rename them using this script

array=( $( grep -r "#!" . | grep php | grep -v ".svn" | cut -d ':' -f 1 | sort | uniq ) )

for ix in ${!array[*]}
do
	file="${array[$ix]}"
	mv "$file" "$file.php"
done

# TODO: Adjust to your path
php7 /root/phpstan.phar

for ix in ${!array[*]}
do
	file="${array[$ix]}"
	mv "$file.php" "$file"
done
