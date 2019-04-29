#!/bin/bash

DIR=$( dirname "$0" )

ln -s "$DIR"/etc/gwhois/ /etc/gwhois
ln -s "$DIR"/usr/bin/gwhois /usr/bin/gwhois
ln -s "$DIR"/var/cache/gwhois/ /var/cache/gwhois
ln -s "$DIR"/usr/share/doc/gwhois/ /usr/share/doc/gwhois
ln -s "$DIR"/usr/share/man/man1/gwhois.1 /usr/share/man/man1/gwhois.1
ln -s "$DIR"/usr/share/gwhois/ /usr/share/gwhois

  db_get gwhois/inetd
  if [ "$RET" = "true" ]; then
    if [ "$(which update-inetd)" != "" ]; then
      update-inetd --add 'whois	 	stream	tcp 	nowait	nobody	/usr/bin/gwhois gwhois'
    else
      db_input high gwhois/noinetd
      db_go
    fi
  else
    if [ "$(which update-inetd)" != "" ]; then
      update-inetd --pattern gwhois --remove whois 2>&1 >/dev/null
    fi
  fi
