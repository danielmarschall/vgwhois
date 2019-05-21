#!/bin/bash

  db_get vgwhois/inetd
  if [ "$RET" = "true" ]; then
    if [ "$(which update-inetd)" != "" ]; then
      update-inetd --add 'whois	 	stream	tcp 	nowait	nobody	/usr/bin/vgwhois vgwhois'
    else
      db_input high vgwhois/noinetd
      db_go
    fi
  else
    if [ "$(which update-inetd)" != "" ]; then
      update-inetd --pattern vgwhois --remove whois 2>&1 >/dev/null
    fi
  fi
