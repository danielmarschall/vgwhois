#!/bin/bash

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
