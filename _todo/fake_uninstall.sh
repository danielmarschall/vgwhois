  db_get gwhois/inetd
  if [ "$RET" = "true" ]; then
    if [ "$(which update-inetd)" != "" ]; then
      update-inetd --pattern gwhois --remove whois 2>&1 >/dev/null
    fi
  fi
