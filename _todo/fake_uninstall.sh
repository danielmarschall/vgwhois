  db_get vgwhois/inetd
  if [ "$RET" = "true" ]; then
    if [ "$(which update-inetd)" != "" ]; then
      update-inetd --pattern vgwhois --remove whois 2>&1 >/dev/null
    fi
  fi
