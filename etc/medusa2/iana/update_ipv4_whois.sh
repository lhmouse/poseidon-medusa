#!/bin/sh

curl http://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv 2>/dev/null | \
  sed -r -e '1cprefix,whois' -e 's@^([0-9]+)/8.+(whois\.\w+\.net).*$@\1,\2@' -e '/\/8/d' > ipv4_whois.csv
