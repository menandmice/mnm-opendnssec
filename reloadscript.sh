#!/bin/bash
SOANUM=$(cat $1 | grep SOA | head -1 | cut -f 3 -d ' ')
logger -t odsmmsync "named reload script: copy $1 and reloading $2"
cp $1 /var/named/hosts/masters/$2-hosts
cp $1 /var/opendnssec/unsigned/$2
cp $1 /var/opendnssec/unsigned/$2.axfr

rm $1
sleep 5
rndc reload $2
sleep 5

# sending notify to all secondary name servers
cat /var/named/scripts/nameservers.lst | xargs sh -c logger -d odsmmsync  "sending notify to "
cat /var/named/scripts/nameservers.lst | xargs ldns-notify -r 1 -s $SOANUM -z $2 2>&1 >/dev/null

