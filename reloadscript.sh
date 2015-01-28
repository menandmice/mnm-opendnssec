#!/bin/bash

logger "named reload script: copy $1 and reloading $2"
cp $1 /var/named/hosts/masters/$2-hosts
cp $1 /var/opendnssec/unsigned/$2
cp $1 /var/opendnssec/unsigned/$2.axfr

rm $1
sleep 5
rndc reload $2
sleep 5

SEQ=/usr/bin/seq

nameserverlist="/var/named/scripts/nameservers.lst"
if [ -s $(nameserverlist) ]; then
    nameservers=( $( < $(nameserverlist) ) )
    for i in $($SEQ 0 $((${#nameservers[@]} - 1)))
    do
	logger "sending notify to ${nameservers[$i]} ..."
	ldns-notify -r 1 -z $2 ${nameservers[$i]} 2>&1 1>/dev/null
    done
fi
exit 0
