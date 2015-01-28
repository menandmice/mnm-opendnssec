Last tested: 28.01.2015 with OpenDNSSEC 1.4.6, Men & Mice Suite 6.7.5
on MacOS X 10.9 with BIND 9.10.1-P1

odsmmsync.py:

This is a sync-script for syncing an OpenDNSSEC server running on a
hidden master with Men and Mice.  It relies on cron job, not the M&M
script triggers which can only be run on the Central machine.  When
the script is run it compares the contents of OpenDNSSEC with what Men
and Mice has, and adds and/or removes to OpenDNSSEC accordingly. It
also updates the custom field list for OpenDNSSEC policies in Men and
Mice, and writes down the list of servers configured in Men and Mice,
which are going to be notified by the reload script (see below)

reloadscript.sh:

This is a script that should be run by the NotifyCommand in
OpenDNSSEC. It moves files into correct places, reloads the nameserver
and notifies the slaves according to nameservers.lst (see above) with
ldns-notify
