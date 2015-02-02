# Installation on MacOS X #

This document describes the OpenDNSSEC integration for the Men & Mice
Suite on MacOS X.

This steps were tested using the Men & Mice Suite 6.7.5, BIND
9.9.6-P1, OpenDNSSEC 1.4.6 on MacOS X 10.9.

It is recommended to run the DNS Management System containing the Men
& Mice Suite and OpenDNSSEC as a "hidden-primary" DNS Server, e.g. a
DNS Server that is not listed in the zones NS-Records and is not
reachable from the public Internet. The signed DNS zone should be
transferred by DNS zonetransfer to DNS-secondaries (DNS slave servers)
that serve the zone on public IP-Addresses in the Internet.

# Install BIND 9 #

Apple MacOS X starting with version 10.9 does not contain the BIND 9
DNS server anymore. BIND 9 needs to be installed from an external
source.

You can compile BIND 9 from the sources ( download from
https://www.isc.org ) or use the pre-compiled installer packages
provided by Men & Mice (
http://packages.menandmice.com/bind/macosx/10.7-Lion/ ). The BIND 9
packages provided by Men & Mice are not part of the Men & Mice Suite
product and are provided "AS-IS" without support or
warranties. Customers that require a supported version of BIND 9 can
purchase a support contract (independend from the Men & Mice Suite)
from Men & Mice or ISC.

Create a basic BIND 9 configuration file and configure one or two DNS
zones. Test the configuration with "named-checkconf -z".

# Install the Men & Mice Suite #

Download and install the Men & Mice Suite DNS-Server Controller on the
MacOS X System. Connect the DNS Server to the Men & Mice Central. The
Men & Mice Central service can run on the same machine or on some
other machine on the network. Please be aware that Microsoft
Active-Directory authentication is only possible with Men & Mice
Central running on a Microsoft Windows system that is part of the
Active Directory Domain.

Make sure that you can view and edit the DNS Zones on the DNS-Server
from within the Men & Mice GUI.

As the Men & Mice User "Administrator" create 4 new "Custom
Properties" on the "zone" object:

 * "DNSSEC" - Type YES/NO - this field holds the information whether the
 zone should be DNSSEC signed
 * "DNSSEC Policy" - Type "text" - this field holds the DNSSEC policy
 selected for this zone
 * "Last Signed Date" - Type "text" - this field holds the information
 when the zone has last been signed by OpenDNSSEC
 * "Next Expiry Date" - Type "text" - this field holds the closted
 RRSIG expiry date of the zone 

The Men & Mice - OpenDNSSEC integration script "odsmmsync.py" uses the
Men & Mice SOAP API calls. The SOAP API is provided by the Men & Mice
Web-UI component. Install the Men & Mice Web-UI component on some
machine in the network. A good place is the machine that is also
running the Men & Mice Central service. For security reasons, the Men
& Mice Web-UI should not be installed on a system that is exposed to
the Internet.

# Install the sync script #

Install the sync script into a directory inside the search-path of the
user that will run the sync script. The sync script must be able to
read and write the zonefile, so it must be either be executed with the
user-account of the BIND 9 DNS-Server, or with the "root"
superuser. Make sure the file has the executable permission bit set:

    # cp odsmmsync.py /usr/local/bin
    # chmod +x /usr/local/bin/odsmmsync.py

Copy the configuration file into the "/etc" directory. Adjust the
configurationfile to fit your installation. Refer to the
"Configuration" file in the "docs" folder for detail information on
the configuration option.

Copy the "reloadscript.sh" file into the script directory
"/var/named/scripts"  and make it executable:

    # mkdir -p /var/named/scripts
    # cp reloadscript.sh /var/named/scripts
    # chmod +x /var/named/scripts/reloadscript.sh

Run the sync script "odsmmsync.py" script manually to test the setup:

    MacBook-Pro% ./odsmmsync.py
    [odsmmsync]: reading from configuration file /etc/odsmmsync.cfg
    [odsmmsync]: Policies in Men and Mice:
    [odsmmsync]:   test.example: default
    [odsmmsync]:   example.com: default
    [odsmmsync]:   testing.example: default
    [odsmmsync]: Policies in OpenDNSSEC:
    [odsmmsync]:   test.example: default
    [odsmmsync]:   example.com: default
    [odsmmsync]:   testing.example: default
    [odsmmsync]: WARNING: no slave servers found in configuration


# periodic execution of the script #

Create a property list (plist) file for MacOS X "launchd" to execute
the script in intervals between 5 and 60 minutes (depending on the
size of your environment and the duration of one script run).

Here is one example script:

    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>Label</key>
        <string>com.menandmice.odsmmsync</string>
        <key>ProgramArguments</key>
        <array>
            <string>/usr/local/bin/odsmmsync.py</string>
        </array>
        <key>StartInterval</key>
        <integer>3600</integer>
    </dict>
    </plist>
 
 load the property list into launchd:

    launchctl load  ~/Library/LaunchAgents/com.menandmice.odsmmsync.plist

Additional information on periodic execution of script in MacOS X can
be found at

 * Schedule jobs using launchd
   <http://nathangrigg.net/2012/07/schedule-jobs-using-launchd/>
 * Mac crontab - Mac OS X startup jobs with crontab, er, launchd
 <http://alvinalexander.com/mac-os-x/mac-osx-startup-crontab-launchd-jobs>
 
