# Section: opendnssec #

    [opendnssec]
    database-file: /var/opendnssec/kasp.db
    default-policy: default
    signed-zones-dir: /var/opendnssec/signed
    unsigned-zones-dir: /var/opendnssec/unsigned
    work-dir: /var/opendnssec/tmp
    path-to-odsksmutil: /usr/local/bin/ods-ksmutil

 * database-file - path of the OpenDNSSEC sqlite database containing
 the Key-and-Signing policy
 * default-policy - name of the OpenDNSSEC policy used as the default
 * signed-zones-dir - path to the directory where OpenDNSSEC will
 store the DNSSEC signed zones
 * unsigned-zones-dir - path to the directory where OpenDNSSEC will
   store the unsigned zone files
 * work-dir - path the to the directory where OpenDNSSEC will store
   temporary files
 * path-to-odsksmutil - path to the OpenDNSSEC "ods-ksmutil"
   commandline tool

# Section: menandmicesuite #

    [menandmicesuite]
    proxy-server: webui.example.com
    central-server: central.example.com
    username: administrator
    password: administrator
    master-dnsserver: dns1.example.com
    dnssec-property-name: DNSSEC
    policy-property-name: DNSSEC Policy
    last-signed-property-name: Last Signed Date
    next-expiry-property-name: Next Expiry Date
    policy-list-update-save-comment: OpenDNSSEC integration script. Maintenance.

 * proxy-server - hostname or IP-address of the machine running the
 Men & Mice Web-UI (containing the SOAP-API proxy)
 * central-server - hostname or IP-address of the machine running the
 Men & Mice Central service
 * username - Username of the user connecting to the Men & Mice
   system. For security reasons, it is recommended to create a
   dedicated user for the odsmmsync.py script with limited rights
 * password - password of the user connecting to the Men & Mice system
 * master-dnsserver - hostname of the DNS server containing the master
   DNS zones to be DNSSEC signed. This name must match the DNS
   servers name in the Men & Mice Suite
 * dnssec-property-name - name of the custom property field containing
   the boolean YES/NO value marking a DNSSEC signed zone
 * policy-property-name - name of the custom property field containing
   a text field with a prefilled list of OpenDNSSEC policy names
 * last-signed-property-name - name of a custom property containing
   the date and time of the last DNSSEC signing event for this zone
 * next-expirey-property-name - name of a custom property containing
   the date and time of the next RRSIG record expiry
 * policy-list-update-save-comment - comment text to be written to the
   Men & Mice Audit log when the script updates the list of DNSSEC
   policies from the OpenDNSSEC database
   


# Section: bind9 #

    [bind9]
    master-zones-dir: /var/named/hosts/masters

 * master-zones-dir - directory where BIND 9 looks for master
 zone-files
 
# Section: odsmmsync # 

    [odsmmsync]
    syslog-process-tag: [odsmmsync]
    script-dir: /var/named/scripts
    slave-servers-list: /var/named/scripts/nameservers.lst

 * syslog-process-tag - text that is printed as a tag for all log
 messages send to syslog
 * script-dir - directory for the Men & Mice DNS shell scripts, this
   is the place where the "reloadscript.sh" needs to be in
 * slave-server-list - textfile to be written by "odsmmsync.py" and
   read by "reloadscript.sh". The directory must exist and must be
   writeable by the script. The file will contain the list of all
   slave-servers that need to receive a notify once the zone is
   changed or DNSSEC (re-)signed
   
