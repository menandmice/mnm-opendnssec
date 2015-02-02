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

# Section: bind9 #

    [bind9]
    master-zones-dir: /var/named/hosts/masters

# Section: odsmmsync # 

    [odsmmsync]
    syslog-process-tag: [odsmmsync]
    script-dir: /var/named/scripts
    slave-servers-list: /var/named/scripts/nameservers.lst

