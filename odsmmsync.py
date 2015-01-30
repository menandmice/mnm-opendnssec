#! env python2
# Copyright (C) 2011-2015 Men & Mice
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND MEN & MICE DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL MEN & MICE BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.
"""
This is a sync-script for syncing an OpenDNSSEC server running on a
hidden master with Men and Mice.  It relies on cron job, not the M&M
script triggers which can only be run on the Central machine.  When
the script is run it compares the contents of OpenDNSSEC with what Men
and Mice has, and adds and/or removes to OpenDNSSEC accordingly. It
also updates the custom field list for OpenDNSSEC policies in Men and
Mice, and writes down the list of servers configured in Men and Mice,
which are going to be notified by the reload script.

Author: Men & Mice Services team - services@menandmice.com
Version: 1.2
Date: 2015-01-30
"""

import sqlite3,sys,os,soapCLI,syslog,re,datetime,ConfigParser
from shutil import copy2

thisViewName = '' #the name of the view, empty string for non-views setup (currently, only '' is supported)
sqlstatement='select z.name as zone,p.name as policy from zones as z join policies as p on p.id=z.policy_id;'


def getSignedZonefile(zone):
	return theDestDir.rstrip('/') + '/' + zone.rstrip('.')
	
def getBINDZonefile(zone):
	return theSourceDir.rstrip('/') + '/' + zone.rstrip('.')  + '-hosts'

def getUnsignedZonefile(zone):
	return theUnsignedDir.rstrip('/') + '/' + zone.rstrip('.')
	
def getTmpFile(zone):
	return theWorkingDir.rstrip('/') + '/' + zone.rstrip('.')
	
def getAXFRFilename(zone):
	return getUnsignedZonefile(zone) + '.axfr'


def getPropertyValue(properties,propertyName):
	propertyValue=None
	for property in properties.property:
		if property.name == propertyName:
			propertyValue=property.value
			break
	return propertyValue
	
def getDNSZoneRef (zonename):
	return thisServerName.rstrip('.') + '.::' + zonename.rstrip('.') + '.'
	
def writeToSyslog(theMsg):
	theMsg = thisProcessName + ': ' + theMsg 
	syslog.syslog(theMsg)
	print theMsg
	
def cleanupFiles (zonename):
	rmfile(getUnsignedZonefile(zonename))
	rmfile(getSignedZonefile(zonename))
	rmfile(getAXFRFilename(zonename))
	rmfile(getTmpFile(zonename))
	
def addNewZone(zonename,policy):
	writeToSyslog('Adding zone %s (policy: %s) to OpenDNSSEC' % (zonename,policy))
	theZoneFile = getBINDZonefile(zonename)
	theUnsignedZoneFile = getUnsignedZonefile(zonename)

	cleanupFiles(zonename)
	copyfile(theZoneFile,theUnsignedZoneFile)
	os.system('%s zone add --zone %s --policy %s' % (odsksmutil,zonename,policy)) 
	os.system('%s update zonelist' % odsksmutil)
	
def removeZone(zonename):
	writeToSyslog('Removing zone %s from OpenDNSSEC' % zonename)
	os.system('%s zone delete --zone %s' % (odsksmutil,zonename) )
	os.system('%s update zonelist' % odsksmutil)
	theTmpFile = cleanZoneFile(zonename)
	if theTmpFile:
		#theTmpFile will be False if the zone was deleted from the server
		#the reloadscript takes care of copying over to unsigned dir
		os.system('%s/reloadscript.sh %s %s' % (theScriptDir,theTmpFile,zonename) )
		clearSigningDatesCPs(zonename)
	cleanupFiles(zonename)

def changePolicy(zonename,policy):
	removeZone(zonename)
	addNewZone(zonename,policy)
	
# copies a file
def copyfile(source, target):
	copy2(source,target)
	
def rmfile(filename):
	try:
		os.remove(filename)
	except:
		pass
	
	
def cleanZoneFile(zone):
	# cleans DNSSEC records from a zonefile
	zonefile = getBINDZonefile(zone)
	
	if not os.path.isfile(zonefile):
		return False
	
	signedFile = getSignedZonefile(zone)
	tmpFile = getTmpFile(zone)
	copy2(zonefile,signedFile)
			
	op = open(tmpFile, "w")
	ip = open(signedFile, "r")
	for rawline in ip:
		line = SOAfilter(rawline) if 'SOA' in rawline else rawline
		dnssec = False
		dnssecrecords=['NSEC',"NSEC3","NSEC3PARAM","RRSIG","DNSKEY","Last refresh stats","Signed on"]
		for rec in dnssecrecords:
			if rec in line:
				dnssec=True
				break
		if not dnssec: 
			op.write(line)
	
	op.close()
	ip.close()
	
	return tmpFile


SOAPattern = '^[^\s]*\s+\d+\s+IN\s+SOA\s+[^\s]+\s+[^\s]+\s+(?P<serial>\d+)'
def SOAfilter (line):
	theMatch = re.match(SOAPattern,line)
	if theMatch:
		serial = int(theMatch.group('serial'))
		return re.sub(str(serial),str(serial+1),line,count=1)
	else:
		return line	

def updateSigningDatesCPs (zone):
	exLastSigned = getPropertyValue(zone.customProperties,lastSignedMMPropName) if zone.customProperties else None
	exNextExpiry = getPropertyValue(zone.customProperties,nextExpiryMMPropName) if zone.customProperties else None
	
	exLastSigned = dateStrToInt(exLastSigned,0)
	exNextExpiry = dateStrToInt(exNextExpiry,300000000000000)
	
	recs = cli.GetDNSRecords(dnsZoneRef=zone.ref,filter='type:^RRSIG$')
	RRSIGs = [rec.data for rec in recs.dnsRecords.dnsRecord] if recs.dnsRecords!= '' else []
	
	largestLastSigned=exLastSigned
	smallestNextExpiry = exNextExpiry
	
	for data in RRSIGs:
		dataparts = data.split('\t')
		if int(dataparts[4]) < smallestNextExpiry:
			smallestNextExpiry = int(dataparts[4])
		if int(dataparts[5]) > largestLastSigned:
			largestLastSigned = int(dataparts[5])
	
	if largestLastSigned!=exLastSigned or smallestNextExpiry !=exNextExpiry:
		props = cli.create('ArrayOfProperty')
		if largestLastSigned != exLastSigned:
			props.property.append({'name':lastSignedMMPropName,'value':intToDateStr(largestLastSigned)})
			writeToSyslog('Updating "%s" for "%s"' % (lastSignedMMPropName,zone.name))
		if smallestNextExpiry != exNextExpiry:
			props.property.append({'name':nextExpiryMMPropName,'value':intToDateStr(smallestNextExpiry)})
			writeToSyslog('Updating "%s" for "%s"' % (nextExpiryMMPropName,zone.name))
		
		cli.SetProperties(ref=zone.ref,properties=props)
		
		
def clearSigningDatesCPs (zonename):
	props = cli.create('ArrayOfProperty')
	props.property.append({'name':lastSignedMMPropName,'value':''})
	props.property.append({'name':nextExpiryMMPropName,'value':''})
	try:
		cli.SetProperties(ref=getDNSZoneRef(zonename),objType='DNSZone',properties=props)
	except:
		pass
			
			
def dateStrToInt (dateStr,defaultVal):
	return int(datetime.datetime.strptime(str(dateStr),'%Y-%m-%d %H:%M:%S').strftime('%Y%m%d%H%M%S')) if dateStr else defaultVal

def intToDateStr (theInt):
	return datetime.datetime.strptime(str(theInt),'%Y%m%d%H%M%S').strftime('%Y-%m-%d %H:%M:%S') if theInt else ''


# main body
if __name__ == "__main__":
        config = ConfigParser.ConfigParser()
        config.read('odsmmsync.cfg')
        # read configuration file
        theSourceDir                   = config.get("bind9","master-zones-dir")

        proxyServer                    = config.get("menandmicesuite","proxy-server")
        centralServer                  = config.get("menandmicesuite","central-server")
        username                       = config.get("menandmicesuite","username")
        password                       = config.get("menandmicesuite","password")
        thisServerName                 = config.get("menandmicesuite","master-dnsserver")
        DNSSECMMPropName               = config.get("menandmicesuite","dnssec-property-name")
        PolicyMMPropName               = config.get("menandmicesuite","policy-property-name")
        lastSignedMMPropName           = config.get("menandmicesuite","last-signed-property-name")
        nextExpiryMMPropName           = config.get("menandmicesuite","next-expiry-property-name")
        thePolicyListUpdateSaveComment = config.get("menandmicesuite","policy-list-update-save-comment")

        defaultPolicy                  = config.get("opendnssec","default-policy")        
        databasefile                   = config.get("opendnssec","database-file")
        theDestDir                     = config.get("opendnssec","signed-zones-dir")
        theUnsignedDir                 = config.get("opendnssec","unsigned-zones-dir")
        theWorkingDir                  = config.get("opendnssec","work-dir")
        odsksmutil                     = config.get("opendnssec","path-to-odsksdmutil")
        
        thisProcessName                = config.get("odsmmsync","syslog-process-tag")
        theScriptDir                   = config.get("odsmmsync","script-dir")
        theSlaveServersListFile        = config.get("odsmmsync","slave-servers-list")


        #fetch existing opendnssec zones
        conn = sqlite3.connect(databasefile)
        c = conn.cursor()

        existingPolicies = {}
        c.execute(sqlstatement)
        for row in c:
                existingPolicies[row[0]] = row[1]

        c.close()
        conn.close()

        #fetch Men and Mice DNSSEC marked zones
        cli = soapCLI.mmSoap(proxy=proxyServer,server=centralServer,username=username,password=password)
        cli.SetCurrentAddressSpace(addressSpaceRef='<Default>')
        thisAuthority = thisServerName.rstrip('.') + '.'
        dnssecZones = cli.GetDNSZones(filter= DNSSECMMPropName + ':1 authority:' + thisAuthority)
        dnssecZones = dnssecZones.dnsZones.dnsZone if dnssecZones.dnsZones else []

        # filter DNSSEC property in case the SOAP filter failes
        # TODO: check why the SOAP filter sometimes fails
        dnssecZones = [z for z in dnssecZones if getPropertyValue(z.customProperties,DNSSECMMPropName) == '1']

        mmPolicies = {}
        for zone in dnssecZones:
                policy=getPropertyValue(zone.customProperties,PolicyMMPropName) if zone.customProperties else None
                mmPolicies[zone.name.rstrip('.')]=policy.strip() if policy is not None else defaultPolicy
	
        #echo all what was found here
        theString  = 'Policies in Men and Mice:' if len(mmPolicies)>0 else 'No DNSSEC zones in Men and Mice' 
        writeToSyslog(theString)
        for mmZone,mmPolicy in mmPolicies.iteritems():
                writeToSyslog('  ' + mmZone + ': ' + mmPolicy) 

        theString = 'Policies in OpenDNSSEC:' if len(existingPolicies)>0 else 'No DNSSEC zones in OpenDNSSEC'
        writeToSyslog(theString)
        for exZone,exPolicy in existingPolicies.iteritems():
                writeToSyslog('  ' + exZone + ': ' + exPolicy)

        ## handle new zones or changed policies
        for mmZone,mmPolicy in mmPolicies.iteritems():
                if mmZone not in existingPolicies:
                        addNewZone(mmZone,mmPolicy)
                elif mmPolicy != existingPolicies[mmZone]:
                        changePolicy(mmZone,mmPolicy)

        ## handle deleted zones
        for exZone,exPolicy in existingPolicies.iteritems():
                if exZone not in mmPolicies:
                        removeZone(exZone)
                ## we have already handled changed policy

        #regenerate list of notify servers
        dnsServers = cli.GetDNSServers().dnsServers.dnsServer

        serverAddresses = []
        for server in dnsServers:
                if server.name.rstrip('.') != thisServerName.rstrip('.') and 'resolvedAddress' in server and server.resolvedAddress not in serverAddresses:
                        serverAddresses.append(server.resolvedAddress)
        if len(serverAddresses) > 0:
                serverFile = open(theSlaveServersListFile,'w')
                for serveraddr in serverAddresses:
                        serverFile.write(serveraddr + '\n')                
                serverFile.close()
                writeToSyslog('Regenerated list of slave servers to ' + theSlaveServersListFile)
        else:
                os.unlink(theSlaveServersListFile)
                writeToSyslog('WARNING: no slave servers found in configuration')

        #regenerate custom fields in Men and Mice with current policies
        conn = sqlite3.connect(databasefile)
        c = conn.cursor()

        policies=[]
        sqlpolicy='select name from policies'
        c.execute(sqlpolicy)
        for row in c:
                policies.append(row[0])
        policies.sort()

        c.close()
        conn.close()

        propDefs = cli.GetPropertyDefinitions(objType='DNSZone').propertyDefinition
        thePropDef = None
        for propDef in propDefs:
                if not propDef.system and propDef.name == PolicyMMPropName:
                        thePropDef = propDef
                        defListItems = propDef.listItems.string if thePropDef.listItems and thePropDef.listItems.string else []
                        defListItems.sort()
                        if defListItems != policies:
                                thePropDef.listItems.string = policies
                                cli.ModifyPropertyDefinition(objType='DNSZone',property=PolicyMMPropName,propertyDefinition=thePropDef,saveComment=thePolicyListUpdateSaveComment)
                                writeToSyslog('Updated list of policies in Men and Mice "%s" custom field.' % (PolicyMMPropName))
                        break
				
                # set the last sign date and next expiry date
                for zone in dnssecZones:
                        updateSigningDatesCPs(zone)
