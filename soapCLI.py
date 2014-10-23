#!/usr/bin/env python -i
from suds import *
from getpass import getpass
import re
from suds.plugin import MessagePlugin


def isList(invar):
	if isinstance(invar,type([])):return True
	else:return False

class mmSoap(client.Client):
	"""
	A module that eases the usage of the Men and Mice SOAP API. 
	
	Start by creating the client:
		cli = mmSoap(proxy=<M&M web server>,server=<M&M Central server>,username=<user name>,password=<password>)
	
	For help of the cli client object, type:
		cli.help()
	
	"""

	def __init__(self,proxy='localhost',server='localhost',platform='windows',https=False,username=None,password=None,namespace=None,**kw):
		class EnvelopeFixer(MessagePlugin):
			def marshalled(self, context):
				root = context.envelope.getRoot()
				envelope = root.getChild("Envelope")
				envelope.getChildren()[1].setPrefix("SOAP-ENV")
				# print envelope.getChildren()[1]
				return context
		
		
		if platform == 'unix':
			url = "http://" + proxy + ":8111/Soap?WSDL?server=" + server
		elif platform == 'windows':
			url = 'http://' + proxy + '/_mmwebext/mmwebext.dll?WSDL?server=' + server
		else:
			print 'Platform not known. Known platforms are "unix" and "windows"'
			return
			
		if https:
			url=url.replace('http://','https://')

		if namespace:
			url=url+'?ns='+namespace
		
		
		kw['plugins']=[EnvelopeFixer()]
		client.Client.__init__(self,url,**kw)
		
		#print self.services
			
		self._url=url
		self._proxy=proxy
		self._server=server
		self._username=username
		self._password=password
		self._session=None
		self._errNetObjHandler='Unable to complete operation. Netobject handler not running'
		self._errInvalidSession='Invalid or expired session'
		self.login(server=server,username=username,password=password)
	
	def __getattr__(self,name):		
		self._operation=name
		return self


	def __call__(self,operation=None,*args,**kw):
		kw['session']=self._session
		if operation==None: operation = self._operation
		
		try:
			return getattr(self._client.service,operation)(*args,**kw)		
		except WebFault,e:
			if self._session is not None and (self._errInvalidSession in str(e) or self._errNetObjHandler in str(e)):
				print 'Trying to log in again because: ' + str(e)
				self.login()
				kw['session']=self._session
				return getattr(self._client.service,operation)(*args,**kw)
			else:
				raise


	def __checkLogin(self):
		if self._session == None: 
			print "You are not logged in. "
			
		
	def login(self,server=None,username=None,password=None):
		if server==None:
			server=self._server
			print 'Server: ' + server
		if username==None:
			username = self._username
			print 'Username: ' + username 
		if password==None: 
			password = self._password
			
		self._session=self.Login(server=self._server,loginName=username,password=password)
		return self._session
	
	def logout(self):
		self.Logout()
	
	
	def __getHelp(self):
		arr = []
		arr.append('\nUsage:')
		arr.append('         >>> cli.<soap call>(parameter1=value1,...) - to call a soap service function')
		arr.append('         >>> cli.factory.create("<name-of-object/array">) - to create an object or array')
		arr.append(' ')
		arr.append('Example: ')
		arr.append('         >>> result = cli.GetDNSZones(filter="name:.com")')
		arr.append('         >>> newZone = cli.create("DNSZone")')
		arr.append('         >>> newZone.name="the.cool.zone.com"')
		arr.append('         >>> newZone.dnsViewRef="server1:"')
		arr.append('         >>> newZone.type.value = "Master"')
		arr.append('         >>> res = cli.AddDNSZone(dnsZone=newZone)')
		arr.append(' ')
		arr.append('To print out all available SOAP commands or with an optional filter (case insensitive):')
		arr.append('         >>> cli.services([filter])')
		arr.append('To print out all available objects/arrays/enumerables or with an optional filter (case insensitive):')
		arr.append('         >>> cli.objects([filter])')
		arr.append('For further information, please refer to the SOAP documentation at: "' + self._url.replace('?WSDL?','?WSDLDoc?') + '"')
		return '\n'.join(arr)
	
	def help(self):
		print self.__getHelp()
	
	def _getServices(self,theFilter=None):
		outString = ''
		for commandObj in self.sd[0].ports[0][1]:
			command = commandObj[0]
			if theFilter is not None and theFilter.lower() not in command.lower():
				continue 
			theSpace='       '
			outString += command + '(\n'
			
			for param in commandObj[1]:
				paramName = param[0]
				if paramName == 'session':
					continue
				paramType = param[1].type[0]
				reqnill=[]
				if param[1].required():
					reqnill.append('required')
				else:
					reqnill.append('optional')
				if param[1].nillable:
					reqnill.append('nillable')
				else:
					reqnill.append('non-nillable')
				reqnill =  '\n' if len(reqnill)==0 else '   [' + ', '.join(reqnill) + ']\n'
				theComma = ',' if param is not commandObj[1][-1] else ''
				outString += theSpace + paramType + '  ' + paramName + theComma + reqnill
				
			outString += ')\n\n'
		
		if outString is '':
			outString = 'No mathing service found\n'
		return outString
	
	def _getObjects(self,theFilter=None):
		allTypes = []
		for type in cli.sd[0].types:
			if theFilter is not None and theFilter.lower() not in type[0].name.lower():
				continue
			allTypes.append(str(self.factory.create(type[0].name)))
		return '\n'.join(allTypes)
	
	def __str__(self):
		return self._getServices()
	
	
	def services(self,theFilter=None):
		print self._getServices(theFilter)	
	
	def objects(self,theFilter=None):
		print self._getObjects(theFilter)
		
	
	def create(self,name):
		return self.factory.create(name)
	
						
	def servers(self,**kw):
		srvs = self.GetDNSServers(**kw)['dnsServers']['dnsServer']
		if not isinstance(srvs,type([])): srvs=[srvs]
		
		srvslist = [item['name'] for item in srvs]
		for item in srvslist: print item
		return srvslist
		
		
		
	def zones(self,**kw):
		dnsZones = self.GetDNSZones(**kw)['dnsZones']['dnsZone']
		if not isinstance(dnsZones,type([])): dnsZones=[dnsZones]
			
		views={}
		fqdnParts=[]
		for i in range(len(dnsZones)):
			czone=dnsZones[i]
			cviewRef=czone['dnsViewRef']
			if cviewRef not in views:
				cview=self.GetDNSView(dnsViewRef=cviewRef)
				cserver=self.GetDNSServer(dnsServerRef=cview['dnsServerRef'])
				
				views[cviewRef] = {'viewName':cview['name'],'serverName':cserver['name']}	
			
			fqdnParts.append({'viewName':views[cviewRef]['viewName'],'serverName':views[cviewRef]['serverName'],'zoneName':czone['name'],'zoneType':czone['type'],'zoneObj': czone})
	
		fqdns = ["%s:%s:%s" % (item['serverName'],item['viewName'],item['zoneName']) for item in fqdnParts]
		types = [item['type'] for item in dnsZones]
		for i in range(len(fqdns)):
			print fqdns[i] + '\t' + types[i]
	
		return fqdnParts
	
	
	
	def _getZone(self,fqzonename,debug=False,**kw):
		fqpatt=re.search(r'([\.\-\_\w]*):([\.\-\_\w]*):([\.\-\_\w]*)',fqzonename)
		if fqpatt:
			zonename=fqpatt.groups()[2]
			viewname=fqpatt.groups()[1]
			servername=fqpatt.groups()[0]
			if debug==True: print zonename,':',viewname,':',servername
			
			serverObj = self.GetDNSServers(filter='name:^'+servername+'$',limit=1)
			if int(serverObj['totalResults'])==0:
				print 'Server "' + servername + '" not found'
				return
			viewObj = self.GetDNSViews(filter='name:^'+viewname+'$ dnsServerRef:^'+serverObj['dnsServers']['dnsServer']['ref']+'$',limit=1)
			if int(viewObj['totalResults'])==0:
				print 'View "' + viewname + '" on server "' + servername + '" not found'
				return
			dnsViewRef = viewObj['dnsViews']['dnsView']['ref']
		else:
			zonename=fqzonename
			dnsViewRef=''
	
		filter = 'name:^'+zonename + '$ '
		if dnsViewRef:
			filter += 'dnsViewRef:'+dnsViewRef+ ' '
		if kw.has_key('filter'): filter += kw['filter']
		kw['filter']=filter
		
		if debug:print kw
		
		res= self.GetDNSZones(**kw)
		if int(res['totalResults'])==0:
			print 'Zone ' + zonename + ' not found!'
			return None
			
		res =res['dnsZones']['dnsZone']
		out=res if isList(res) else [res]
		return out

		
	def zoneInfo(self,fqzonename,print2stdout=True,**kw):
		theZones = self._getZone(fqzonename,**kw)
		if theZones == None: return
		
		tmpOut=[]	
		orgfields=['name','authority','type','dynamic','adIntegrated']
		fields=orgfields[:]
		for zone in theZones:
			tmpZone={}
			for f in range(len(orgfields)):
				tmpZone[orgfields[f]]=zone[orgfields[f]]
			
			cProps=zone['customProperties']
			if isinstance(cProps,type('')): 
				cProps=[]
			else: 
				cProps=cProps['property']
				
			if not isinstance(cProps,type([])): cProps=[cProps]
			for item in cProps:
				if item['name'] not in fields: fields.append(item['name'])
				tmpZone[item['name']] = item['value']
			
			tmpOut.append(tmpZone)
		
		zonesOut=[]
		for zone in tmpOut:
			tmpZone={}
			for field in fields:
				tmpZone[field] = zone[field] if zone.has_key(field) else ''
			zonesOut.append(tmpZone)

		if print2stdout:
			for field in fields: print field + '\t',
			print '\n'
			
			for zone in zonesOut:
				for field in fields: print zone[field] +'\t',
				print '\n'
		
		return zonesOut
		
	def printZone(self,fqzonename,**kw):
		theZones=self._getZone(fqzonename)
		if theZones == None: return
		
		if len(theZones)>1: 
			print 'Zone name is ambiguous'
			return
		else:
			theZone=theZones[0]
			
		records=self.GetDNSRecords(dnsZoneRef=theZone['ref'],**kw)['dnsRecords']['dnsRecord']
		if not isList(records): records=[records]
		
		
		fields=['name','ttl','type','data','comment','enabled']
		colwidths=[25,6,6,25,20,3]
		for f in range(len(fields)):
			print fields[f]+':'.ljust(colwidths[f]) + ' ',
		print
		
		for rec in records:
			for f in range(len(fields)):
				print rec[fields[f]].ljust(colwidths[f]) + ' ',
			print
			
		return records

def main():
	import optparse
	import sys,os
    
	p=optparse.OptionParser('\n        ./%prog [options] \nOR\n        python -i %prog [options]')
	p.add_option('--server','-s',default='localhost',help='The address of the M&M Web Server which hosts the SOAP web service')
	p.add_option('--central','-c', default=None, help='The address of the M&M Central server, if different from "--server" option')
	p.add_option('--user','-u',default='administrator',help = 'The M&M username')
	p.add_option('--password','-p',default='administrator',help='The password for user')
	p.add_option('--namespace','-n',default=None,help='The additional namespace(s - commma separated) to include')
	opts,args = p.parse_args()

	
	
	if opts.central is None:
		opts.central = opts.server
		
	print 'Using...'
	print 'Web server: ' + opts.server
	print 'Central server  : ' + opts.central
	print 'Username        : ' + opts.user
	print 'Password        : ******'
	if opts.namespace:
		print 'Namespace       : ' + opts.namespace	
	print '\n'
	
	try:
		cli = mmSoap(proxy=opts.server,server=opts.central,username=opts.user,password=opts.password,namespace=opts.namespace)
		print 'Successfully created the SOAP service and stored in the variable "cli", accessible from this prompt'
		cli.help()
		print '\n\n\n\n'
		return cli
	except:
		print 'Could not create "cli" variable...Exiting'
		os._exit(os.EX_OK)

if __name__ == '__main__':
	
	try:
		cli = main()
	except:
		os._exit(os.EX_OK)
	
	
