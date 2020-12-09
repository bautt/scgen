# scgen
**scgen.py script created by @github/hovu96**
Script which generates serverclasses.conf based on rules file (serverclass_rules.csv) for Splunk deployment server. 

Rules file contains:
- regex for hostname
- CIDR
- regex for OS
- regex application name

## Rules file example:
*serverclass,hostname,cidr,os,apps,active*

*WebServer_Apache,(raspi4)|(data),,linux.\*,^web_auth_apache$,false*
 
*WebServer_nginx,(raspi4)|(data)|(dex)|(test),10.11.12.0/24,,.*nginx$,true*

*DBServer_mysql,^mac,,^darwin,test1,true*

## scgen app
scgen.tar.gz can be installed as a splunk app. 
Resulting serverclass.conf will be written to $SPLUNK_HOME/etc/apps/scgen/local/serverclass.conf

