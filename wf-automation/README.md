#WildFire Automation Scripts

## WildFire FTP Control (wf-ftp-control)
_wf-ftp-control_ is a scripting project to be used in conjunction with a DMZ FTP server to allow the scanning of
incoming files before they are released to the be downloaded to the internal network.  Currently Malware discovery is
alerted via syslog, but as this is being handled out of a module it can be quickly and easily adapted to cover other
functions such as email, SNMP Traps, etc.  Data is tracked in a SQLite3 database as well as to syslog on the system,
please note that if you are running this on a Windows machine, you will need to alert the code for the logging function.


## WildFire Directory Scanning (wf-dir-scan)
**_This project is a work in progress and should not be used at this time._**
_wf-dir-scan_ is a project in progress that will scan any locally mounted directories that it has the permissions to
read the files on.  Several checks will be performed on the files (Reported File Type, Size of File, etc) before
attempting to upload to the WildFire systems.

