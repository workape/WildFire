#WildFire Automation Scripts

##wf-ftp-control.py
This script will handle the functionality of picking up files from an incoming directory, locking them, sending
them up to WildFire for scanning, then based upon determination of file status the files will be either unlocked
(for benign files) or kept locked and alerted on for malware.  Benign files are then moved into the outgoing
directory.

This system is proposed to be used with an FTP server with an external (untrusted/public) interface and an internal
(trusted/private) interface.  The basics of the system is that files are uploaded into the external interface, this
interface will be bound to the /ftp/incoming directory by the ftp service.  If the files are found to be not malware
they will be "released" into the /ftp/outgoing directory.  This /ftp/outgoing directory will be bound to the
internal interface by the ftp service.


ASCII Art to visualize.

    <external ftp>                                                       -> [if malware] -> <alert to syslog>
          |                                                             /
    </ftp/incoming> -> [files locked] -> <moved to /ftp/quarantine> -> <
                                                                        \
                                                                         -> [if benign]  -> <move to /ftp/outgoing>
                                                                                                         |
                                                                                                   <internal ftp>

Global Variables definitions, these are the only components that will need have their configuration adjusted.
>**wf_tracking_db** - This is the location of the sqlite DB which will be used for tracking files move through the script.

>**wf_files_incoming** - This is the location of files that are uploaded to the file server, files are held here until scanned.

>**wf_files_outgoing** - This is the location of files that have been determined to not be malware by the WildFire system.

>**wf_url_upload** - This is the URL of the WildFire system where files will be uploaded.

>**wf_url_report** - This is the URL of the WildFire system where reports will be pulled.

>**wf_api_key** - This is the API Key for connecting to the WildFire system.

>**logging_dev** - This is the OS device used for the connection to the logging subsystem.

##create-tracker-db.py
This script will create the sqlite3 database which is used by the wf-ftp-control.py script.  It is a simple enough
to use and simply creates a DB with the following schema:

>**hash** _text primary key_ - This is the SHA256 hash which is locally generated on the box before uploading.
>**filename** _text_ - This is the full path to the file that is being uploaded, this will be updated to reflect the location of the file as it moves through the incoming/quarantine/outgoing directories.
>**owner_uid** _text_ - This is the UID of the owner of the uploaded file.
>**upload_successful** _text_ - This is a status checker about whether or not a file has been uploaded or not.
>**file_type** _text_ - This refers to whether or not a file is malware, benign, or still unknown due to a lack ofreport back from the WildFire system.