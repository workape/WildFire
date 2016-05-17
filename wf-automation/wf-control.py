#!/usr/bin/env python

import os
import requests
import sqlite3
import hashlib
import logging
import logging.handlers
import lxml.etree as ET
import pwd

__author__ = 'Tighe Schlottog || tschlottog@paloaltonetworks.com'
__version__ = '1.0.0'
__license__ = 'GPL'

'''
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
    wf_tracking_db - This is the location of the sqlite DB which will be used for tracking files move through the script.
    wf_files_incoming - This is the location of files that are uploaded to the file server, files are held here until scanned.
    wf_files_outgoing - This is the location of files that have been determined to not be malware by the WildFire system.
    wf_url_upload - This is the URL of the WildFire system where files will be uploaded.
    wf_url_report - This is the URL of the WildFire system where reports will be pulled.
    wf_api_key - This is the API Key for connecting to the WildFire system.
    logging_dev - This is the OS device used for the connection to the logging subsystem.
'''

wf_tracking_db = '/wf-control/wf-file-tracker.db'
wf_files_incoming = '/ftp/incoming'
wf_files_quarantine = '/ftp/quarantine'
wf_files_outgoing = '/ftp/outgoing'
wf_url_upload = 'https://wildfire.paloaltonetworks.com/publicapi/submit/file'
wf_url_report = 'https://wildfire.paloaltonetworks.com/publicapi/get/report'
wf_api_key = 'cd3bd322ddc8065664ce787c89504f9e'
logging_dev = '/dev/log'


def load_incoming_files_into_db():
    '''
    This function will ingest all files within a directory, looping through on each file and pulling together the full
    path.  It will generate a hash, track the original owner of the file, and lock it until a result can be pulled from
    the WildFire systems.

    :param incoming_dir: The location of the files to be scanned by wildfire.
    :return: This function does not return any variables.
    '''
    global wf_files_incoming
    global wf_files_quarantine
    sql_con = sqlite3.connect(wf_tracking_db)
    sql_cur = sql_con.cursor()
    for filename in os.listdir(wf_files_incoming):
        file_full_path = '%s/%s' % (wf_files_incoming, filename)
        quarantine_file_path = '%s/%s' % (wf_files_quarantine, filename)
        file_hash = file_hasher(file_full_path)
        file_owner = str(os.stat(file_full_path).st_uid)
        lock_file(file_full_path)
        quarantine_file(file_full_path)
        try:
            sql_cur.execute('insert into wf_tracking values ("%s", "%s", "%s", "no", "unknown")' % (file_hash, quarantine_file_path, file_owner))
            log_errors('User %s has uploaded file %s with a SHA256 hash of %s' % (pwd.getpwuid(int(file_owner))[0], file_full_path, file_hash))
        except sqlite3.IntegrityError:
            log_errors('Hash already exists within WildFire tracker')
    sql_con.commit()


def upload_files_control():
    '''
    This function will upload all files that are currently not flagged with upload_successful = "yes"
    :return: This function does not return any variables.
    '''
    sql_con = sqlite3.connect(wf_tracking_db)
    sql_cur = sql_con.cursor()
    for file_upload in sql_cur.execute('select * from wf_tracking where upload_successful = "no"'):
        (file_hash, file_name, file_owner, file_status, file_type) = file_upload
        upload_status = wf_upload(file_name)
        if upload_status == 200:
            sql_cur.execute('update wf_tracking set upload_successful="yes" where hash="%s"' % file_hash)
        elif upload_status == 413:
            sql_cur.execute('update wf_tracking set upload_successful="oversize" where hash="%s"' % file_hash)
            log_errors('File %s is too large to upload to WildFire, file will be unlocked and passed without scanning' % file_name)
        elif upload_status == 418:
            sql_cur.execute('update wf_tracking set upload_successful="unsupported" where hash="%s"' % file_hash)
            log_errors('File Type for file %s is not supported for WildFire scanning, file will be unlocked and passed without scanning' % file_name)
        elif upload_status == 513:
            log_errors('Unable to upload file %s to WildFire, will upload next iteration' % file_name)
        else:
            wf_error_codes(upload_status)
    sql_con.commit()


def report_hashes_control():
    '''
    This function will pull a list of files from the sqlite database that has been successfully uploaded and are still
    in an unknown state (have not been determined to be malware or not).

    :return: This function does not return any variables.
    '''
    sql_con = sqlite3.connect(wf_tracking_db)
    sql_cur = sql_con.cursor()
    malware_list = []
    for sql_data in sql_cur.execute('select hash,filename,owner_uid from wf_tracking where upload_successful="yes" and file_type="unknown"'):
        (file_hash, file_name, file_owner) = sql_data
        file_status = wf_report(file_hash)
        if file_status != 'unknown':
            if file_status == 'yes':
                sql_cur.execute('update wf_tracking set file_type="malware" where hash="%s"' % file_hash)
                sql_con.commit()
                malware_list.append(file_hash)
            else:
                sql_cur.execute('update wf_tracking set file_type="benign" where hash="%s"' % file_hash)
                sql_con.commit()
                log_errors('WildFire reports file %s with SHA256 hash %s is benign' % (file_name, file_hash))
                unlock_file(file_name, file_owner)
                release_file(file_hash, file_name)
    alert_malware(malware_list)


def wf_upload(wf_filename):
    '''
    This function will upload a file to the WildFire systems for scanning.

    :param wf_filename: This string is the full path location of the file that is going to be uploaded.
    :return: Will return the HTTP status code.
    '''
    global wf_url_upload
    global wf_api_key

    wf_headers = {'apikey': wf_api_key}
    try:
        wf_file = {'file': open(wf_filename, 'rb')}
        wf_req = requests.post(wf_url_upload, data=wf_headers, files=wf_file)
    except IOError as err:
        log_errors('Unable to open file "%s": %s' % (wf_file, err.strerror))
    except requests.exceptions.ConnectionError:
        log_errors('An error has occurred contacting %s, please check the URL and try again.' % wf_url_upload)
    return wf_req.status_code


def wf_report(wf_hash):
    '''
    This function will take in a SHA256 hash and query the WildFire system for a report based on that hash.

    :param wf_hash: SHA256 Hash that is used to pull the report from WildFire
    :return: Will return either a yes, no, or unknown.  Unknown is used for when a HTTP 404 is returned, which is the
    response that occurs when the report is not available within the API.
    '''
    global wf_url_report
    global wf_api_key
    wf_headers = {"apikey": wf_api_key, "hash": wf_hash, "format": 'xml'}

    try:
        wf_req = requests.post(wf_url_report, data=wf_headers)
        if wf_req.status_code == requests.codes.ok:
            root = ET.fromstring(wf_req.content)
            return root.xpath('//wildfire/file_info/malware/text()')[0]
        elif wf_req.status_code == 404:
            return "unknown"
        else:
            wf_error_codes(wf_req.status_code)
    except requests.exceptions.ConnectionError:
        log_errors('An error has occurred contacting %s, please check the URL and try again.' % wf_url_report)


def wf_error_codes(error_code):
    '''
    This function will take in the HTTP error codes from the requests function in both the upload and download functions
    and parse them out into human readable error messages.

    :param error_code: http error code from the requests module functions (req_handler.status_code)
    :return: This function does not return any variables.
    '''
    if error_code == 401:
        log_errors("HTTP Error %s: API Key is invalid, please retry with valid WildFire API key" % error_code)
    elif error_code == 404:
        log_errors('HTTP Error %s: Cannot find report associated with requested hash' % error_code)
    elif error_code == 405:
        log_errors('HTTP Error %s: You must use the POST method for this call' % error_code)
    elif error_code == 419:
        log_errors("HTTP Error %s: You have exceeded your maximum number of requests per day" % error_code)
    elif error_code == 420:
        log_errors("HTTP Error %s: Insufficient arguments for accessing the API" % error_code)
    elif error_code == 421:
        log_errors('HTTP Error %s: Invalid arguments for accessing the API' % error_code)
    elif error_code == 500:
        log_errors("HTTP Error %s: WildFire cloud is currently experiencing issues, please try again later" % error_code)
    else:
        log_errors('An unknown error has occurred, the HTTP status code is ', error_code)


def file_hasher(filename):
    '''
    This function will generate the SHA256 hash of a file that is handed too it.

    :param filename: This is the full path for the file that will be hashed.
    :return: The function will return the SHA256 hash as a string for use in other functions.
    '''
    bsize = 65536
    f_hash = hashlib.sha256()
    try:
        with open(filename, 'rb') as hash_file:
            buf = hash_file.read(bsize)
            while len(buf) > 0:
                f_hash.update(buf)
                buf = hash_file.read(bsize)
    except IOError as err:
        log_errors('Unable to open file "%s": %s' % (filename, err.strerror))
    return f_hash.hexdigest()


def lock_file(filename):
    '''
    This function will "lock" a file, setting it to be unreadable/unwritable as well as change the owner to root.

    :param filename: This is the full path of the file that is being locked.
    :return: This function does not return any variables.
    '''
    log_errors('Locking file %s' % filename)
    os.chmod(filename, 0000)
    os.chown(filename, 0, -1)


def unlock_file(filename, uid):
    '''
    This function will "unlock" a file, setting it back to a owner read/write, group read as well as back to the
    original owner.

    :param filename: This is the full path of the file that is being unlocked.
    :param uid: This is the original owner of the file.
    :return: This function does not return any variables.
    '''
    log_errors('Unlocking file %s for user %s' % (filename, pwd.getpwuid(int(uid))[0]))
    os.chmod(filename, 0640)
    os.chown(filename, int(uid), -1)


def quarantine_file(filename):
    '''
    This function will move the file from the incoming directory to the quarantine directory.

    :param filehash: SHA256 hash of the file being quarantined
    :param filename: Location of file in the incoming files directory
    :return: This function does not return any variables.
    '''
    global wf_files_quarantine
    quarantine_fileloc = '%s/%s' % (wf_files_quarantine, filename.split('/')[-1])
    os.rename(filename, quarantine_fileloc)


def release_file(filehash, filename):
    '''
    This function will move the file from the quarantine directory to the outgoing directory.

    :param filehash: SHA256 hash of the file that is being released.
    :param filename: Location of the file in the quarantine directory.
    :return: This function does not return any variables.
    '''
    global wf_files_outgoing
    outgoing_fileloc = '%s/%s' % (wf_files_outgoing, filename.split('/')[-1])
    os.rename(filename, outgoing_fileloc)
    sql_con = sqlite3.connect(wf_tracking_db)
    sql_cur = sql_con.cursor()
    sql_cur.execute('update wf_tracking set filename="%s" where hash="%s"' % (outgoing_fileloc, filehash))
    sql_con.commit()


def log_errors(log_msg):
    '''
    This function will log an error to syslog, which can then be exported back out to external syslog systems.

    Note:  The handler will need to be targeted to the correct "address" in the event of Ubuntu (and most *nix) this
    will likely be /dev/log, but in the event of Mac OSX this will be /var/run/syslog.  Verify for your OS and update
    the global logging_dev variable.

    :param log_msg: This is the string that will be sent to syslog.
    :return: This function does not return any variables.
    '''

    global logging_dev
    err_logger = logging.getLogger('WFLogger')
    err_logger.setLevel(logging.DEBUG)
    handler = logging.handlers.SysLogHandler(address=logging_dev)
    err_logger.addHandler(handler)
    err_logger.critical('WF-CONTROL: %s' % log_msg)


def alert_malware(malware_list):
    '''
    This function will log alert on files that has been identified as malware by the WildFire systems.

    :param malware_list: List of hashes that have been determined by previous functions.
    :return: This function does not return any variables.
    '''
    for filehash in malware_list:
        log_errors('File hash %s has been determined to be malware by WildFire, file will not be released' % filehash)

if __name__ == '__main__':
    load_incoming_files_into_db()
    upload_files_control()
    report_hashes_control()
