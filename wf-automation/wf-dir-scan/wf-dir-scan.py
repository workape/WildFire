#!/usr/bin/env python

import requests
import magic
import hashlib
import os

__author__ = 'Tighe Schlottog || tschlottog@paloaltonetworks.com'

DEBUG = True
supported_mime_types = [] # This needs to be defined with the MIME types that are supported in WildFire
wf_upload_url = ''
wf_report_url = ''
wf_api_key = ''
target_dir = ''


def file_checks(filename):
    '''
    This function will perform all necessary file checks on a file before it is sent up to WildFire
    :param filename:
    :return:
    '''
    file_hash = file_hasher(filename)
    file_type = file_typer(filename)
    file_size = file_sizer(filename)
    if file_hash and file_type and file_size:
        if DEBUG:
            print 'File %s is good for WildFire Upload' % filename
        return True
    else:
        if DEBUG:
            print 'File %s is not good for WildFire Upload' % filename
        return False


def file_hasher(filename):
    '''
    This function will generate the SHA256 hash of a file that is handed too it.

    :param filename: This is the full path for the file that will be hashed.
    :return: Either the SHA256 hash or False in the case that an error is raised.
    '''
    bsize = 65536
    f_hash = hashlib.sha256()
    try:
        with open(filename, 'rb') as hash_file:
            buf = hash_file.read(bsize)
            while len(buf) > 0:
                f_hash.update(buf)
                buf = hash_file.read(bsize)
            return f_hash.hexdigest()
    except IOError as err:
        if DEBUG:
            print 'Error: Cannot open %s %s' % (filename, err.strerror)
        return False


def file_typer(filename):
    '''
    This function will find the MIME type of a file from the magic number and return it if possible.

    :param filename: This is the file that is to be checked.
    :return: Either the MIME type or False in the case that an error is raised.
    '''
    global supported_mime_types
    try:
        return magic.from_file(filename, mime=True)
    except IOError as file_err:
        if DEBUG:
            print 'Error: Cannot open %s %s' % (filename, file_err.strerror)
        return False


def file_sizer(filename):
    '''
    This function will find the size of a file

    :param filename: This is the file that is to be sized
    :return: Either the size of file in bytes or False in the case that an error is raised.
    '''
    try:
        if os.stat(filename).st_size < 10000000:
            return True
        else:
            if DEBUG:
                print 'Error: %s exceeds WildFire maximum 10MB file size limitation.' % filename
    except OSError as size_err:
        if DEBUG:
            print 'Error: Cannot open %s %s' % (filename, size_err.strerror)
        return False

def wf_upload(wf_filename):
    '''
    This function will upload a file to the WildFire systems for scanning.

    :param wf_filename: This string is the full path location of the file that is going to be uploaded.
    :return: Will return the HTTP status code.
    '''
    global wf_upload_url
    global wf_api_key

    wf_headers = {'apikey': wf_api_key}
    try:
        wf_file = {'file': open(wf_filename, 'rb')}
        wf_req = requests.post(wf_url_upload, data=wf_headers, files=wf_file)
    except IOError as err:
        print 'Unable to open file "%s": %s' % (wf_file, err.strerror)
    except requests.exceptions.ConnectionError:
        print 'An error has occurred contacting %s, please check the URL and try again.' % wf_url_upload
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
        print 'An error has occurred contacting %s, please check the URL and try again.' % wf_url_report


def wf_error_codes(error_code):
    '''
    This function will take in the HTTP error codes from the requests function in both the upload and download functions
    and parse them out into human readable error messages.

    :param error_code: http error code from the requests module functions (req_handler.status_code)
    :return: This function does not return any variables.
    '''
    if error_code == 401:
        print "HTTP Error %s: API Key is invalid, please retry with valid WildFire API key" % error_code
    elif error_code == 404:
        print 'HTTP Error %s: Cannot find report associated with requested hash' % error_code
    elif error_code == 405:
        print 'HTTP Error %s: You must use the POST method for this call' % error_code
    elif error_code == 419:
        print "HTTP Error %s: You have exceeded your maximum number of requests per day" % error_code
    elif error_code == 420:
        print "HTTP Error %s: Insufficient arguments for accessing the API" % error_code
    elif error_code == 421:
        print 'HTTP Error %s: Invalid arguments for accessing the API' % error_code
    elif error_code == 500:
        print "HTTP Error %s: WildFire is currently experiencing issues, please try again later" % error_code
    else:
        print 'An unknown error has occurred, the HTTP status code is ', error_code


def wf_control():
    global target_dir
    for file in os.listdir(target_dir):
        file_fullpath = '%s/%s' % (target_dir, file)
        if file_checks(file_fullpath):
            wf_upload(file_fullpath)

if __name__ == '__main__':
    #wf_control()
    pass

