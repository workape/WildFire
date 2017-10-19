#!/usr/bin/env python

import argparse
import requests
import sys
import os
import xml.dom.minidom

__author__ = 'Tighe Schlottog || tschlottog@paloaltonetworks.com'

'''
    wf.py is a script to interact with the WildFire API to upload files or pull back reports on specific hashes.  You
    need to have the argparse and requests installed.  Both modules perform their functions perfectly for the work that
    is looking to be completed.

    For functional assistance, check out the -h or --help options while executing the wf.py script.

    Currently the script is configured to use the WildFire public cloud, but you can easily adapt it to use your WF-500.

    This script is only for use with file uploads and report pulling.

    File uploads are completed and the WildFire reported SHA256 hash will be output.
    Report pulls are written in the format of wildfire-report-<SHA256 hash>.<report format>, they can be either PDF or
    XML.
'''

#  Global Variables (only edit these)
wf_upload_url = 'https://wildfire.paloaltonetworks.com/publicapi/submit/file'
wf_report_url = 'https://wildfire.paloaltonetworks.com/publicapi/get/report'


def parse_args():
    '''
    This function is used to parse the CLI arguments that are passed into the function, after parsing the data it will
    return both the parser itself and the parsed arguments.  While not needed, the parser is passed back in case of
    future need.
    :return: parser - the argparse parser itself
    :return: args - the parsed CLI arguments
    '''
    parser = argparse.ArgumentParser(description='Script to upload unknown files to WildFire.')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-f', '--file', type=str, help='Location of file to upload to WildFire')
    group.add_argument('-d', '--dir', type=str, help='Location of directory of files to upload to WildFire')
    parser.add_argument('-hash', type=str, help='SHA256 hash of file to pull report from WildFire')
    parser.add_argument('-api_key', type=str, help='WildFire API Key')
    parser.add_argument('-format', type=str, help='Report file format (either xml or pdf)')
    parser.add_argument('-hf', '--hashfile', type=str, help='File of hashes to pull reports from WildFire')
    args = parser.parse_args()
    check_args(parser, args)
    return parser, args


def check_args(parser, wf_args):
    '''
    This function will take in the parser and the parsed args and will perform some basic verification checks.  The
    checks themselves are more complicated than rules that I can feed into the argparse module.
    :param parser: argparse parser
    :param wf_args: parsed CLI arguments, came from the parser argparse handler
    :return: Nothing, this is just a basic verification check.  The function will exit the entire script if it doesn't
    pass muster.
    '''
    if not (((wf_args.file or wf_args.dir) or ((str(wf_args.format).lower() != 'xml' or str(wf_args.format).lower() != 'pdf')and wf_args.hash)) and wf_args.api_key):
        print "You are missing one of the necessary options, please check your command structure and try again."
        parser.print_help()
        sys.exit()


def wf_error_codes(error_code):
    '''
    This function will take in the HTTP error codes from the requests function in both the upload and download functions
    and parse them out into human readable error messages.
    :param error_code: http error code from the requests module functions (req_handler.status_code)
    :return:  Nothing, this will dump human readable errors and exit the script.
    '''
    if error_code == 401:
        print "HTTP Error %s: API Key is invalid, please retry with valid WildFire API key" % error_code
        sys.exit()
    elif error_code == 404:
        print 'HTTP Error %s: Cannot find report associated with requested hash' % error_code
        sys.exit()
    elif error_code == 405:
        print 'HTTP Error %s: You must use the POST method for this call' % error_code
        sys.exit()
    elif error_code == 413:
        print "HTTP Error %s: Sample file size exceeds maximum WildFire allowed size" % error_code
        sys.exit()
    elif error_code == 418:
        print "HTTP Error %s: Sample file type is unsupported" % error_code
        sys.exit()
    elif error_code == 419:
        print "HTTP Error %s: You have exceeded your maximum number of requests per day" % error_code
        sys.exit()
    elif error_code == 420:
        print "HTTP Error %s: Insufficient arguments for accessing the API" % error_code
        sys.exit()
    elif error_code == 421:
        print 'HTTP Error %s: Invalid arguments for accessing the API' % error_code
        sys.exit()
    elif error_code == 500:
        print "HTTP Error %s: WildFire cloud is currently experiencing issues, please try again later" % error_code
        sys.exit()
    elif error_code == 513:
        print 'HTTP Error %s: File upload to WildFire has failed, please check file and try again' % error_code
        sys.exit()
    else:
        print 'An unknown error has occurred, the HTTP status code is ', error_code
        sys.exit()


def upload_wf_control(wf_args):
    '''
    This is a control function to access the upload_wf_file function.  For directories, it will look through all the
    files in the directory and upload them.  For single files, it will push through the single upload.
    :param wf_args: These are the parsed CLI arguments from the previous parse_args function.
    :return:  Nothing, this is a control function which calls another function.
    '''
    if wf_args.dir:
        try:
            for file in os.listdir(wf_args.dir):
                upload_wf_file(wf_args, '%s/%s' %(wf_args.dir, file))
        except OSError as err:
            print '%s -> %s' % (err.strerror, wf_args.dir)
    elif wf_args.file:
        upload_wf_file(wf_args, wf_args.file)
    else:
        print 'Something went wrong, you should never see this error.'
        sys.exit()


def upload_wf_file(wf_args, filename):
    '''
    This function is used to upload files into the WildFire Cloud
    :param wf_args: This is the parsed CLI arguments from the called parse_args function.
    :param wf_file: This is the name of the file from either the args.file or from the read directory on args.dir
    :return: Nothing, this function only uploads files into the WildFire Cloud.
    '''
    global wf_upload_url
    wf_headers = {'apikey': wf_args.api_key}
    try:
        wf_file = {'file': open(filename, 'rb')}
    except IOError as err:
        print 'Unable to open file "%s", %s' % (wf_file, err.strerror)
        sys.exit()

    try:
        wf_req = requests.post(wf_upload_url, data=wf_headers, files=wf_file)
    except requests.exceptions.ConnectionError:
        print 'An error has occurred contacting %s, please check the URL and try again.' % wf_upload_url
        sys.exit()

    if wf_req.status_code != requests.codes.ok:
        wf_error_codes(wf_req.status_code)
    else:
        print 'Successfully uploaded %s with SHA256 hash %s' % (filename, xml.dom.minidom.parseString(wf_req.text).getElementsByTagName('sha256')[0].firstChild.nodeValue)


def pull_wf_report(hash, args):
    '''
    This function will pull down reports from the WildFire Cloud.  It can be pulled down in either PDF or XML formats,
    the reports will then be written to the file of the appropriate type.
    :param args: This is the parsed CLI arguments from the called parse_args function.  All components needed will be
    pulled from this passed parameter.
    :return: Nothing, this function only pulls down reports from the WildFire Cloud.
    '''
    global wf_report_url
    wf_headers = {"apikey": args.api_key, "hash": hash, "format": str(args.format).lower()}
    wf_filename = 'wildfire-report-%s.%s' % (hash, str(args.format).lower())

    try:
        wf_req = requests.post(wf_report_url, data=wf_headers)
    except requests.exceptions.ConnectionError:
        print 'An error has occurred contacting %s, please check the URL and try again.' % wf_report_url
        sys.exit()

    if wf_req.status_code != requests.codes.ok:
        wf_error_codes(wf_req.status_code)
    else:
        print 'Successfully pulled report wildfire-report-%s.%s' % (hash, str(args.format).lower())
        with open(wf_filename, 'wb') as wf_dataout:
            wf_dataout.write(wf_req.content)


def multi_hash(args):
    '''
    This function will roll through a file one line at a time to pull the associated hashes on that line.  It will
    assume that there is a single hash per line and chop off anything after a space.
    :param args: This is the parsed CLI arguments from the called parse_args function.  All components needed will be
    pulled from this passed parameter.
    :return: Nothing, this function only loops and calls the pull_wf_report function for pulling reports.
    '''
    with open(args.hashfile, 'r') as hashes:
        for hash in hashes:
            hash = hash.split() # Drop anything after a space character
            pull_wf_report(hash, args)


def main():
    args_parser, args = parse_args()
    if args.hash:
        pull_wf_report(args.hash, args)
    elif args.hashfile:
        multi_hash(args)
    else:
        upload_wf_control(args)
    pass


if __name__ == '__main__':
    main()
