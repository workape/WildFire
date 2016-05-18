#!/usr/bin/env python

import requests
import magic
import hashlib
import os

__author__ = 'Tighe Schlottog || tschlottog@paloaltonetworks.com'

DEBUG = True


def file_checks(filename):
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


file_checks('./README.md')

