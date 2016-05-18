#!/usr/bin/env python

__author__ = 'Tighe Schlottog || tschlottog@paloaltonetworks.com'

import sqlite3

conn = sqlite3.connect('wf-file-tracker.db')
curs = conn.cursor()

curs.execute('create table wf_tracking (hash text primary key, filename text, owner_uid text, upload_successful text, file_type text)')
conn.commit()
conn.close()