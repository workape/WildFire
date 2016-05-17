# WildFire CLI Scripts

###wf.py
wf.py is a script to interact with the WildFire API to upload files or pull back reports on specific hashes.  You
need to have the argparse and requests installed.  Both modules perform their functions perfectly for the work that
is looking to be completed.

These modules can be installed with a **pip install argparse** and **pip install requests**, that is assuming that
you have pip installed.  If you don't have pip installed, you will need to obtain it for your OS before moving
forward with installing the modules.  pip is awesome, seriously get it.

For functional assistance, check out the -h or --help options while executing the wf.py script.

Currently the script is configured to use the WildFire public cloud, but you can easily adapt it to use your WF-500.
This can be done by altering the wf_upload_url and wf_report_url global variables just under the leading comment
block in the script.


