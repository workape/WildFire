# WildFire CLI Scripts

###wf.py

    wf.py is a script to interact with the WildFire API to upload files or pull back reports on specific hashes.  You
    need to have the argparse and requests installed.  Both modules perform their functions perfectly for the work that
    is looking to be completed.

    For functional assistance, check out the -h or --help options while executing the wf.py script.

    Currently the script is configured to use the WildFire public cloud, but you can easily adapt it to use your WF-500.

    This script is only for use with file uploads and report pulling.

    File uploads are completed and the WildFire reported SHA256 hash will be output.
    Report pulls are written in the format of wildfire-report-<SHA256 hash>.<report format>, they can be either PDF or
    XML.

