import queue
import threading
import getopt
import sys
import urllib.request as urllib2
import hashlib
import socket
import time
import os
import re
# import netaddr
import subprocess
from C_display import *

# Module

def m_anonymous_run(ip_address, iPort, displayMode):
    # Identifier is not used
    IP = ip_address.strip()
    try:
        socket.inet_aton(IP)
        showDisplay(" - [LOG] IP Check Ok.")
    except socket.error:
        showDisplay("%s, invalid IP" % IP)
        return "0x02"
    
    try:
        showDisplay(" - [LOG] Start SSL Connection")
        result = subprocess.Popen(
            ['timeout', '4', 'openssl', 's_client', '-connect', ip_address + ":" + str(iPort), "--cipher", "aNULL"],
            stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
        showDisplay(" - [LOG] Analysis SSL Information")
        
        if "handshake failure" in result.decode('utf-8'):
            showDisplay(" - [LOG] 'Connection fail'")
            return "0x01"
        else:
            showDisplay(" - [LOG] 'Connection success'")
            return "0x00"
    except Exception as e:
        showDisplay("[INF] Error Anonymous Module: %s" % str(e))
        return "0x02"
