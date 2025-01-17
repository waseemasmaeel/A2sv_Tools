#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#==============================================
#    A2SV(Auto Scanning to SSL Vulnerability  |
#     by HaHwul(www.hahwul.com)               |
#     https://github.com/hahwul/a2sv          |
#==============================================
import os
import sys
import argparse
import socket
import datetime
import subprocess
from urllib.parse import urlparse

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/module")
from M_ccsinjection import *
from M_heartbleed import *
from M_poodle import *
from M_freak import *
from M_logjam import *
from M_drown import *
from M_crime import *
from M_anonymous import *
from C_display import *

#==============================================
displayMode = 0
targetMode = 0
output_ck = 0
output_path = "./a2sv_output.txt"

targetfileList = []
# Version 
myPath = os.path.dirname(os.path.abspath(__file__))
with open(myPath + "/version", "r") as vfp:
    a2sv_version = vfp.read().rstrip()
#==============================================

global targetIP
global port
global ccs_result
global heartbleed_result
global poodle_result
global freak_result
global logjam_result
global drown_result
global crime_result
global anonymous_result

# Set Result Val
# -1: Not Scan
# 0x00: Not Vuln
# 0x01: Vuln
ccs_result = "-1"
heartbleed_result = "-1"
poodle_result = "-1"
freak_result = "-1"
logjam_result = "-1"
drown_result = "-1"
crime_result = "-1"
anonymous_result = "-1"
#===========================
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
PURPLE = '\033[95m'
VIOLET = '\033[0;35m'
END = '\033[0m'

## Report Table
class TablePrinter(object):
    "Print a list of dicts as a table"
    def __init__(self, fmt, sep=' ', ul=None):
        """        
        @param fmt: list of tuple(heading, key, width)
                        heading: str, column label
                        key: dictionary key to value to print
                        width: int, column width in chars
        @param sep: string, separation between columns
        @param ul: string, character to underline column label, or None for no underlining
        """
        super(TablePrinter, self).__init__()
        self.fmt = str(sep).join('{lb}{0}:{1}{rb}'.format(key, width, lb='{', rb='}') for heading, key, width in fmt)
        self.head = {key: heading for heading, key, width in fmt}
        self.ul = {key: str(ul) * width for heading, key, width in fmt} if ul else None
        self.width = {key: width for heading, key, width in fmt}

    def row(self, data):
        return self.fmt.format(**{k: str(data.get(k, ''))[:w] for k, w in self.width.items()})

    def __call__(self, dataList):
        _r = self.row
        res = [_r(data) for data in dataList]
        res.insert(0, _r(self.head))
        if self.ul:
            res.insert(1, _r(self.ul))
        return '\n'.join(res)
########################

#def mainScreen():
#    os.system('cls' if os.name == 'nt' else 'clear')
#    showDisplay(displayMode, "                                A_A")
#    showDisplay(displayMode, "                               (-.-)")
#    showDisplay(displayMode, "                               /   h ")
#    showDisplay(displayMode, "                              |     |   __ ")
#    showDisplay(displayMode, "                              |  || |  |  t__  ")
#    showDisplay(displayMode, "                               t_|| /_/ ")
#    showDisplay(displayMode, "                    в–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•— в–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•— в–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•—в–Ҳв–Ҳв•—   в–Ҳв–Ҳв•— ")
#    showDisplay(displayMode, "                   в–Ҳв–Ҳв•”в•җв•җв–Ҳв–Ҳв•—в•ҡв•җв•җв•җв•җв–Ҳв–Ҳв•—в–Ҳв–Ҳв•”в•җв•җв•җв•җв•қв–Ҳв–Ҳв•‘   в–Ҳв–Ҳв•‘ ")
#    showDisplay(displayMode, "                   в–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•‘ в–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•”в•қв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•—в–Ҳв–Ҳв•‘   в–Ҳв–Ҳв•‘ ")
#    showDisplay(displayMode, "                   в–Ҳв–Ҳв•”в•җв•җв–Ҳв–Ҳв•‘в–Ҳв–Ҳв•”в•җв•җв•җв•қ в•ҡв•җв•җв•җв•җв–Ҳв–Ҳв•‘в•ҡв–Ҳв–Ҳв•— в–Ҳв–Ҳв•”в•қ")
#    showDisplay(displayMode, "                   в–Ҳв–Ҳв•‘  в–Ҳв–Ҳв•‘в–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•—в–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•‘ в•ҡв–Ҳв–Ҳв–Ҳв–Ҳв•”в•қ ")
#    showDisplay(displayMode, "                   в•ҡв•җв•қ  в•ҡв•җв•қв•ҡв•җв•җв•җв•җв•җв•җв•қв•ҡв•җв•җв•җв•җв•җв•җв•қ  в•ҡв•җв•җв•җв•қ  ")
#    showDisplay(displayMode, BLUE + "               [Auto Scanning to SSL Vulnerability " + a2sv_version + "]" + END)
#    showDisplay(displayMode, VIOLET + "                     by HaHwul (www.hahwul.com)" + END)
#    showDisplay(displayMode, "________________________________________________________________________")

def runScan(s_type):
    global ccs_result, heartbleed_result, poodle_result, freak_result, logjam_result, drown_result, crime_result, anonymous_result

    print(GREEN)
    # SSL Check Logic --------------------------- 
    showDisplay(GREEN + "[INF] Check the SSL.." + END)
    result = subprocess.Popen(['timeout', '4', 'openssl', 's_client', '-connect', targetIP + ":" + str(port)], stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
    if b"Connection refused" in result:
        showDisplay(RED + "[RES] This target does not support SSL.." + END)
    # ------------------------------------------------------
    else:
        showDisplay(GREEN + "[RES] This target supports SSL.." + END)
        if s_type == "anonymous":
            showDisplay(GREEN + "[INF] Scan Anonymous Cipher.." + END)
            anonymous_result = m_anonymous_run(targetIP, port, displayMode)
            showDisplay(GREEN + "[RES] Anonymous Cipher :: " + anonymous_result + END)
        elif s_type == "crime":
            showDisplay(GREEN + "[INF] Scan CRIME(SPDY).." + END)
            crime_result = m_crime_run(targetIP, port, displayMode)
            showDisplay(GREEN + "[RES] CRIME(SPDY) :: " + crime_result + END)
        elif s_type == "heart":
            showDisplay(GREEN + "[INF] Scan HeartBleed.." + END)
            heartbleed_result = m_heartbleed_run(targetIP, port, displayMode)
            showDisplay(GREEN + "[RES] HeartBleed :: " + heartbleed_result + END)
        elif s_type == "ccs":
            showDisplay(GREEN + "[INF] Scan CCS Injection.." + END)
            ccs_result = m_ccsinjection_run(targetIP, port, displayMode)
            showDisplay(GREEN + "[RES] CCS Injection :: " + ccs_result + END)
        elif s_type == "poodle":
            showDisplay(GREEN + "[INF] Scan SSLv3 POODLE.." + END)
            poodle_result = m_poodle_run(targetIP, port, displayMode)
            showDisplay(GREEN + "[RES] SSLv3 POODLE :: " + poodle_result + END)
        elif s_type == "freak":
            showDisplay(GREEN + "[INF] Scan OpenSSL FREAK.." + END)
            freak_result = m_freak_run(targetIP, port, displayMode)
            showDisplay(GREEN + "[RES] OpenSSL FREAK :: " + freak_result + END)
        elif s_type == "logjam":
            showDisplay(GREEN + "[INF] Scan OpenSSL LOGJAM.." + END)
            logjam_result = m_logjam_run(targetIP, port, displayMode)
            showDisplay(GREEN + "[RES] OpenSSL LOGJAM :: " + logjam_result + END)
        elif s_type == "drown":
            showDisplay(GREEN + "[INF] Scan SSLv2 DROWN.." + END)
            logjam_result = m_drown_run(targetIP, port, displayMode)
            showDisplay(GREEN + "[RES] SSLv2 DROWN :: " + drown_result + END)
        else:
            showDisplay(GREEN + "[INF] Scan Anonymous Cipher.." + END)
            anonymous_result = m_anonymous_run(targetIP, port, displayMode)
            showDisplay(GREEN + "[INF] Scan CRIME(SPDY).." + END)
            crime_result = m_crime_run(targetIP, port, displayMode)
            showDisplay(GREEN + "[INF] Scan CCS Injection.." + END)
            ccs_result = m_ccsinjection_run(targetIP, port, displayMode)
            showDisplay(GREEN + "[INF] Scan HeartBleed.." + END)
            heartbleed_result = m_heartbleed_run(targetIP, port, displayMode)
            showDisplay(GREEN + "[INF] Scan SSLv3 POODLE.." + END)
            poodle_result = m_poodle_run(targetIP, port, displayMode)
            showDisplay(GREEN + "[INF] Scan OpenSSL FREAK.." + END)
            freak_result = m_freak_run(targetIP, port, displayMode)
            showDisplay(GREEN + "[INF] Scan OpenSSL LOGJAM.." + END)
            logjam_result = m_logjam_run(targetIP, port, displayMode)
            showDisplay(GREEN + "[INF] Scan SSLv2 DROWN.." + END)
            drown_result = m_drown_run(targetIP, port, displayMode)
            showDisplay(GREEN + "[RES] Finish scan all vulnerability.." + END)

def outVersion():
    print("A2SV v" + a2sv_version)

def updateVersion():
    print(GREEN + "[INF] Update A2SV" + END)
    print(GREEN + "[INF] This A2SV version is .. v" + a2sv_version + END)
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    os.system("git reset --hard HEAD")
    os.system("git pull -v")
    with open(myPath + "/version", "r") as vfp:
        print(RED + "[FIN] Updated A2SV" + END)

def outReport(o_ck, o_path, tmode):
    global ccs_result, heartbleed_result, poodle_result, freak_result, logjam_result, drown_result, crime_result, anonymous_result

    results = {
        "anonymous": anonymous_result,
        "crime": crime_result,
        "ccs": ccs_result,
        "heartbleed": heartbleed_result,
        "poodle": poodle_result,
        "freak": freak_result,
        "logjam": logjam_result,
        "drown": drown_result
    }

    for key, value in results.items():
        if value == "0x01":
            results[key] = "Vulnerable!"
        elif value == "0x00":
            results[key] = "Not Vulnerable."
        elif value == "0x02":
            results[key] = "Exception."
        else:
            results[key] = "Not Scan."

    data = [
        {'v_vuln': 'Anonymous Cipher', 'v_cve': 'CVE-2007-1858', 'cvss': 'AV:N/AC:H/Au:N/C:P/I:N/A:N', 'v_state': results["anonymous"]},
        {'v_vuln': 'CRIME(SPDY)', 'v_cve': 'CVE-2012-4929', 'cvss': 'AV:N/AC:H/Au:N/C:P/I:N/A:N', 'v_state': results["crime"]},
        {'v_vuln': 'HeartBleed', 'v_cve': 'CVE-2014-0160', 'cvss': 'AV:N/AC:L/Au:N/C:P/I:N/A:N', 'v_state': results["heartbleed"]},
        {'v_vuln': 'CCS Injection', 'v_cve': 'CVE-2014-0224', 'cvss': 'AV:N/AC:M/Au:N/C:P/I:P/A:P', 'v_state': results["ccs"]},
        {'v_vuln': 'SSLv3 POODLE', 'v_cve': 'CVE-2014-3566', 'cvss': 'AV:N/AC:M/Au:N/C:P/I:N/A:N', 'v_state': results["poodle"]},
        {'v_vuln': 'OpenSSL FREAK', 'v_cve': 'CVE-2015-0204', 'cvss': 'AV:N/AC:M/Au:N/C:N/I:P/A:N', 'v_state': results["freak"]},
        {'v_vuln': 'OpenSSL LOGJAM', 'v_cve': 'CVE-2015-4000', 'cvss': 'AV:N/AC:M/Au:N/C:N/I:P/A:N', 'v_state': results["logjam"]},
        {'v_vuln': 'SSLv2 DROWN', 'v_cve': 'CVE-2016-0800', 'cvss': 'AV:N/AC:M/Au:N/C:P/I:N/A:N', 'v_state': results["drown"]}
    ]

    fmt = [
        ('Vulnerability', 'v_vuln', 16),
        ('CVE', 'v_cve', 13),
        ('CVSS v2 Base Score', 'cvss', 26),
        ('State', 'v_state', 15)
    ]

    if o_ck == 1:
        print("The result is in \"" + str(o_path) + "\".")
        if tmode == 1:
            with open(str(o_path), 'a') as of:
                of.write(" [TARGET]: " + targetIP + "\r\n")
                of.write(" [PORT]: " + str(port) + "\r\n")
                of.write(" [SCAN TIME]: " + str(datetime.datetime.now()) + "\r\n")
                of.write(" [VULNERABILITY]" + "\r\n")
                of.write(TablePrinter(fmt, ul='=')(data))
                of.write("\r\n")
        else:
            with open(str(o_path), 'w') as of:
                of.write(" [TARGET]: " + targetIP + "\r\n")
                of.write(" [PORT]: " + str(port) + "\r\n")
                of.write(" [SCAN TIME]: " + str(datetime.datetime.now()) + "\r\n")
                of.write(" [VULNERABILITY]" + "\r\n")
                of.write(TablePrinter(fmt, ul='=')(data))
                of.write("\r\n")
    else:
        print(BLUE + " [TARGET]: " + targetIP + END)
        print(BLUE + " [PORT]: " + str(port) + END)
        print(BLUE + " [SCAN TIME]: " + str(datetime.datetime.now()) + END)
        print(RED + " [VULNERABILITY]" + END)
        print(TablePrinter(fmt, ul='=')(data))

###MAIN##
parser = argparse.ArgumentParser("a2sv", formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument("-t", "--target", help="Target URL and IP Address\n > e.g -t 127.0.0.1")
parser.add_argument("-tf", "--targetfile", help="Target file(list) URL and IP Address\n > e.g -tf ./target.list")
parser.add_argument("-p", "--port", help="Custom Port / Default: 443\n > e.g -p 8080")
parser.add_argument("-m", "--module", help="Check SSL Vuln with one module\n[anonymous]: Anonymous Cipher\n[crime]: Crime(SPDY)\n[heart]: HeartBleed\n[ccs]: CCS Injection\n[poodle]: SSLv3 POODLE\n[freak]: OpenSSL FREAK\n[logjam]: OpenSSL LOGJAM\n[drown]: SSLv2 DROWN")
parser.add_argument("-d", "--display", help="Display output\n[Y,y] Show output\n[N,n] Hide output")
parser.add_argument("-o", "--out", help="Result write to file\n > e.g -o /home/yourdir/result.txt")
parser.add_argument("-u", "--update", help="Update A2SV (GIT)", action='store_true')
parser.add_argument("-v", "--version", help="Show Version", action='store_true')
args = parser.parse_args()

if args.version:
    outVersion()
    exit()
if args.update:
    updateVersion()
    exit()
if args.display:
    disoption = args.display
    if disoption.lower() == "n":
        print("Running a2sv silent mode")
        displayMode = 1
    else:
        displayMode = 0
if args.target:
    target = args.target
    showDisplay(BLUE + "[SET] target => " + args.target + END)
    targetIP = socket.gethostbyname(target)
    showDisplay(BLUE + "[SET] IP Address => " + targetIP + END)
elif args.targetfile:
    with open(args.targetfile, "r") as f:
        showDisplay(BLUE + "[SET] target => " + args.targetfile + END)
        showDisplay(BLUE + "[SET] IP Address list" + END)
        for line in f:
            targetfileList.append(socket.gethostbyname(line.rstrip('\n')))
            showDisplay(BLUE + "       => " + str(targetfileList[-1:]) + END)
        targetMode = 1
        displayMode = 1
        print("Running a2sv silent mode[file list default]")
else:
    mainScreen()
    showDisplay(displayMode, "Please Input Target Argument / -h --help")
    exit()
if args.port:
    port = int(args.port)
    showDisplay(BLUE + "[SET] target port => " + args.port + END)
else:
    port = 443
    showDisplay(BLUE + "[SET] target port => 443" + END)
if args.module:
    checkVun = args.module
    ModuleName = args.module
    if ModuleName == "ccs":
        ModuleName = "CCS Injection"
    elif ModuleName == "heart":
        ModuleName = "HeartBleed"
    elif ModuleName == "poodle":
        ModuleName = "SSLv3 POODLE Attack"
    elif ModuleName == "freak":
        ModuleName = "OpenSSL FREAK Attack"
    elif ModuleName == "logjam":
        ModuleName = "OpenSSL LOGJAM Attack"
    elif ModuleName == "drown":
        ModuleName = "SSLv2 DROWN Attack"
    elif ModuleName == "crime":
        ModuleName = "CRIME(SPDY)"
    elif ModuleName == "anonymous":
        ModuleName = "Anonymous Cipher Suite"
    showDisplay(BLUE + "[SET] include => " + ModuleName + " Module" + END)
else:
    checkVun = "all"
    showDisplay(BLUE + "[SET] include => All Module" + END)

if args.out:
    output_path = args.out
    output_ck = 1
else:
    output_ck = 0

#if displayMode == 0:
#    mainScreen()
if targetMode == 1:
    i = 0
    imax = len(targetfileList)
    print("_________________________________________________________________________")
    print("                              [A2SV REPORT]                             ")
    while i < imax:
        targetIP = targetfileList.pop()
        runScan(checkVun)
        outReport(output_ck, output_path, targetMode)
        i += 1
    print("_________________________________________________________________________")
else:
    runScan(checkVun)
    print("_________________________________________________________________________")
    print("                              [A2SV REPORT]                             ")
    outReport(output_ck, output_path, targetMode)
    print("_________________________________________________________________________")
showDisplay(RED + "[FIN] Scan Finish!" + END)
