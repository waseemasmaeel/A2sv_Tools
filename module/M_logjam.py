import socket
import subprocess
from C_display import *

# Module

def m_logjam_run(ip_address, iPort, displayMode):
    # Identifier is not used
    IP = ip_address.strip()
    try:
        socket.inet_aton(IP)
        showDisplay(" - [LOG] IP Check Ok.")
    except socket.error:
        showDisplay("%s, invalid IP" % IP)
        return "0x02"
    
    try:
        showDisplay(" - [LOG] Start SSL Connection / Gathering Information")
        result = subprocess.run(
            ['openssl', 's_client', '-connect', f"{ip_address}:{iPort}", "-cipher", "EDH"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=4,
            text=True
        ).stdout
        showDisplay(" - [LOG] Ending Get Information")
        
        if "Cipher is EDH" in result:
            showDisplay(" - [LOG] 'Cipher is EDH' in Response")
            return "0x01"
        else:
            showDisplay(" - [LOG] 'Cipher is EDH' not in Response")
            return "0x00"
    except subprocess.TimeoutExpired:
        showDisplay(" - [LOG] Timeout occurred while connecting to the server.")
        return "0x02"
    except Exception as e:
        showDisplay(f"[INF] Error in LOGJAM Module: {e}")
        return "0x02"
