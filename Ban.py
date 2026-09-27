import os, sys, subprocess, threading, socket
import time, re, logging, json, time
from collections import defaultdict
import Settings

SC = Settings
For_Error = SC.Settings_Check_Configure()["Ban_Type"]

# Configure logging to use an absolute path
pkg_dir = os.path.dirname(__file__)

def _resolve_writable_path(path):
    try:
        with open(path, "a", encoding="utf-8"):
            pass
        return path
    except OSError:
        fallback_dir = os.path.join(os.path.expanduser("~"), ".port_protector")
        os.makedirs(fallback_dir, exist_ok=True)
        fallback_path = os.path.join(fallback_dir, os.path.basename(path))
        try:
            with open(fallback_path, "a", encoding="utf-8"):
                pass
            return fallback_path
        except OSError:
            return path

log_file_path = _resolve_writable_path(os.path.join(pkg_dir, "Foreign_IP_ATTEMPTS.log"))
banned_file_path = _resolve_writable_path(os.path.join(pkg_dir, "Banned_IPS.json"))
logging.basicConfig(filename=log_file_path, level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

ip_attempt_tracker = defaultdict(lambda: {"first_attempt_time": None, "attempt_count": 0})
port_counter = []
global Multiple_IP_counter_list
Multiple_IP_counter_list = []
global TIMING
TIMING = 0
global BANNED_IPS
BANNED_IPS = []
global PERM_BANNED_IPS
PERM_BANNED_IPS = []



def log_ban_attempt(IP, port, type, duration, end_trigger=None):

    if type == "temp":
        logging.info(IP + " attempted to access port " + str(port) + " Multiple times and is now banned for " + str(duration) + " seconds")

    elif type == "perm":
        logging.info(IP + " attempted to access port " + str(port) + " Multiple times and is now permanently banned")
    
    elif end_trigger == "unban":
        logging.info(IP + " ban duration of " + str(duration) + " seconds has expired and is now unbanned")

    elif type == "port_lockdown":
        logging.info("Port " + str(port) + " is being attacked by multiple IPs and is now in lockdown mode")

    elif type == "manual_unban_temp":
        logging.info(IP + " was manually unbanned by the user [IGNORE SECOND MESSAGE OF THIS IP BEING UNBANNED, THAT IS A BUG I WILL FIX IN THE NEXT UPDATE]")

    elif type == "manual_unban_perm":
        logging.info(IP + " was manually unbanned by the user")


def Ban_Choosing(IP_Address, Ban_Type, time_limit):
    global TIMING
    try:
        logging.info(f"Ban_Choosing called with {IP_Address}, Ban_Type={Ban_Type}, time_limit={time_limit}")
    except Exception:
        pass

    Whitelist = [w.strip() for w in SC.Settings_Check_Configure()["Whitelist"]]
    if Ban_Type == "temp":
        for entrys in Whitelist:
            if entrys == (IP_Address[0] if isinstance(IP_Address, (list, tuple)) else IP_Address):
                print("ALLOWED")
                logging.info(f"A white-listed IP --> {IP_Address[0]} <-- tried accessing port {IP_Address[1]}")
                break
        else:
            TIMING = time_limit
            temp_ban(IP_Address, time_limit)

    elif Ban_Type == "perm":
        for entrys in Whitelist:
            if entrys == (IP_Address[0] if isinstance(IP_Address, (list, tuple)) else IP_Address):
                print("ALLOWED")
                logging.info(f"A white-listed IP --> {IP_Address[0]} <-- tried accessing port {IP_Address[1]}")
                break
        else:
            TIMING = time_limit
            perm_ban(IP_Address)
    else:
        print(f"Ban Type --> {For_Error} <-- not Reconized, please got to the Data.json file and set the Ban Type option to either 'temp' or 'perm'")


# actual perm banning takes place here
def perm_ban(IP_Address):

    BAN_IP = single_port_detection(IP_Address)
    BAN_IP_MULTIPLE = Multiple_IP_single_port_detection(IP_Address)

    if BAN_IP:
        # Check if IP is already permanently banned
        if BAN_IP in PERM_BANNED_IPS:
            if BAN_IP not in SC.Settings_Check_Configure()["Banned IPs"]:
                PERM_BANNED_IPS.remove(BAN_IP)
            else:
                return

        subprocess.run(["ufw", "insert", "1", "deny", "from", str(BAN_IP)])
        SC.Add_Banned_IP(BAN_IP)
        PERM_BANNED_IPS.append(BAN_IP)
        subprocess.run(["ss", "-K", f"dst {BAN_IP}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # Close sockets to this IP
        log_ban_attempt(BAN_IP, None, "perm", None, None)
        print(f" [!] IP ADDRESS --> {BAN_IP} <-- ATTEMPTED TO ACCESS {IP_Address[1]} [!]")
        print(f"[!] {BAN_IP} has been permanently banned [!]")

        if BAN_IP_MULTIPLE in PERM_BANNED_IPS:
            return
        else:
            pass
        



# temp banning happens here
def temp_ban(IP_Address, time_limit):

    BAN_IP  = single_port_detection(IP_Address)
    BAN_IP_MULTIPLE = Multiple_IP_single_port_detection(IP_Address)


    if BAN_IP:
        # Check if IP is already banned
        ip_already_banned = False
        for index, entry in enumerate(BANNED_IPS):
            if entry[0] == BAN_IP:
                if BAN_IP not in SC.Settings_Check_Configure()["Banned IPs"]:
                    del BANNED_IPS[index]
                else:
                    ip_already_banned = True
                break
        
        if not ip_already_banned:
            subprocess.run(["ufw", "insert", "1", "deny", "from", str(BAN_IP)])
            BANNED_IPS.append([BAN_IP, "START", time.time(), time_limit])
            SC.Add_Banned_IP(BAN_IP)
            subprocess.run(["ss", "-K", f"dst {BAN_IP}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # Close sockets to this IP
            log_ban_attempt(BAN_IP, IP_Address[1], SC.Settings_Check_Configure()["Ban_Type"], time_limit)
            print (f" [!] IP ADDRESS --> {BAN_IP} <-- ATTEMPTED TO ACCESS {IP_Address[1]} [!]")
            print (f"[!] {BAN_IP} will be banned for {time_limit} seconds [!]")
            
        else:
            pass

        if BAN_IP_MULTIPLE in PERM_BANNED_IPS:
            return
        else:
            pass


def PORT_LOCKDOWN(Port):
    Whitelist = SC.Settings_Check_Configure()["Whitelist"]
    Whitelist_COUNTER = len(Whitelist)
    print ("FIRST", Port)

    if Port:
        Block = Nametonumber(Port)
        
        # Check if port is already locked to prevent UFW "Skipping inserting existing rule"
        if f"PORT LOCKED: {Block}" in SC.Settings_Check_Configure()["Banned IPs"]:
            return

        print (Block)
        subprocess.run(["ufw", "insert", str(Whitelist_COUNTER + 1), "deny", f"{Block}/tcp"],check=True)
       
        SC.Add_Banned_IP(f"PORT LOCKED: {Block}")

        log_ban_attempt(None, Block, "port_lockdown", None, None)

    for ip, __ in Multiple_IP_counter_list:

        subprocess.run(["ss", "-K", f"dst {ip}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)



# detects ip's atacking a single port
def single_port_detection(IP_Address):
    
    current_time = time.time()
    ip = IP_Address[0]
    
   
    tracker = ip_attempt_tracker[ip]
    
    # first attempt posted on the tracker list
    if tracker["first_attempt_time"] is None:
        tracker["first_attempt_time"] = current_time
        tracker["attempt_count"] = 1

    else:
        # Calculate time difference
        time_difference = current_time - tracker["first_attempt_time"]
        
        # Check if time window has expired
        if time_difference >= 10:
            # Reset if time window expired
            tracker["first_attempt_time"] = current_time
            tracker["attempt_count"] = 1
            
        else:
            # Still within 10 second window, increment count
            tracker["attempt_count"] += 1
           

            # Ban if 5+ attempts within 60 seconds
            if tracker["attempt_count"] >= 5:
                
                TARGET = ip
                # Reset tracker for this IP
                ip_attempt_tracker[ip] = {"first_attempt_time": None, "attempt_count": 0}
                return TARGET
            

def Multiple_IP_single_port_detection(IP_Address):
    global port_counter
    global Multiple_IP_counter_list

    if IP_Address in Multiple_IP_counter_list:
        return

    Multiple_IP_counter_list.append(IP_Address)
    port = IP_Address[1]

    # Find existing port entry
    port_entry = None
    for entry in port_counter:
        if entry[0] == port:
            port_entry = entry
            break

    now_mono = time.monotonic()
    print(Multiple_IP_counter_list)

    if port_entry:
        port_entry[2] += 1
        first_seen_mono = port_entry[3]
        if (now_mono - first_seen_mono) <= 10 and port_entry[2] >= 2:
            PORT_LOCKDOWN(port)
            print(f"[!] ALERT: Port {port} is being attacked by multiple IPs [!]\n")
            print(f"[!] {port} is in lockdown mode use white-listed IP's to investigate remotely [!]\n")
            # Reset lists after lockdown to prevent stale data
            Multiple_IP_counter_list.clear()
            port_counter.clear()
        else:
            Multiple_IP_counter_list.clear()
            port_counter.clear()
            print("CLEARED")

    else:
        normal_time = time.strftime("%H:%M:%S", time.localtime())
        port_counter.append([port, normal_time, 1, now_mono])
        print(f"Port {port} first attack detected at {normal_time}")

# temp ban timer for banned IP's
def unbanning():
    while True:
        for search in BANNED_IPS:
            if search[1] == "START":
                ip = search[0]
                ban_start_time = search[2]
                time_limit = search[3]
                current_time = time.time()
                elapsed_time = current_time - ban_start_time
                
                if elapsed_time >= time_limit:
                    subprocess.run(["ufw", "delete", "deny", "from", str(ip)])
                    search[1] = "REMOVED"
                    print(f"[!] IP ADDRESS --> {ip} <-- BAN EXPIRED AND IS NOW UNBANNED [!]")
                    log_ban_attempt(ip, None, None, time_limit, end_trigger="unban")
            elif search[1] == "MANUAL":
                search[1] = "REMOVED"

        BANNED_IPS[:] = [entry for entry in BANNED_IPS if entry[1] != "REMOVED"]
        
        time.sleep(1)


def Nametonumber(name):
    if str(name).isdigit():
        return name
    try:
        return socket.getservbyname(name)
    except OSError:
        return name