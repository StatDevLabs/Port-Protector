from asyncio import log
import json
import os
import json
import re
import Settings 


# Initialize Settings
SC = Settings
Scanning_Path = SC.Settings_Check_Configure()["Path to Port Logs"]
Port_Types = SC.Settings_Check_Configure()["Port Types"]


# Keywords that indicate a failed login attempt
FAIL_KEYWORDS = [
    "Failed password",
    "Invalid user",
    "Authentication failure",
    "PAM: Authentication failure",
    "Maximum authentication attempts exceeded",
    "Connection closed by authenticating user",
    "FAIL LOGIN",
    "LOGIN FAILED",
    "530 Login incorrect",
    "530 Permission denied",
    "authentication failure",
    "user not found",
    "password mismatch",
    "unauthorized",
    "invalid credentials",
    "incorrect password",
    "password authentication failed",
    "role does not exist",
    "failed",
    "failure",
    "invalid",
    "denied",
    "incorrect",
    "authentication error",
]

service_names = [
    "ftp",
    "ssh",
    "telnet",
    "smtp",
    "smtps",
    "pop3",
    "pop3s",
    "imap",
    "imaps",
    "ldap",
    "http",
    "https",
    "smb",
    "rdp",
    "mysql",
    "postgresql",
    "mssql",
    "oracle",
    "nfs",
    "docker",
    "redis",
    "mongodb",
    "elasticsearch",
    "kibana",
    "weblogic",
    "zookeeper",
    "vnc",
    "dns",
    "ntp",
    "http-alt",
    "https-alt",
    "smtp-submission",
    "php-fpm",
    "cpanel",
    "cpanel-ssl",
    "dev-http"
]


def load_config():
    pkg_dir = os.path.dirname(__file__)
    data_file = os.path.join(pkg_dir, "Data.json")
    with open(data_file, "r") as file_data:
        data = json.load(file_data)
        return data

def load_state():
    """Load State from TimeStamp.json"""
    try:
        pkg_dir = os.path.dirname(__file__)
        state_file = os.path.join(pkg_dir, "TimeStamp.json")
        with open(state_file, "r") as file_data:
            content = file_data.read().strip()
            if not content:  # File is empty
                return {}
            state = json.loads(content)
            if not isinstance(state, dict):
                return {}
    except (FileNotFoundError, json.JSONDecodeError):
        state = {}
    return state

def save_state_only(state):
    """Only save the State tracking, don't touch Events"""
    pkg_dir = os.path.dirname(__file__)
    state_file = os.path.join(pkg_dir, "TimeStamp.json")
    with open(state_file, "w") as file_data:
        json.dump(state, file_data, indent=4)


# filters the logs from the scanning process to output a neat IP Address result for the ban mechanism
def filtering_logs(Material):
    material_lower = Material.lower()
    if not any(word.lower() in material_lower for word in FAIL_KEYWORDS):
        return None

    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", Material)
    if not ip_match:
        return None

    ip_address = ip_match.group()
    normalized_service_names = [service.lower() for service in service_names]

    for service in normalized_service_names:
        if service in material_lower:
            return ip_address, service

    port_match = re.search(r"\bport\s+(\d+)\b", material_lower)
    if port_match:
        return ip_address, port_match.group(1)

    return ip_address, "unknown"


# actual scanning process done here
def Scanning_paths():
    data = load_config()

    # use your JSON key exactly
    Port_Log_Path = data["Path to Port Logs"]

    # Load state from TimeStamp.json
    state = load_state()

    detected_ips = []  # List of IPs (with duplicates if same IP attempts multiple times)
    new_state = {}  # Track new state separately

    for Log in Port_Log_Path:
        key = os.path.abspath(Log)

        try:
            st = os.stat(Log)
        except FileNotFoundError:

            if key in state:
                new_state[key] = state[key]
            continue

        prev = state.get(key, {})
        prev_inode = prev.get("inode")
        prev_offset = prev.get("offset", 0)

        if prev_inode != st.st_ino or prev_offset > st.st_size:
            prev_offset = 0

        with open(Log, "r", errors="ignore") as file_data:
            file_data.seek(prev_offset)

            for line in file_data:
                Material = line.strip()
                True_or_False = filtering_logs(Material)

                if True_or_False:
                    detected_ips.append(True_or_False)

            new_offset = file_data.tell()
            new_state[key] = {"inode": st.st_ino, "offset": new_offset}

    save_state_only(new_state)
    
    Scanning_paths.last_state = new_state
    
    return detected_ips


def Save_Shutdown():
    """Saves the current state to TimeStamp.json on shutdown"""
    current_state = getattr(Scanning_paths, 'last_state', load_state())
    pkg_dir = os.path.dirname(__file__)
    state_file = os.path.join(pkg_dir, "TimeStamp.json")
    with open(state_file, "w") as file_data:
        json.dump(current_state, file_data, indent=4)