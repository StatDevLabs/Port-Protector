import json
import time
import os, sys, subprocess, shutil, ipaddress

# checks if program is run in root

def check_root_status():
    if os.geteuid() != 0:
        print("Port Protector must be run as root to function properly.")
        sys.exit(1)

def enable_whitelisting():
    if os.geteuid() != 0:
        print("Port Protector must be run as root to configure UFW whitelist rules.")
        sys.exit(1)

    IP = Settings_Check_Configure().get("Whitelist", [])
    templist = [ip.strip() for ip in IP if ip.strip()]

    if not templist:
        print("There are no IP's listed. Port Protector needs at least one trusted IP just in case Port Protector needs to activate Port Lockdown \n")
        print("DO NOT SHARE THESE TRUSTED IP'S WITH ANYONE OR ELSE THEY WILL BE ABLE TO BYPASS PORT PROTECTORS DEFENSES")
        sys.exit(1)

    for checking in templist:
        try:
            ipaddress.ip_address(checking)
        except ValueError:
            print(f"IP --> {checking} <-- INVALID, please correct this IP")
            sys.exit(1)

        try:

            subprocess.run(["ufw", "allow", "from", str(checking),
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        except OSError as exc:
            print(f"Failed to add whitelist rule for {checking}: {exc}")
            sys.exit(1)

# Warns user about Software usage 3 times

def Warn_User(Settings_Check_Configure):
    if Settings_Check_Configure["Warn User Amount"] < 3:
        print("Thank you for usintg Port Protector!\n")

        print("Port protector is supposed to be a fun project for me to learn how brute forcing network services works and how to defend against them\n")
        time.sleep(3)
        print("I highly do not reccomend you use this software to protect real valuable data, If you do end up using this software in a production enviroment I am not responsible for any damage that may occur\n")
        time.sleep(3)
        print("(Port Protector is a very buggy program)")
        time.sleep(3)
        print("I am not a professional software developer and probably wont be updating this software regularly or even at all")
        time.sleep(3)
        print("Other than that Port Protector will start in\n")
        time.sleep(3)
        print("3...")
        time.sleep(2)
        print("2...")
        time.sleep(1)
        print("1...")
        time.sleep(1)
        print("Protecting Ports Now!\n")

        # Adding a value to "Warn User Amount" in Json file
        pkg_dir = os.path.dirname(__file__)
        data_file = os.path.join(pkg_dir, "Data.json")
        with open(data_file, "r") as file_data:
            data = json.load(file_data)
        
        data["Warn User Amount"] += 1
        
        with open(data_file, "w") as file_data:
            json.dump(data, file_data, indent=4)
    else:
        print ("Port Protector starting now ... \n")

# loads all the Json data for every file to use
 
def Settings_Check_Configure():
    # Load Data.json relative to this package file so imports work from any CWD
    pkg_dir = os.path.dirname(__file__)
    data_file = os.path.join(pkg_dir, "Data.json")
    with open(data_file, "r") as file_data:
        data = json.load(file_data)

    return data

# Remove an IP from the whitelist

def Remove_Whitelist(ip):
    pkg_dir = os.path.dirname(__file__)
    data_file = os.path.join(pkg_dir, "Data.json")
    
    with open(data_file, "r") as file_data:
        data = json.load(file_data)
    
    if ip in data["Whitelist"]:
        data["Whitelist"].remove(ip)
        with open(data_file, "w") as file_data:
            json.dump(data, file_data, indent=4)
        return True
    else:
        return False
    
def Remove_Banned_IP(ip):
    pkg_dir = os.path.dirname(__file__)
    data_file = os.path.join(pkg_dir, "Data.json")
    
    with open(data_file, "r") as file_data:
        data = json.load(file_data)
    
    if ip in data["Banned IPs"]:
        data["Banned IPs"].remove(ip)
        with open(data_file, "w") as file_data:
            json.dump(data, file_data, indent=4)
        return True
    else:
        return False

# Small checks for possible misconfigurations in the Json file
def add_Whitelist(ip):
    pkg_dir = os.path.dirname(__file__)
    data_file = os.path.join(pkg_dir, "Data.json")
    
    with open(data_file, "r") as file_data:
        data = json.load(file_data)

    if ip not in data["Whitelist"]:
        data["Whitelist"].append(ip)
        with open(data_file, "w") as file_data:
            json.dump(data, file_data, indent=4)
        return True

# Add an IP to the banned list

def Add_Banned_IP(ip):
    pkg_dir = os.path.dirname(__file__)
    data_file = os.path.join(pkg_dir, "Data.json")
    
    with open(data_file, "r") as file_data:
        data = json.load(file_data)
    
    if ip not in data["Banned IPs"]:
        data["Banned IPs"].append(ip)
        with open(data_file, "w") as file_data:
            json.dump(data, file_data, indent=4)
        return True
    else:
        return False

# Remove a locked port from banned list

def Remove_Locked_Port(port):
    pkg_dir = os.path.dirname(__file__)
    data_file = os.path.join(pkg_dir, "Data.json")
    
    with open(data_file, "r") as file_data:
        data = json.load(file_data)
    
    locked_port_key = f"PORT LOCKED: {port}"
    if locked_port_key in data["Banned IPs"]:
        data["Banned IPs"].remove(locked_port_key)
        with open(data_file, "w") as file_data:
            json.dump(data, file_data, indent=4)
            
        return True
    else:
        return False

# Add a locked port to banned list

def Add_Locked_Port(port):
    pkg_dir = os.path.dirname(__file__)
    data_file = os.path.join(pkg_dir, "Data.json")
    
    with open(data_file, "r") as file_data:
        data = json.load(file_data)
    
    locked_port_key = f"PORT LOCKED: {port}"
    if locked_port_key not in data["Banned IPs"]:
        data["Banned IPs"].append(locked_port_key)
        with open(data_file, "w") as file_data:
            json.dump(data, file_data, indent=4)
        return True
    else:
        return False


def Any_Small_Checks():
    check_for_programs = subprocess.run(["which", "ufw"], capture_output=True, text=True)
    For_Error = Settings_Check_Configure()["Ban_Type"]
    
    if Settings_Check_Configure()["Ban_Type"] != "temp" and Settings_Check_Configure()["Ban_Type"] != "perm":
        print(f"Ban Type --> {For_Error} <-- not Reconized, please got to the Data.json file and set the Ban Type option to either 'temp' or 'perm'")
        sys.exit()

    elif Settings_Check_Configure()["Temp_Ban_Duration"][0] > 60 or Settings_Check_Configure()["Temp_Ban_Duration"][1] > 60 or Settings_Check_Configure()["Temp_Ban_Duration"][2] > 60:
        print("The Time parameters set for Temp Ban are invalid, please enter a valid time duration")
        sys.exit()

    elif Settings_Check_Configure()["Path to Port Logs"]:
        for path in Settings_Check_Configure()["Path to Port Logs"]:
            if not os.path.exists(path):
                print(f"The Log path --> {path} <-- does not exist, please enter a valid log path in Data.json")
                sys.exit()

    if check_for_programs.returncode != 0:
        
        print("UFW is not found on this system, Port Protector requires UFW to function properly")
        time.sleep(2)
        print("would you like us to automatically isnatll UFW for you? (y/n)\n")
        user_input = input().lower()

        if user_input == "y":
            print("Insstalling UFW now...")
            if shutil.which("apt"):
                subprocess.run(["apt", "install", "ufw", "-y"])
                print("\n")
                print("\n")
                print ("Configuring UFW so Ports IN Data.json are allowed...")
                for port in Settings_Check_Configure()["Port Types"]:
                    subprocess.run(["ufw", "allow", str(port)])  # loop through your ports here
                subprocess.run(["ufw", "enable"])
                print("\n")
                print("\n")
                print ("relaunch Port Protector")
                sys.exit()

            elif shutil.which("dnf"):
                subprocess.run(["dnf", "install", "ufw", "-y"])
                print("\n")
                print("\n")
                print ("Configuring UFW so Ports IN Data.json are allowed...")
                for port in Settings_Check_Configure()["Port Types"]:
                    subprocess.run(["ufw", "allow", str(port)])  # loop through your ports here
                subprocess.run(["ufw", "enable"])
                print("\n")
                print("\n")
                print ("relaunch Port Protector")
                sys.exit()

            elif shutil.which("yum"):
                subprocess.run(["yum", "install", "ufw", "-y"])
                print("\n")
                print("\n")
                print ("Configuring UFW so Ports IN Data.json are allowed...")
                for port in Settings_Check_Configure()["Port Types"]:
                    subprocess.run(["ufw", "allow", str(port)])  # loop through your ports here
                subprocess.run(["ufw", "enable"])
                print("\n")
                print("\n")
                print ("relaunch Port Protector")
                sys.exit()

            elif shutil.which("pacman"):
                subprocess.run(["pacman", "-S", "ufw", "--noconfirm"])
                print("\n")
                print("\n")
                print ("Configuring UFW so Ports IN Data.json are allowed...")
                for port in Settings_Check_Configure()["Port Types"]:
                    subprocess.run(["ufw", "allow", str(port)])  # loop through your ports here
                subprocess.run(["ufw", "enable"])
                print("\n")
                print("\n")
                print ("relaunch Port Protector")
                sys.exit()

            elif shutil.which("zypper"):
                subprocess.run(["zypper", "install", "ufw", "-y"])
                print("\n")
                print("\n")
                print ("Configuring UFW so Ports IN Data.json are allowed...")
                for port in Settings_Check_Configure()["Port Types"]:
                    subprocess.run(["ufw", "allow", str(port)])  # loop through your ports here
                subprocess.run(["ufw", "enable"])
                print("\n")
                print("\n")
                print ("relaunch Port Protector")
                sys.exit()

            elif shutil.which("apk"):
                subprocess.run(["apk", "add", "ufw", "-y"])
                print("\n")
                print("\n")
                print ("Configuring UFW so Ports IN Data.json are allowed...")
                for port in Settings_Check_Configure()["Port Types"]:
                    subprocess.run(["ufw", "allow", str(port)])  # loop through your ports here
                subprocess.run(["ufw", "enable"])
                print("\n")
                print("\n")
                print ("relaunch Port Protector")
                sys.exit()

            else:
                print("package manager not reconized on Port Protector, you may need to manually install and configure UFW (ignore the 2 error messages, its just a non zero exit error)")
                sys.exit()
        else:
            sys.exit()

if __name__ == "__main__":

    enable_whitelisting()
    check_root_status()
    Warn_User(Settings_Check_Configure())
    Any_Small_Checks()
