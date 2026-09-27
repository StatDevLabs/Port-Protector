import json
import os
import threading, sys
import signal
import time

import Settings # type: ignore
import Scan # pyright: ignore[reportMissingImports]
import Ban # type: ignore

SC = Settings 
SS = Scan
BB = Ban
global switch 
switch = True

def active_notifier(status):
    pkg_dir = os.path.dirname(__file__)
    data_file = os.path.join(pkg_dir, "Data.json")

    if os.path.exists(data_file):
        try:
            with open(data_file, "r") as file_data:
                data = json.load(file_data)
        except (json.JSONDecodeError, IOError):
            data = {}
            
        data["Status"] = status
        
        with open(data_file, "w") as file_data:
            json.dump(data, file_data, indent=4)

def settings_ouput_Message():
    print(f"IP banning mode set to --> {str(Ban_Type)}")
    print(f"Whitelisted IP's --> {SC.Settings_Check_Configure()['Whitelist']}")
    print(f"Ban Durationn time --> {Duration_time}\n")

def signal_handler(signum, frame):
    print("\nShutting down Port Protector...")
    SS.Save_Shutdown()
    active_notifier("inactive")
    sys.exit(0)

def main():
    signal.signal(signal.SIGTERM, signal_handler)
    global switch, Ban_Type, Duration_time
    SC.Any_Small_Checks()
    SC.check_root_status()
    SC.enable_whitelisting()
    Ban_Type = SC.Settings_Check_Configure()["Ban_Type"]
    Ban_Type = Ban_Type.lower()
    Duration_time = SC.Settings_Check_Configure()["Temp_Ban_Duration"]
    active_notifier("active")
    SC.Warn_User(SC.Settings_Check_Configure())
    dih = BB.unbanning
    dih = threading.Thread(target=dih, daemon=True)
    dih.start()
    
    settings_ouput_Message()
    
    try:
        while switch == True:

            Scan_Results = SS.Scanning_paths()  
            
            if Scan_Results: 
                for result in Scan_Results:
                    For_Error = SC.Settings_Check_Configure()["Ban_Type"]
                    time_limit = SC.Settings_Check_Configure()["Temp_Ban_Duration"]  # [hours, minutes, seconds]
                    total_seconds = time_limit[0] * 3600 + time_limit[1] * 60 + time_limit[2]
                    Ban.Ban_Choosing(result, Ban_Type, total_seconds)
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nShutting down Port Protector...")
        SS.Save_Shutdown()
        BB.save_temp_bans()
        active_notifier("inactive")
        time.sleep(1.5)
        switch = False


if __name__ == "__main__":
    main()