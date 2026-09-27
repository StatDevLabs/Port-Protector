from rich.console import Console
from rich.table import Table
import argparse
import subprocess
import sys
import time
import Ban as BB
import Settings as SC
import os, json
import Main as MM

class SilentArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        sys.exit(1)
reader = SilentArgumentParser(prog="pp", description="Port Protector CLI", epilog="usage:\n pp <command> <arguments>")
material = reader.add_subparsers(
    dest="cmd",
    required=False,
    title="commands",
    metavar=" settings | unban | remove | ban | show-banned | add | unlock | lock | list-add | list-remove | add-port | remove-port | set-min | set-hour | set-sec | set-ban-type",
)


# show settings/config
material.add_parser("settings")
material.add_parser("show-banned")
material.add_parser("start")
material.add_parser("stop")
material.add_parser("show-logs")

# unban: remove a ban for a specific IP
unban_parser = material.add_parser("unban")
unban_parser.add_argument("ip", help="IP address to unban")

# add: add an IP address to whitelist
add_parser = material.add_parser("add")
add_parser.add_argument("ip", help="IP address to add to whitelist")

# ban: ban an IP address; optional --perm to force permanent ban
ban_parser = material.add_parser("ban")
ban_parser.add_argument("ip", help="IP address to ban")
ban_parser.add_argument("--perm", action="store_true", help="Make ban permanent")

# remove: remove an IP from whitelist and UFW allow rule
remove_parser = material.add_parser("remove")
remove_parser.add_argument("ip", help="IP address to remove from ufw rules")

# unlock: unlock a port that was locked due to multiple IP attacks
unlock_parser = material.add_parser("unlock")
unlock_parser.add_argument("port", help="Port number to unlock")

lock_parser = material.add_parser("lock")
lock_parser.add_argument("port", help="Port number to lock")

list_parser = material.add_parser("list-add")
list_parser.add_argument("port", help="Port number to list-add")

list_parser = material.add_parser("list-remove")
list_parser.add_argument("port", help="Port number to list-remove")

list_parser = material.add_parser("add-port")
list_parser.add_argument("port", help="Port number to add to list of ports to monitor")

list_parser = material.add_parser("remove-port")
list_parser.add_argument("port", help="Port number to remove from list of ports to monitor")

list_parser = material.add_parser("set-min")
list_parser.add_argument("port", help="Port number to minutes")

list_parser = material.add_parser("set-hour")
list_parser.add_argument("port", help="Port number to set hours")

list_parser = material.add_parser("set-sec")
list_parser.add_argument("port", help="Port number to remove from list of ports to monitor")

list_parser = material.add_parser("set-ban-type")
list_parser.add_argument("port", help="Port number to set ban type")

def check_for_commands():
    try:
        args = reader.parse_args()
    except SystemExit:
        console = Console()
        console.print("Invalid command. Use 'pp --help' for a list of available commands.", style="red")
        return

    console = Console()
    
    if args.cmd == "settings":
        settings = SC.Settings_Check_Configure()
        table = Table(title="=== Port Protector Settings ===")

        table.add_column("Setting", style="green", no_wrap=True)
        table.add_column("Value", style="white")

        for key, value in settings.items():
            if key == "Warn User Amount":
               continue
            table.add_row(key, str(value))

        console.print(table)

    elif args.cmd == "unban":
        try:
            if SC.Settings_Check_Configure()["Ban_Type"] == "perm":
                subprocess.run(["ufw", "delete", "deny", "from", args.ip], check=True)
                BB.log_ban_attempt(args.ip, None, "manual_unban_perm", None, None)
                removed = SC.Remove_Banned_IP(args.ip)
                print(f"Successfully unbanned IP address {args.ip}")

            elif SC.Settings_Check_Configure()["Ban_Type"] == "temp":

                subprocess.run(["ufw", "delete", "deny", "from", args.ip], check=True)
                removed = SC.Remove_Banned_IP(args.ip)
                for entry in BB.BANNED_IPS[:]: 
                    if entry[0] == args.ip:
                        entry[1] = "MANUAL"
                        BB.log_ban_attempt(args.ip, None, "manual_unban_temp", None, None)
                        break
                print(f"Successfully unbanned IP address {args.ip}")

        except subprocess.CalledProcessError:
            console.print(f"Failed to unban IP address {args.ip} it may not exist or there was an error with ufw", style="red")

    elif args.cmd == "remove":
        try:
            subprocess.run(["ufw", "delete", "allow", "from", args.ip], check=True)
            removed = SC.Remove_Whitelist(args.ip)
            if removed:
                print(f"Successfully removed IP address {args.ip} from whitelist and UFW rules")
            else:
                console.print(f"IP address {args.ip} was not in the whitelist", style="yellow")
        except subprocess.CalledProcessError:
            console.print(f"Failed to remove IP address {args.ip} from UFW rules", style="red")

    elif args.cmd == "ban":
        try:
            settings = SC.Settings_Check_Configure()
            if settings["Ban_Type"] == "perm":
                subprocess.run(["ufw", "insert", "1", "deny", "from", args.ip], check=True)
                SC.Add_Banned_IP(args.ip)
                print(f"Successfully permanently banned IP address {args.ip}")

            elif settings["Ban_Type"] == "temp":
                BB.temp_ban(args.ip, SC.Settings_Check_Configure()["Temp_Ban_Duration"])
                SC.Add_Banned_IP(args.ip)
                print(f"Successfully temporarily banned IP address {args.ip} for {SC.Settings_Check_Configure()['Temp_Ban_Duration']} seconds")
                
        except subprocess.CalledProcessError:
            console.print(f"Failed to ban IP address {args.ip}, The IP address may not exist or there is an error with ufw", style="red")

    elif args.cmd == "show-banned":
        results = SC.Settings_Check_Configure()["Banned IPs"]
        if not results:
            console.print("No IP addresses are currently banned.", style="green")
            return
        else: 
            table = Table(title="=== Currently Banned IP Addresses ===")
            table.add_column("IP Address", style="red", no_wrap=True)
            for ip in results:
                table.add_row(ip)
            console.print(table)

    elif args.cmd == "add":
        try:
            subprocess.run(["ufw", "insert", "1", "allow", "from", args.ip], check=True)
            added = SC.add_Whitelist(args.ip)
            if added:
                print(f"Successfully added IP address {args.ip} to whitelist and UFW rules")
            else:
                console.print(f"IP address {args.ip} is already in the whitelist", style="yellow")
        except subprocess.CalledProcessError:
            console.print(f"Failed to add IP address {args.ip} to UFW rules", style="red")

    elif args.cmd == 'unlock':
        try:
            subprocess.run(["ufw", "delete", "deny", f"{args.port}/tcp"], check=True)
            unlocked = SC.Remove_Locked_Port(args.port)
            if unlocked:
                print(f"Successfully unlocked port {args.port}")
            else:
                console.print(f"Port {args.port} was not locked", style="yellow")
        except subprocess.CalledProcessError:
            console.print(f"Failed to unlock port {args.port}, there may be an error with UFW", style="red")

    elif args.cmd == "lock":
        try:
            subprocess.run(["ufw", "insert", "1", "deny", f"{args.port}/tcp"], check=True)
            SC.Add_Locked_Port(args.port)
            print(f"Successfully locked port {args.port}")
        except subprocess.CalledProcessError:
            console.print(f"Failed to lock port {args.port}, there may be an error with UFW", style="red")

    elif args.cmd == "list-add":
        try:
            data = args.port
            settings = SC.Settings_Check_Configure()
            settings["Path to Port Logs"].append(data)
            pkg_dir = os.path.dirname(__file__)
            data_file = os.path.join(pkg_dir, "Data.json")
            with open(data_file, "w") as file_data:
                json.dump(settings, file_data, indent=4)
            print(f"Successfully added log path --> {data} <-- to the list of ports to monitor")
        except Exception as e:
            console.print(f"Failed to add log path {data} to the list of ports to monitor, error: {str(e)}", style="red")

    elif args.cmd == "list-remove":
        try:
            data = args.port
            settings = SC.Settings_Check_Configure()
            if data in settings["Path to Port Logs"]:
                settings["Path to Port Logs"].remove(data)
                pkg_dir = os.path.dirname(__file__)
                data_file = os.path.join(pkg_dir, "Data.json")
                with open(data_file, "w") as file_data:
                    json.dump(settings, file_data, indent=4)
                print(f"Successfully removed log path --> {data} <-- from the list of ports to monitor")
            else:
                console.print(f"Log path {data} is not in the list of ports to monitor", style="yellow")
        except Exception as e:
            console.print(f"Failed to remove log path {data} from the list of ports to monitor, error: {str(e)}", style="red")
           
    elif args.cmd == "add-port":
        try:
            data = args.port
            settings = SC.Settings_Check_Configure()
            if data not in settings["Port Types"]:
                settings["Port Types"].append(data)
                pkg_dir = os.path.dirname(__file__)
                data_file = os.path.join(pkg_dir, "Data.json")
                with open(data_file, "w") as file_data:
                    json.dump(settings, file_data, indent=4)
                print(f"Successfully added port --> {data} <-- to the list of ports to monitor")
            else:
                console.print(f"Port {data} is already in the list of ports to monitor", style="yellow")
        except Exception as e:
            console.print(f"Failed to add port {data} to the list of ports to monitor, error: {str(e)}", style="red")

    elif args.cmd == "remove-port":
        try:
            data = args.port
            settings = SC.Settings_Check_Configure()
            if data in settings["Port Types"]:
                settings["Port Types"].remove(data)
                pkg_dir = os.path.dirname(__file__)
                data_file = os.path.join(pkg_dir, "Data.json")
                with open(data_file, "w") as file_data:
                    json.dump(settings, file_data, indent=4)
                print(f"Successfully removed port --> {data} <-- from the list of ports to monitor")
            else:
                console.print(f"Port {data} is not in the list of ports to monitor", style="yellow")
        except Exception as e:
            console.print(f"Failed to remove port {data} from the list of ports to monitor, error: {str(e)}", style="red")

    elif args.cmd == "set-min":
        try:
            data = int(args.port)
            settings = SC.Settings_Check_Configure()
            time_limit = settings["Temp_Ban_Duration"]
            time_limit[1] = data
            pkg_dir = os.path.dirname(__file__)
            data_file = os.path.join(pkg_dir, "Data.json")
            with open(data_file, "w") as file_data:
                json.dump(settings, file_data, indent=4)
            print(f"Successfully set temporary ban duration minutes to --> {data} <--")
        except Exception as e:
            console.print(f"Failed to set temporary ban duration minutes, error: {str(e)}", style="red")

    elif args.cmd == "set-hour":
        try:
            data = int(args.port)
            settings = SC.Settings_Check_Configure()
            time_limit = settings["Temp_Ban_Duration"]
            time_limit[0] = data
            pkg_dir = os.path.dirname(__file__)
            data_file = os.path.join(pkg_dir, "Data.json")
            with open(data_file, "w") as file_data:
                json.dump(settings, file_data, indent=4)
            print(f"Successfully set temporary ban duration hours to --> {data} <--")
        except Exception as e:
            console.print(f"Failed to set temporary ban duration hours, error: {str(e)}", style="red")

    elif args.cmd == "set-sec":
        try:
            data = int(args.port)
            settings = SC.Settings_Check_Configure()
            time_limit = settings["Temp_Ban_Duration"]
            time_limit[2] = data
            pkg_dir = os.path.dirname(__file__)
            data_file = os.path.join(pkg_dir, "Data.json")
            with open(data_file, "w") as file_data:
                json.dump(settings, file_data, indent=4)
            print(f"Successfully set temporary ban duration seconds to --> {data} <--")
        except Exception as e:
            console.print(f"Failed to set temporary ban duration seconds, error: {str(e)}", style="red")

    elif args.cmd == "set-ban-type":
        try:
            data = args.port.lower()
            settings = SC.Settings_Check_Configure()
            settings["Ban_Type"] = data
            pkg_dir = os.path.dirname(__file__)
            data_file = os.path.join(pkg_dir, "Data.json")
            with open(data_file, "w") as file_data:
                json.dump(settings, file_data, indent=4)
            print(f"Successfully set ban type to --> {data} <--")
        except Exception as e:
            console.print(f"Failed to set ban type, error: {str(e)}", style="red")

    elif args.cmd == "start":

        if os.geteuid() != 0:
            console.print("Port Protector must be run as root. Use: sudo pp start", style="red")
            sys.exit(1)

        if SC.Settings_Check_Configure()["Status"] == "inactive":
            try:
                SC.Any_Small_Checks()
                SC.enable_whitelisting()
                SC.Warn_User(SC.Settings_Check_Configure())
                subprocess.Popen([sys.executable, "-m", "Main"], cwd=os.path.dirname(__file__))

            except Exception as e:
                console.print(f"Failed to start Port Protector: {str(e)}", style="red")
        else:
            console.print("Port Protector is already running.", style="yellow")

    elif args.cmd == "stop":
        finding = subprocess.run([ "pgrep", "-f", "Main.py" ], capture_output=True)
        print(finding.returncode)
        if finding.returncode == 1:
            try:
                print("Stopping Port Protector...")
            
                pkg_dir = os.path.dirname(__file__)
                data_file = os.path.join(pkg_dir, "Data.json")
                with open (data_file, "r") as file_data:
                    data = json.load(file_data)

                with open (data_file, "w") as file_data:
                    data["Status"] = "inactive"
                    json.dump(data, file_data, indent=4)

                time.sleep(1)
                subprocess.run(["pkill", "-f", "Main.py"], check=False)
                print("Port Protector has been stopped.")
            except subprocess.CalledProcessError:
                console.print("Failed to stop Port Protector, it may not be running.", style="red")
        else:
            console.print("Port Protector is not running.", style="yellow")

    elif args.cmd == "show-logs":

        pkg_dir = os.path.dirname(__file__)
        data_file = os.path.join(pkg_dir, "Foreign_IP_ATTEMPTS.log")
        if os.path.exists(data_file):
            with open(data_file, "r") as log_file:
                logs = log_file.read()
                console.print(logs)
        else:
            console.print("Log file couldnt be found", style="yellow")

if __name__ == "__main__":
    check_for_commands()