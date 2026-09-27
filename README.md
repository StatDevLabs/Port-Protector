# Port-Protector

A python program that detects brute force attempts made on ports of the users choosing

This program includes logging of banned IP addresses that attempted to brute force ports, white listing, manual banning and unbanning, built in commands to change settings in port protector, and Port lockdown

DISCLAIMER: DO NOT USE THIS PROGRAM TO PROTECT REAL DATA, THIS IS JUST A FUN PROJECT I MADE AND PORT PROTECT IS VERY BUGGY, IF YOU DO USE THIS TO PROTECT REAL DATA I AM NOT RESPONSIBLE FOR ANY DAMAGES THAT MAY OCCUR

NOTE: there may be commands and code that may not contribute anything to the overall functionality of port protector. These will be removed in the next branch

Command Syntax:

pp ban [IP ADDRESS] --> this command will manually ban the IP address you enter

pp unban [IP ADDRESS] --> this command will manually unban the IP address you enter

pp settings --> this command will show you the data.json file variables

pp show-banned --> this command will show all the banned IP addresses

pp add [IP ADDRESS] --> this command will add the entered IP address to the whitelist allowing it to bypass port protector even if the port is on lockdown

pp remove [IP ADDRESS] --> this command will remove the entered IP address from whitelist

pp lock [PORT NUMBER] --> this will lock the port that is entered. This will not allow any IP address, except for the whitelisted IPs, to use that port.

pp unlock [PORT NUMBER] --> this will unlock the entered port

pp list-add [PATH TO PORT LOG LOCATION] --> this will tell port protector what port log path to monitor

pp list-remove [PATH TO PORT LOG LOCATION] --> this will make port protector not monitor that log file path anymore

pp set-sec [number in seconds <= 60] --> sets the seconds that temp ban will ban the IP address for

pp set-min [number in minutes <= 60] --> sets the minutes that temp ban will ban the IP address for

pp set-hour [number in hour <= 60] --> sets the hour that temp ban will ban the IP address for

pp set-ban-type [perm or temp] --> will set the ban type top permanent or temporary depending on what the user chooses

pp start --> will start port protector

pp stop --> will stop port protector

pp show-logs --> will show the IP address log data
