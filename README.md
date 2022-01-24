Go App Server to send WOL (Wake on LAN) packet on LAN.  
  
A simple interface to list, add and remove user (and send WOL packet) can be found at:  
http(s)://[adress]:[port]/listUsrToMac?key=[key]  
  
WOL with username (if in DB)  
http(s)://[adress]:[port]/sendWOLuser?user=[username]  
  
WOL with macadress  
http(s)://[adress]:[port]/sendWOL?mac=[macadress]  
  
Aadd user in DB  
http(s)://[adress]:[port]/addUsrToMac?user=[username]&mac=[macadress]&key=[key]  
  
Remove user from DB  
http(s)://[adress]:[port]/remUsrToMac?user=[username]&key=[key]  
  
List user in DB  
http(s)://[adress]:[port]/listUsrToMac?key=[key]  
  
[username] username in DB  
[macadress] MAC address of the target machine.  
[key] password see cofig.yaml  
[port] see config.yaml  
  
See config.yaml and adjust settings as need (https, etc)  
  
Thanks to https://github.com/linde12/gowol  
