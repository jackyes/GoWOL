# GoWOL  
  
## This is a WOL (Wake On LAN) server written in Go that allows you to wake up your devices remotely.  

## Configuration:  

Configuration
The server requires a configuration file in YAML format named config.yaml with the following parameters:
```  
ServerPort: the port on which the server will listen for incoming HTTP requests.
ServerPortTLS: the port on which the server will listen for incoming HTTPS requests.
CertPathCrt: the path to the server's SSL certificate in PEM format.
CertPathKey: the path to the server's SSL key in PEM format.
EnableTLS: whether to enable HTTPS.
DisableNoTLS: whether to disable HTTP.
Key: a secret key used to authenticate requests.
DisableWOLWithoutusername: whether to allow WOL requests without a username.
AllowOnlyWolWithKey: whether to allow only WOL requests with the specified secret key.
``` 

Once started, the server exposes the following endpoints:  

```/sendWOLuser?user=<username>&port=<port>&key=<key>``` :  
sends a WOL packet to the device with the MAC address associated with the specified username in the database. The port parameter is optional and defaults to 9. The key parameter is required if AllowOnlyWolWithKey is set to true.  
  
```/addUsrToMac?mac=<mac>&user=<user>&key=<key>``` :  
adds a new user-MAC address pair to the database. The key parameter is required.  
  
```/remUsrToMacWithId?id=<id>&key=<key>``` :  
removes the user-MAC address pair with the specified ID from the database. The key parameter is required.  
  
  
```/listUsrToMac?key=<key>``` :  
lists all the user-MAC address pairs in the database.  
  
## Docker  

It is possible to use an image on Docker Hub with the following command:

    docker run -p 8080:8080 --name gowol -v /home/user/config.yaml:/config.yaml jackyes/gowol 
    
`/home/user/config.yaml` is the path to your config.yaml file (copy and edit the one in this repository).  
change the default port 8080 accordingly with the one in config.yaml if you modify it.
  
### Build Docker image yourself  
It is possible to create a Docker container following these steps:  
Clone the repository  

    git clone https://github.com/jackyes/GoWOL.git  
    
Edit the config.yaml file  
  
    cd GoWOL
    nano config.yaml
  
Create the Docker container  
  
    docker build -t gowol .  
  
Run the container  
  
    docker run -p 8080:8080 gowol  
  
  

## Example
  
A simple interface to list, add and remove user (and send WOL packet) can be found at:  
http(s)://[adress]:[port]/listUsrToMac?key=[key]  
  
WOL with username (if in DB)  
```http(s)://[adress]:[port]/sendWOLuser?user=[username]```  
  
WOL with macadress  
```http(s)://[adress]:[port]/sendWOL?mac=[macadress]```  
  
Aadd user in DB  
```http(s)://[adress]:[port]/addUsrToMac?user=[username]&mac=[macadress]&key=[key]```  
  
Remove user from DB  
```http(s)://[adress]:[port]/remUsrToMac?user=[username]&key=[key]```  
  
List user in DB  
```http(s)://[adress]:[port]/listUsrToMac?key=[key]```  
  
[username] username in DB  
[macadress] MAC address of the target machine.  
[key] password see cofig.yaml  
[port] see config.yaml  
  
See config.yaml and adjust settings as need (https, etc)  
  
Thanks to https://github.com/linde12/gowol  
