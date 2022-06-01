```
                   ___           ___           ___           ___           ___     
       ___        /  /\         /  /\         /  /\         /  /\         /  /\    
      /__/\      /  /::|       /  /::\       /  /::\       /  /::\       /  /::|   
      \__\:\    /  /:|:|      /  /:/\:\     /  /:/\:\     /  /:/\:\     /  /:|:|   
      /  /::\  /  /:/|:|_    /  /:/  \:\   /  /::\ \:\   /  /::\ \:\   /  /:/|:|__ 
   __/  /:/\/ /__/:/ |:| /\ /__/:/ __ \:\ /__/:/\:\_\:\ /__/:/\:\_\:\ /__/:/_|::::\
  /__/\/:/    \__\/  |:|/:/ \  \:\/_/\ \/ \__\/ |::\/:/ \__\/  \:\/:/ \__\/  /~~/:/
  \  \::/         |  |:/:/   \  \:\ \:\      |  |:|::/       \__\::/        /  /:/ 
   \  \:\         |__|::/     \  \:\/:/      |  |:|\/        /  /:/        /  /:/  
    \__\/         /__/:/       \  \::/       |__|:|         /__/:/        /__/:/   
                  \__\/         \__\/         \__\|         \__\/         \__\/    
```

```
@Name: INGRAM
@Auth: Jorhelp<jorhelp@qq.com>
@Date: Wed Apr 20 00:17:30 HKT 2022
@Desc: Network camera vulnerability detection
```


## Introduction

Schools, hospitals, shopping malls, restaurants, and other places where equipment is not well maintained, there will always be vulnerabilities, either because they are not patched in time or because weak passwords are used to save trouble.

This tool can use multiple threads to batch detect whether there are vulnerabilities in the cameras on the local or public network, so as to repair them in time and improve device security.

**Only successfully tested on Mac and Linux, but not on Windows!**


## Installation

+ Clone this repository by:
```shell
git clone https://github.com/jorhelp/Ingram.git
```

+ **Make sure the Python version you use is >= 3.7**, and install packages by:
```shell
cd Ingram
pip install -r requirements.txt
```


## Preparation

+ You should prepare a target file, which contains the ip addresses will be scanned. The following formats are allowed:
```
# Use '#' to comment (must have a single line!!)
# Single ip
192.168.0.1
# Single ip with port
192.168.0.2:80
# IP segment with '/'
192.168.0.0/16
# IP segment with '-'
192.168.0.0-192.168.255.255
```

+ The `utils/config.py` file already specifies some usernames and passwords to support weak password scanning. You can expand or decrease it:
```python
# camera
USERS = ['admin']
PASSWORDS = ['admin', 'admin12345', 'asdf1234', '12345admin', '12345abc']
```

+ (**Optional**) If you use wechat app, and want to get a reminder on your phone. You need to follow [wxpusher](https://wxpusher.zjiecode.com/docs/) instructions to get your *UID* and *APP_TOKEN*, and write them to `utils/config.py`:
```python
# wechat
UIDS = ['This is your UID', 'This is another UID if you have', ...]
TOKEN = 'This is your APP_TOKEN'
```

+ (**Optional**) Email is not supported yet...


## Run

```shell
optional arguments:
  -h, --help           show this help message and exit
  --in_file IN_FILE    the targets will be scan
  --out_path OUT_PATH  the path where results saved
  --send_msg           send finished msg to you (by wechat or email)
  --all                scan all the modules of [hik_weak, dahua_weak, cve_...]
  --hik_weak
  --dahua_weak
  --cctv_weak
  --hb_weak
  --cve_2021_36260
  --cve_2021_33044
  --cve_2017_7921
  --cve_2020_25078
  --th_num TH_NUM      the processes num
  --masscan            run massscan sanner
  --port PORT          same as masscan port
  --rate RATE          same as masscan rate
```

+ Scan with all modules (**TARGET** is your ip file, **OUT_DIR** is the path where results will be saved):
```shell
./run_ingram.py --in TARGET --out OUT_DIR --all --th_num 80
# If you use wechat, then the --send_msg should be provided:
./run_ingram.py --in TARGET --out OUT_DIR --all --th_num 80 --send_msg
```

+ There are some *IP FILE* in `statics/iplist/data/` that you can use, for example:
```shell
./run_ingram.py --in statics/iplist/data/country/JP.txt --out OUT_DIR --all --th_num 80
```

+ All modules can be combined arbitrarily to scan, for example, if you want to scan Hikvision, then:
```shell
./run_ingram.py --in TARGET --out OUT_DIR --hik_weak --cve_2017_7921 --cve-2021_36260 --th_num 80
```

+ Direct scanning can be slow. You can use the Masscan to speed up. The Masscan needs to be installed in advance. For example, we find hosts whose port 80 and 8000 to 8008 opened and scan them:
```shell
./run_ingram.py --in TARGET --out OUT_DIR --masscan --port 80,8000-8008 --rate 5000
./run_ingram.py --in OUT_DIR/masscan_res --out OUT_DIR --all --th_num 80
```

+ Snapshot of running process: 
![](statics/imgs/run_time.png)


## Results

+ The results are saved in the `OUT_DIR/results.csv` file, and each line is `ip,port,user,passwd,device,vulnerability`:
![](statics/imgs/results.png)

+ Some camera's snapshots can be found in `OUT_DIR/snapshots/`:
![](statics/imgs/snapshots.png)


## The Live

+ You can log in directly from the browser to see the live screen.
  
+ If you want to view the live screen in batch, we provided a script: `show/show_rtsp/show_all.py`, though it has some flaws:
```shell
python3 -Bu show/show_rtsp/show_all.py OUT_DIR/results.csv
```

![](statics/imgs/show_rtsp.png)


## Disclaimer

This tool is only for learning and safety testing, do not fucking useing it for illegal purpose, all legal consequences caused by this tool will be borne by the user!!!


## Acknowledgements & References

Thanks to [Aiminsun](https://github.com/Aiminsun/CVE-2021-36260) for CVE-2021-36260  
Thanks to [chrisjd20](https://github.com/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor) for hidvision config file decryptor  
Thanks to [metowolf](https://github.com/metowolf/iplist) for ip list  
