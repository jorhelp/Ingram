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


<div align=center>
    <img alt="Ingram" src="https://github.com/jorhelp/Ingram/blob/master/statics/imgs/logo.png">
</div>


<!-- icons -->
<div align=center>
    <img alt="GitHub" src="https://img.shields.io/github/license/jorhelp/Ingram">
    <img alt="GitHub issues" src="https://img.shields.io/github/issues/jorhelp/Ingram">
    <img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/jorhelp/Ingram">
    <img alt="GitHub last commit (branch)" src="https://img.shields.io/github/last-commit/jorhelp/Ingram/master">
</div>


English | [简体中文](https://github.com/jorhelp/Ingram/blob/master/README_CN.md)


## Introduction

![](statics/imgs/run_time.gif)

Schools, hospitals, shopping malls, restaurants, and other places where equipment is not well maintained, there will always be vulnerabilities, either because they are not patched in time or because weak passwords are used to save trouble.

This tool can use multiple threads to batch detect whether there are vulnerabilities in the cameras on the local or public network, so as to repair them in time and improve device security.

**Only successfully tested on Mac and Linux, but not on Windows!**


## Installation

+ Clone this repository by:
```bash
git clone https://github.com/jorhelp/Ingram.git
```

+ **Make sure the Python version you use is >= 3.7**, and install packages by:
```bash
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
  --nosnap             do not capture snapshot
  --masscan            run massscan sanner
  --port PORT          same as masscan port
  --rate RATE          same as masscan rate
```

+ Scan with all modules (**TARGET** is your ip file, **OUT_DIR** is the path where results will be saved):
```bash
# th_num number of threads needs to be adjusted by yourself to state of your network
./run_ingram.py --in TARGET --out OUT_DIR --all --th_num 80

# If you use wechat, then the --send_msg should be provided:
./run_ingram.py --in TARGET --out OUT_DIR --all --th_num 80 --send_msg
```

+ Snapshots (Snapshoting is supported by default, but you can disable it with --nosnap if you think it's too slow)
```bash
./run_ingram.py --in TARGET --out OUT_DIR --all --th_num 80 --nosnap
```

+ There are some *IP FILE* in `statics/iplist/data/` that you can use, for example:
```bash
./run_ingram.py --in statics/iplist/data/country/JP.txt --out OUT_DIR --all --th_num 80
```

+ All modules can be combined arbitrarily to scan, for example, if you want to scan Hikvision, then:
```bash
./run_ingram.py --in TARGET --out OUT_DIR --hik_weak --cve_2017_7921 --cve_2021_36260 --th_num 80
```

+ Direct scanning can be slow. You can use the Masscan to speed up. The Masscan needs to be installed in advance. For example, we find hosts whose port 80 and 8000 to 8008 opened and scan them:
```shell
./run_ingram.py --in TARGET --out OUT_DIR --masscan --port 80,8000-8008 --rate 5000
./run_ingram.py --in OUT_DIR/masscan_res --out OUT_DIR --all --th_num 80
```

+ If your program breaks due to network or other reasons, you can continue the previous process by simply running the command that ran last time. For example, the last command you executed was `./run_ingram.py --in ip.txt --out output --all --th_num 80`, to resume, simply continue `./run_ingram.py --in ip.txt --out output --all --th_num 80`, also for the masscan.


## Results

```bash
.
├── not_vulnerable.csv
├── results_all.csv
├── results_simple.csv
└── snapshots
```

+ The comprehensive results are saved in the `OUT_DIR/results_all.csv` file, and each line is `ip,port,user,passwd,device,vulnerability`:   
![](statics/imgs/results.png)

+ The `OUT_DIR/results_simple.csv` file contains only the target with the password, in the format of `IP,port,user,passwd`

+ `OUT_DIR/not_vulnerable.csv` file is stored in the target without vulnerability exposure

+ Some camera's snapshots can be found in `OUT_DIR/snapshots/`:  
![](statics/imgs/snapshots.png)


## The Live

+ You can log in directly from the browser to see the live screen.
  
+ If you want to view the live screen in batch, we provided a script: `show/show_rtsp/show_all.py`, though it has some flaws:
```shell
python3 -Bu show/show_rtsp/show_all.py OUT_DIR/results_all.csv
```

![](statics/imgs/show_rtsp.png)


## Change Logs

+ [2022-06-11] **Optimized running speed; Supportted storage of the not vulnerable targets**

+ [2022-06-11] **Resume supported!!!**


## Disclaimer

This tool is only for learning and safety testing, do not fucking use it for illegal purpose, all legal consequences caused by this tool will be borne by the user!!!


## Acknowledgements & References

Thanks to [Aiminsun](https://github.com/Aiminsun/CVE-2021-36260) for CVE-2021-36260  
Thanks to [chrisjd20](https://github.com/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor) for hidvision config file decryptor  
Thanks to [metowolf](https://github.com/metowolf/iplist) for ip list  
