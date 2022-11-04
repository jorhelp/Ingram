<div align=center>
    <img alt="Ingram" src="https://github.com/jorhelp/imgs/blob/master/Ingram/logo.png">
</div>


<!-- icons -->
<div align=center>
    <img alt="Platform" src="https://img.shields.io/badge/platform-Linux%20|%20Mac-blue.svg">
    <img alt="Python Version" src="https://img.shields.io/badge/python-3.7|3.8-yellow.svg">
    <img alt="GitHub" src="https://img.shields.io/github/license/jorhelp/Ingram">
    <img alt="Github Checks" src="https://img.shields.io/github/checks-status/jorhelp/Ingram/master">
    <img alt="GitHub Last Commit (master)" src="https://img.shields.io/github/last-commit/jorhelp/Ingram/master">
    <img alt="Languages Count" src="https://img.shields.io/github/languages/count/jorhelp/Ingram?style=social">
</div>


## Introduction

Mainly for the vulnerability scanning framework of network cameras, it has integrated common equipment such as Hikvision, Dahua, and Uniview. More camera devices and router devices will be added later.  
<div align=center>
    <img alt="run" src="https://github.com/jorhelp/imgs/blob/master/Ingram/run_time.gif">
</div>


## Install

**Windows still has some bugs, Linux and Mac can be used normally. Please make sure to install Python 3.7 and above, 3.8 is recommended**

+ clone the repository:
```bash
git clone https://github.com/avikowy/Ingram.git
```

+ Enter the project directory to install dependencies:
```bash
cd Ingram
pip3 install git+https://github.com/arthaud/python3-pwntools.git
pip3 install -r requirements.txt
```

So far the installation is complete!


## run

+ You need to prepare a target file, such as target.txt, which stores the IP addresses you want to scan, one target per line, the specific format is as follows:
```
# You can use the pound sign (#) to comment
# single IP address
192.168.0.1
# IP address and port to scan
192.168.0.2:80
# IP segment with '/'
192.168.0.0/16
# IP segment with '-'
192.168.0.0-192.168.255.255
```

+ run after:
```bash
python run_ingram.py -i files you want to scan -o output folder
```

+ port:
If the target port is specified in the target.txt file, for example: 192.168.6.6:8000, then the target port 8000 will be scanned

Otherwise, only common ports are scanned by default. If you want to scan other ports in batches, you need to specify them yourself, for example:
```bash
python run_ingram.py -i files you want to scan -o output folder -p 80 81 8000
```

+ The default number of concurrency may be so easy for your broadband, you can increase it appropriately according to the network conditions, for example, increasing the number of concurrency to 800 on my test machine still works well, and the speed is extremely fast:
```bash
python run_ingram.py -i files you want to scan -o output folder -t 800
```

+ other parameters:
```
optional arguments:
  -h, --help print parameter information
  -i IN_FILE, --in_file IN_FILE
                        file to scan
  -o OUT_DIR, --out_dir OUT_DIR
                        Scan result output path
  -p PORT [PORT ...], --port PORT [PORT ...]
                        The port to scan, you can specify multiple ports, such as -p 80 81 82
  -t TH_NUM, --th_num TH_NUM
                        The number of concurrent, adjusted according to the network conditions
  -T TIME_OUT, --time_out TIME_OUT
                        time out
  --debug debug mode
```

+ (**Optional**) The scan time may be very long, if you want to send a reminder via WeChat when the program scan is over, you need to follow [wxpusher](https://wxpusher.zjiecode.com/docs /) to get your own *UID* and *APP_TOKEN* and write them into `run_ingram.py`:
```python
#wechat
config.set_val('WXUID', 'write uid here')
config.set_val('WXTOKEN', 'write token here')
```

+ Support interruption recovery, but because the running status is recorded every 5 minutes, it cannot accurately restore to the last running status. (It's rough here, it will be adjusted in the next version)


## result

```bash
.
├── not_vulnerable.csv
├── results.csv
├── snapshots
└── log.txt
```

+ `results.csv` saves the complete results in the format: `ip,port,devicetype,username,password,vulnerability entry`:  

<div align=center>
    <img alt="Ingram" src="https://github.com/jorhelp/imgs/blob/master/Ingram/results.png">
</div>

+ `not_vulnerable.csv` stores unexposed devices

+ `snapshots` stores snapshots of some devices:  

<div align=center>
    <img alt="Ingram" src="https://github.com/jorhelp/imgs/blob/master/Ingram/snapshots.png">
</div>


## ~~Live Preview~~ (removed for some reasons)

+ ~~You can log in directly through the browser to preview~~
  
+ ~~If you want to view batches, we provide a script `show/show_rtsp/show_all.py`, but it still has some problems :~~

<div align=center>
    <img alt="Ingram" src="https://github.com/jorhelp/imgs/blob/master/Ingram/show_rtsp.png">
</div>


## Changelog

+ [2022-06-11] **Optimize running speed, support storage of non-exposed devices, support interrupt recovery**

+ [2022-07-23] **Username and password can be obtained through CVE-2021-33044(Dahua)! Modify the camera snapshot logic (replace rtsp with http), optimize the running speed**
    - **Because the new version has added some dependency packages, the environment needs to be reconfigured!!!**

+ [2022-08-05] **Added CVE-2021-33045 (Dahua NVR), but because the account password of the NVR device may not be the same as that of the real camera, the snapshot function does not always work**

+ [2022-08-06] **Added a password exposure module for Uniview devices, but snapshots are not currently supported**

+ [2022-08-17] **A relatively large update, we refactored all the code (need to reconfigure the environment), as follows:**
    - Refactored the code structure to facilitate the integration of more vulnerabilities in the future, removed some dependent packages, and reduced hyperparameters
    - Replaced multi-threading with coroutines, the speed is significantly improved than before
    - Solved the bug that the child process could not be closed automatically
    - Removed support for masscan, because the new version will automatically detect the port, of course, you can also extract the result ip of masscan as the input of Ingram
    - Removed several device-related hyperparameters, the new version will automatically detect the device
    - No built-in iplist, because it takes up too much space and is inconvenient to maintain, you can find it online yourself if you need it
    - Solved the problem of memory explosion when reading large files


## Disclaimer

This tool is for security testing only, and is strictly prohibited for illegal use, and the consequences have nothing to do with the team


## Acknowledgments & Quotes

Thanks to [Aiminsun](https://github.com/Aiminsun/CVE-2021-36260) for CVE-2021-36260  
Thanks to [chrisjd20](https://github.com/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor) for hidvision config file decryptor  
Thanks to [mcw0](https://github.com/mcw0/DahuaConsole) for DahuaConsole
