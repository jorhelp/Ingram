<div align=center>
    <img alt="Ingram" src="https://github.com/jorhelp/imgs/blob/master/Ingram/logo.png">
</div>


<!-- icons -->
<div align=center>
    <img alt="Platform" src="https://img.shields.io/badge/platform-Linux%20|%20Mac-blue.svg">
    <img alt="Python Version" src="https://img.shields.io/badge/python-3.8-yellow.svg">
    <img alt="GitHub" src="https://img.shields.io/github/license/jorhelp/Ingram">
    <img alt="Github Checks" src="https://img.shields.io/github/checks-status/jorhelp/Ingram/master">
    <img alt="GitHub Last Commit (master)" src="https://img.shields.io/github/last-commit/jorhelp/Ingram/master">
    <img alt="Languages Count" src="https://img.shields.io/github/languages/count/jorhelp/Ingram?style=social">
</div>

English | [简体中文](https://github.com/jorhelp/Ingram/blob/master/README.md)

## Intro

This is a web camera device vulnerability scanning tool, which already supports Hikvision, Dahua and other devices

<div align=center>
    <img alt="run" src="https://github.com/jorhelp/imgs/blob/master/Ingram/run_time.gif">
</div>


## Installation

**Please run it under Linux or Mac. Please make sure you have installed Python >= 3.8, but 3.11 is not recommended.**

+ Firstly, clone this repo:
```bash
git clone https://github.com/jorhelp/Ingram.git
```

+ Then, go to the repo dir, create a virtual environment and activate it:
```bash
cd Ingram
pip3 install virtualenv
python3 -m virtualenv venv
source venv/bin/activate
```

+ After that, install dependencies:
```bash
pip3 install -r requirements.txt
```

So far, it has been installed!


## Run

+ Since it is configured in a virtual environment, pls activate the virtual environment before each running

+ You need to prepare an target file, let's name it `input`, which contains the targets that will be scanned. The content of `input` file can be:
```
# use '#' to comment

# single ip
192.168.0.1

# ip with a port
192.168.0.2:80

# ip segment ('/')
192.168.0.0/16

# ip segment ('-')
192.168.0.0-192.168.255.255
```

+ With the `input` file, let's start scanning:
```bash
python3 run_ingram.py -i input -o output
```

+ If you specified the port like: `x.x.x.x:80`, then the port 80 will be scanned, otherwise common ports will be scanned(defined in `Ingram/config.py`). And you can also override it with the `-p` argument such as:
```bash
python3 run_ingram.py -i input -o output -p 80 81 8000
```

+ The number of coroutines can be controlled by the `-t` argument:
```bash
python3 run_ingram.py -i input -o output -t 500
```

+ all arguments：
```
optional arguments:
  -h, --help            show this help message and exit
  -i IN_FILE, --in_file IN_FILE
                        the targets will be scan
  -o OUT_DIR, --out_dir OUT_DIR
                        the dir where results will be saved
  -p PORTS [PORTS ...], --ports PORTS [PORTS ...]
                        the port(s) to detect
  -u USERS [USERS ...], --users USERS [USERS ...]
                        username(s) for weak-password checks (overrides defaults)
  --passwords PASSWORDS [PASSWORDS ...]
                        password(s) for weak-password checks (overrides defaults)
  -U USERS_FILE, --users-file USERS_FILE
                        file with one username per line (# comments allowed)
  -P PASS_FILE, --pass-file PASS_FILE
                        file with one password per line (# comments allowed)
  -t TH_NUM, --th_num TH_NUM
                        the processes num
  -T TIMEOUT, --timeout TIMEOUT
                        requests timeout
  -D, --disable_snapshot
                        disable snapshot
  -f {csv,json,both}, --format {csv,json,both}
                        output format for results (default: csv)
  --poc POC [POC ...]   only run these POCs (by file name or product name)
  --exclude-poc EXCLUDE_POC [EXCLUDE_POC ...]
                        exclude these POCs (by file name or product name)
  -R RATE, --rate RATE  max new hosts scanned per second (0 = unlimited)
  --retries RETRIES     extra retries for HTTP fingerprint probes on network errors (default: 0)
  --retry-delay RETRY_DELAY
                        seconds to wait between retries (default: 0)
  --html-report         also write an HTML summary report (report.html) to the output dir
  --no-resume           do not resume from previous scan, start fresh
  --debug
```

+ You can customize the credentials used by the weak-password POCs, either inline or from files:
```bash
# inline
python3 run_ingram.py -i input -o output -u admin root --passwords admin 12345 ""
# from files (one entry per line, '#' comments allowed)
python3 run_ingram.py -i input -o output -U users.txt -P passwords.txt
```

+ You can select which POCs to run (handy to focus a scan or skip noisy ones), and emit machine-readable results:
```bash
# only Hikvision/Dahua POCs, results also written as NDJSON
python3 run_ingram.py -i input -o output --poc hikvision dahua -f both
# run everything except a specific POC
python3 run_ingram.py -i input -o output --exclude-poc dahua-weak-password
```

+ With `-f json` (or `both`) results are additionally written as one JSON object per line (NDJSON) to `results.json` / `not_vulnerable.json`, with named fields (`ip`, `port`, `product`, `user`, `password`, `poc`). This avoids the quoting issues of CSV and is easy to pipe into other tools.

+ You can throttle and add retries to a scan, to cope with flaky networks or reduce load on targets:
```bash
# start at most 20 new hosts/sec, retry failed HTTP fingerprint probes twice, 0.5s apart
python3 run_ingram.py -i input -o output --rate 20 --retries 2 --retry-delay 0.5
```

+ With `--html-report`, a self-contained `report.html` (inline styles, no external dependencies) is written to the output dir at the end of the scan. It contains a per-device summary, a FINDINGS section with severity and description, and a full results table — handy for offline viewing and sharing:
```bash
python3 run_ingram.py -i input -o output --html-report
```

+ Fingerprinting now falls back to https when http can't connect (many cameras are https-only) and remembers the working scheme, improving detection coverage without adding requests.


## Port scanner

+ We can use powerful port scanner to obtain active hosts, thereby reducing the scanning range of Ingram and improving the running speed. The specific method is to organize the result file of the port scanner into the format of `ip:port` and use it as the input file of Ingram

+ Here is a brief demonstration of masscan as an example (the detailed usage of masscan will not be repeated here).

+ First, use masscan to scan the surviving host on port 80 or 8000-8008 (you sure can change the port anything else if you want): `masscan -p80,8000-8008 -iL INPUT -oL OUTPUT --rate 8000`

+ After masscan is done, sort out the result file: `grep 'open' OUTPUT | awk '{printf"%s:%s\n", $4, $3}' > input`

+ Then: `python run_ingram.py -i input -o output`


## Output

```bash
.
├── not_vulnerable.csv
├── results.csv
├── snapshots
└── log.txt
```

+ `results.csv` contains the vulnerable devices: `ip,port,device-type,user,password,vul`: 

<div align=center>
    <img alt="Ingram" src="https://github.com/jorhelp/imgs/blob/master/Ingram/results.png">
</div>

+ `not_vulnerable.csv` contains the not vulnerable devices

+ `snapshots` contains some snapshots of a part of devices (not all device can have a snapshot!!!):  

<div align=center>
    <img alt="Ingram" src="https://github.com/jorhelp/imgs/blob/master/Ingram/snapshots.png">
</div>


## Warning

This tool is for security testing only, it is strictly prohibited to use it for illegal purposes, and the consequences have nothing to do with this team.


## Thanks & Reference

Thanks to [Aiminsun](https://github.com/Aiminsun/CVE-2021-36260) for CVE-2021-36260  
Thanks to [chrisjd20](https://github.com/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor) for hidvision config file decryptor  
Thanks to [mcw0](https://github.com/mcw0/DahuaConsole) for DahuaConsole
