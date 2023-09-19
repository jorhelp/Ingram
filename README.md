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

简体中文 | [English](https://github.com/jorhelp/Ingram/blob/master/README.en.md)

## 简介

主要针对网络摄像头的漏洞扫描框架，目前已集成海康、大华、宇视、dlink等常见设备

<div align=center>
    <img alt="run" src="https://github.com/jorhelp/imgs/blob/master/Ingram/run_time.gif">
</div>


## 安装

**请在 Linux 或 Mac 系统使用，确保安装了3.8及以上版本的Python，尽量不要使用3.11，因为对许多包的兼容不是很好**

+ 克隆该仓库:
```bash
git clone https://github.com/jorhelp/Ingram.git
```

+ 进入项目目录，创建一个虚拟环境，并激活该环境：
```bash
cd Ingram
pip3 install virtualenv
python3 -m virtualenv venv
source venv/bin/activate
```

+ 安装依赖:
```bash
pip3 install -r requirements.txt
```

至此安装完毕！


## 运行

+ 由于是在虚拟环境中配置，所以，每次运行之前，请先激活虚拟环境：`source venv/bin/activate`

+ 你需要准备一个目标文件，比如 targets.txt，里面保存着你要扫描的 IP 地址，每行一个目标，具体格式如下：
```
# 你可以使用井号(#)来进行注释

# 单个的 IP 地址
192.168.0.1

# IP 地址以及要扫描的端口
192.168.0.2:80

# 带 '/' 的IP段
192.168.0.0/16

# 带 '-' 的IP段
192.168.0.0-192.168.255.255
```

+ 有了目标文件之后就可直接运行:
```bash
python3 run_ingram.py -i 你要扫描的文件 -o 输出文件夹
```

+ 端口：
如果target.txt文件中指定了目标的端口，比如: 192.168.6.6:8000，那么会扫描该目标的8000端口 

否则的话，默认只扫描常见端口(定义在 `Ingram/config.py` 中)，若要批量扫描其他端口，需自行指定，例如：
```bash
python3 run_ingram.py -i 你要扫描的文件 -o 输出文件夹 -p 80 81 8000
```

+ 默认并发数目为 300，可以根据机器配置及网速通过 `-t` 参数来自行调控：
```bash
python3 run_ingram.py -i 你要扫描的文件 -o 输出文件夹 -t 500
```

+ 支持中断恢复，不过并不会实时记录当前运行状态，而是间隔一定时间，所以并不能准确恢复到上次的运行状态。如果扫描因为网络或异常而中断，可以通过重复执行上次的扫描命令来继续扫描

+ 所有参数：
```
optional arguments:
  -h, --help            show this help message and exit
  -i IN_FILE, --in_file IN_FILE
                        the targets will be scan
  -o OUT_DIR, --out_dir OUT_DIR
                        the dir where results will be saved
  -p PORTS [PORTS ...], --ports PORTS [PORTS ...]
                        the port(s) to detect
  -t TH_NUM, --th_num TH_NUM
                        the processes num
  -T TIMEOUT, --timeout TIMEOUT
                        requests timeout
  -D, --disable_snapshot
                        disable snapshot
  --debug
```


## 端口扫描器

+ 我们可以利用强大的端口扫描器来获取活动主机，进而缩小 Ingram 的扫描范围，提高运行速度，具体做法是将端口扫描器的结果文件整理成 `ip:port` 的格式，并作为 Ingram 的输入

+ 这里以 masscan 为例简单演示一下（masscan 的详细用法这里不再赘述），首先用 masscan 扫描 80 或 8000-8008 端口存活的主机：`masscan -p80,8000-8008 -iL 目标文件 -oL 结果文件 --rate 8000`

+ masscan 运行完之后，将结果文件整理一下：`grep 'open' 结果文件 | awk '{printf"%s:%s\n", $4, $3}' > targets.txt`

+ 之后对这些主机进行扫描：`python run_ingram.py -i targets.txt -o out`


## ~~微信提醒~~(已移除)

+ (**可选**) 扫描时间可能会很长，如果你想让程序扫描结束的时候通过微信发送一条提醒的话，你需要按照 [wxpusher](https://wxpusher.zjiecode.com/docs/) 的指示来获取你的专属 *UID* 和 *APP_TOKEN*，并将其写入 `run_ingram.py`:
```python
# wechat
config.set_val('WXUID', '这里写uid')
config.set_val('WXTOKEN', '这里写token')
```


## 结果

```bash
.
├── not_vulnerable.csv
├── results.csv
├── snapshots
└── log.txt
```

+ `results.csv` 里保存了完整的结果, 格式为: `ip,端口,设备类型,用户名,密码,漏洞条目`:  

<div align=center>
    <img alt="Ingram" src="https://github.com/jorhelp/imgs/blob/master/Ingram/results.png">
</div>

+ `not_vulnerable.csv` 中保存的是没有暴露的设备

+ `snapshots` 中保存了部分设备的快照:  

<div align=center>
    <img alt="Ingram" src="https://github.com/jorhelp/imgs/blob/master/Ingram/snapshots.png">
</div>


## ~~实时预览~~ (由于部分原因已移除)

+ ~~可以直接通过浏览器登录来预览~~
  
+ ~~如果想批量查看，我们提供了一个脚本 `show/show_rtsp/show_all.py`，不过它还有一些问题:~~

<div align=center>
    <img alt="Ingram" src="https://github.com/jorhelp/imgs/blob/master/Ingram/show_rtsp.png">
</div>


## 免责声明

本工具仅供安全测试，严禁用于非法用途，后果与本团队无关


## 鸣谢 & 引用

Thanks to [Aiminsun](https://github.com/Aiminsun/CVE-2021-36260) for CVE-2021-36260  
Thanks to [chrisjd20](https://github.com/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor) for hidvision config file decryptor  
Thanks to [mcw0](https://github.com/mcw0/DahuaConsole) for DahuaConsole
