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

简体中文 | [English](https://github.com/jorhelp/Ingram/blob/master/README.en.md)

## 简介

主要针对网络摄像头的漏洞扫描框架，目前已集成海康、大华、宇视、dlink等常见设备

<div align=center>
    <img alt="run" src="https://github.com/jorhelp/imgs/blob/master/Ingram/run_time.gif">
</div>


## 安装

**Windows 仍有部分bug，Linux 与 Mac可以正常使用。请确保安装了3.7及以上版本的Python，推荐3.8**

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

+ 你需要准备一个目标文件，比如 target.txt，里面保存着你要扫描的 IP 地址，每行一个目标，具体格式如下：
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
python run_ingram.py -i 你要扫描的文件 -o 输出文件夹
```

+ 端口：
如果target.txt文件中指定了目标的端口，比如: 192.168.6.6:8000，那么会扫描该目标的8000端口 

否则的话，默认只扫描常见端口，若要批量扫描其他端口，需自行指定，例如：
```bash
python run_ingram.py -i 你要扫描的文件 -o 输出文件夹 -p 80 81 8000
```

+ 默认的并发数目可能对你的宽带来说 so easy 了， 你可以根据网络情况适当增大，比如在我测试机上将并发数目加到800依然运行良好，而且速度极快:
```bash
python run_ingram.py -i 你要扫描的文件 -o 输出文件夹 -t 800
```

+ 其他参数：
```
optional arguments:
  -h, --help            打印参数信息
  -i IN_FILE, --in_file IN_FILE
                        要扫描的文件
  -o OUT_DIR, --out_dir OUT_DIR
                        扫描结果输出路径
  -p PORT [PORT ...], --port PORT [PORT ...]
                        要扫描的端口，可以指定多个端口，比如 -p 80 81 82
  -t TH_NUM, --th_num TH_NUM
                        并发数目，视网络状况自行调整
  -T TIME_OUT, --time_out TIME_OUT
                        超时
  --debug               调试模式
```


## 端口扫描器

+ 我们可以利用强大的端口扫描器来获取活动主机，进而缩小 Ingram 的扫描范围，提高运行速度，具体做法是将端口扫描器的结果文件整理成 `ip:port` 的格式，并作为 Ingram 的输入

+ 这里以 masscan 为例简单演示一下（masscan 的详细用法这里不再赘述），首先用 masscan 扫描 80 或 8000-8008 端口存活的主机：`masscan -p80,8000-8008 -iL 目标文件 -oL 结果文件 --rate 8000`

+ masscan 运行完之后，将结果文件整理一下：`grep 'open' 结果文件 | awk '{printf"%s:%s\n", $4, $3} > targets'`

+ 之后对这些主机进行扫描：`python run_ingram.py -i targets -o out`


## 微信提醒(可有可无)

+ (**可选**) 扫描时间可能会很长，如果你想让程序扫描结束的时候通过微信发送一条提醒的话，你需要按照 [wxpusher](https://wxpusher.zjiecode.com/docs/) 的指示来获取你的专属 *UID* 和 *APP_TOKEN*，并将其写入 `run_ingram.py`:
```python
# wechat
config.set_val('WXUID', '这里写uid')
config.set_val('WXTOKEN', '这里写token')
```

+ 支持中断恢复，不过由于考虑到性能，并不会实时记录当前运行状态，而是间隔一定时间，所以并不能准确恢复到上次的运行状态。(这里做的比较粗糙，下个版本调整)


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


## 更新日志

+ [2022-06-11] **优化运行速度，支持存储非暴露设备，支持中断恢复**

+ [2022-07-23] **可以通过 CVE-2021-33044(Dahua) 来获取用户名与密码了！修改了摄像头快照逻辑(将rtsp替换为了http)，优化了运行速度**
    - **由于新版本加入了一些依赖包，需要重新配置环境!!!**

+ [2022-08-05] **增加了 CVE-2021-33045(Dahua NVR)，不过由于NVR设备的账号密码与真正的摄像头的账号密码可能不一致，所以快照功能并不总是有效**

+ [2022-08-06] **增加了 宇视 设备的密码暴露模块，暂不支持快照**

+ [2022-08-17] **比较大的一次更新，我们重构了所有代码 (需要重新配置环境)，具体如下：**
    - 重构了代码结构，便于以后集成更多漏洞，移除部分依赖包，减少了超参数
    - 将多线程替换为协程，速度较之前有明显提升
    - 解决了子进程无法自动关闭的bug
    - 去掉了对masscan的支持，因为新版本会自动探测端口，当然你还可以把masscan的结果ip提取出来作为Ingram的输入
    - 去掉了若干与设备相关的超参数，新版本会自动探测设备
    - 不再内置iplist，因为其太占空间且不便于维护，需要的可以自己去网上找
    - 解决了读取大文件内存爆炸的问题


## 免责声明

本工具仅供安全测试，严禁用于非法用途，后果与本团队无关


## 鸣谢 & 引用

Thanks to [Aiminsun](https://github.com/Aiminsun/CVE-2021-36260) for CVE-2021-36260  
Thanks to [chrisjd20](https://github.com/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor) for hidvision config file decryptor  
Thanks to [mcw0](https://github.com/mcw0/DahuaConsole) for DahuaConsole