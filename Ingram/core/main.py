"""coordinate various configurations and make decisions"""
import os
import sys
import asyncio
import aiohttp

from Ingram.utils import config
from Ingram.utils import logger
from Ingram.utils import color
from Ingram.middleware import check_device
from Ingram.module import get_module


async def test(iplist):
    loop = asyncio.get_event_loop()
    for i in iplist:
        res = await loop.run_in_executor(None, check_device, i)
        print(res)


def run():
    # input and output check
    if not os.path.isfile(config['IN']):
        print(color.red(f"the input file {config['IN']} does not exists!"))
        sys.exit()

    if not os.path.exists(config['OUT']):
        os.mkdir(config['OUT'])

    # test
    with open(config['IN'], 'r') as f:
        ip_list = [i.strip() for i in f if not i.startswith('#') and i.strip()]
    asyncio.run(test(ip_list))


    # ip = '14.48.152.197'  # hik-2021
    # ip = '175.204.191.112'  # hik-2017
    # ip = '220.135.27.32'  # uniview
    # ip = '211.74.178.193'  # dlink
    # ip = '122.116.18.69'  # 33044
    # ip = '60.248.25.31'  # 33045
    # ip = '111.70.17.205'  # dahua weak
    # device = check_device(ip)
    # mods = get_module(device)
    # if mods:
    #     for mod in mods:
    #         print(ip, device, mod(ip))