"""端口扫描"""
import socket

from loguru import logger


def port_scan(ip: str, port: str, timeout: int=1) -> bool:
    """使用 socket 的方式"""
    s = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((ip, int(port))) == 0:
            return True
    except Exception as e:
        logger.error(e)
    finally:
        s.close()
    return False
