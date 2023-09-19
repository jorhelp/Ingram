"""日志相关"""
from loguru import logger


def no_debug(record):
    """若命令行参数 debug 设置为 False, 则不会打印 error 或 debug 级别的日志"""
    return record['level'].name != 'ERROR' and record['level'].name != 'DEBUG'


def config_logger(log_file, debug=False):
    """loguru 相关配置"""
    logger.remove(handler_id=None)  # do not print to terminal
    _format = "[{time:YYYY-MM-DD HH:mm:ss}][{level}][{module}.{function}] {message}"
    if debug: logger.add(log_file, format=_format, rotation='200 MB')
    else: logger.add(log_file, format=_format, filter=no_debug, rotation='200 MB')