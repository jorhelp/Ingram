"""logger"""
from loguru import logger


def no_debug(record):
    """if debug is False, then filter error and debug msg"""
    return record['level'].name != 'ERROR' and record['level'].name != 'DEBUG'


def config_logger(log_file, debug=False):
    logger.remove(handler_id=None)  # do not print to terminal
    _format = "[{time:YYYY-MM-DD HH:mm:ss}][{level}][{module}.{function}] {message}"
    if debug: logger.add(log_file, format=_format, rotation='200 MB')
    else: logger.add(log_file, format=_format, filter=no_debug, rotation='200 MB')