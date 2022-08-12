"""logger"""
from loguru import logger


logger.remove(handler_id=None)  # do not print to terminal

def no_debug(record):
    """if debug is False, then filter error and debug msg"""
    return record['level'].name != 'ERROR' and record['level'].name != 'DEBUG'

_formatter = "[{time:YYYY-MM-DD HH:mm:ss}][{level}][{module}.{function}] {message}"
# if debug:
#     trace = logger.add('test.log', format=_formatter)
# else:
#     trace = logger.add('test.log', format=_formatter, filter=no_debug)
trace = logger.add('test.log', format=_formatter, filter=no_debug)