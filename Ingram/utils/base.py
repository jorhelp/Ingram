import os
import signal
import platform
import subprocess


def os_check() -> str:
    """check the operate system"""
    _os = platform.system().lower()
    if _os == 'windows': return 'windows'
    elif _os == 'linux': return 'linux'
    elif _os == 'darwin': return 'mac'
    else: return 'other'


def singleton(cls, *args, **kwargs):
    """singleton decorator"""
    instance = {}
    def wrapper(*args, **kwargs):
        if cls not in instance:
            instance[cls] = cls(*args, **kwargs)
        return instance[cls]
    return wrapper

 
def run_cmd(cmd_string, timeout=60):
    p = subprocess.Popen(cmd_string, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True, close_fds=True,
                         start_new_session=True)
 
    if os_check() == 'windows': format = 'gbk'
    else: format = 'utf-8'
 
    try:
        (msg, errs) = p.communicate(timeout=timeout)
        ret_code = p.poll()
        if ret_code:
            code = 1
            msg = "[Error]Called Error: " + str(msg.decode(format))
        else:
            code = 0
            msg = str(msg.decode(format))
    except subprocess.TimeoutExpired:
        # 注意：不能只使用p.kill和p.terminate，无法杀干净所有的子进程，需要使用os.killpg
        p.kill()
        p.terminate()
        os.killpg(p.pid, signal.SIGTERM)
 
        # 注意：如果开启下面这两行的话，会等到执行完成才报超时错误，但是可以输出执行结果
        (outs, errs) = p.communicate()
        code = 0
        msg = str(outs.decode(format))
 
        # code = 1
        # msg = "[ERROR]Timeout Error: Command '" + cmd_string + "' timed out after " + str(timeout) + " seconds"
    except Exception as e:
        code = 1
        msg = "[ERROR]Unknown Error : " + str(e)
 
    return code, msg