"""scanners"""
from Ingram.utils import logger
from Ingram.utils import get_current_time
from Ingram.middleware import progress_bar
from Ingram.middleware import device_detect
from Ingram.middleware import port_detect
from Ingram.VDB import get_vul


class Scan:

    def __init__(self, data, port):
        super().__init__()
        self.data = data
        self.start_time = get_current_time()
        self.bar = progress_bar(data.total, self.start_time)

        if type(port) == list: self.port = port
        else: self.port = [port]

    def __call__(self, ip):
        if ':' in ip:
            ip, user_specific_port = ip.split(':')
            user_specific_port = [user_specific_port]
        else:
            user_specific_port = []

        record = []
        try:  # Prevent thread pool exceptions
            for port in self.port + user_specific_port:
                port = str(port)
                # port open detect
                vulnerable = False
                if port_detect(ip, port):
                    # device type detect
                    device = device_detect(ip, port)
                    if device != 'other':
                        # get vul mods
                        mods = get_vul(device)
                        for mod in mods:
                            res = mod(f"{ip}:{port}")
                            if res[0]:
                                vulnerable = True
                                msg = [ip, port, device] + res[1:]
                                with self.data.var_lock:
                                    self.data.msg_queue.put(msg)
                                    self.data.found += 1
                                with self.data.file_lock:
                                    self.data.vuls.writelines(','.join(msg[:6]) + '\n')
                                    self.data.vuls.flush()
                        if not vulnerable:
                            record.append((port, device))
            with self.data.var_lock:
                self.data.done += 1
                self.bar(self.data.done, self.data.found)
            with self.data.file_lock:
                for port, device in record:
                    self.data.not_vuls.writelines(','.join([ip, port, device]) + '\n')
                    self.data.not_vuls.flush()
            # log the running state
            logger.info(f"#@#{self.data.taskid}#@#{self.data.done}#@#running state")
        except Exception as e:
            logger.error(e)