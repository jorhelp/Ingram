"""the scanner that produce data"""
from Ingram.utils import logger
from Ingram.middleware import device_detect
from Ingram.middleware import port_detect
from Ingram.VDB import get_vul


class Scan:

    def __init__(self, data, workshop, port):
        super().__init__()
        self.data = data
        self.workshop = workshop

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
                                self.workshop.put(msg)
                                self.data.found_add()
                                self.data.vul_add(','.join(msg[:6]) + '\n')
                        if not vulnerable:
                            record.append((port, device))
            # done
            self.data.done_add()
            for port, device in record:
                self.data.not_vul_add(','.join([ip, port, device]) + '\n')
            self.data.record_running_state()
            
        except Exception as e:
            logger.error(e)