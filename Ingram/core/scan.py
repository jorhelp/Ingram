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
            ip, port = ip.split(':')
            ports = [port]
        else:
            ports = self.port

        record = []
        try:  # Prevent thread pool exceptions
            for port in ports:
                port = str(port)
                # port open detect
                vulnerable = False
                if port_detect(ip, port):
                    # device type detect
                    device = device_detect(ip, port)
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
                    if mods and not vulnerable:
                        record.append((port, device))
            
        except Exception as e:
            logger.error(e)

        # done
        self.data.done_add()
        for port, device in record:
            self.data.not_vul_add(','.join([ip, port, device]) + '\n')