import json
from json.decoder import JSONDecodeError
from pwn import *
"""Just to keep out error warnings in PyCharm"""
global p8, p16, p32, p64, u8, u16, u32, u64

# Colours
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
BLUE = '\033[34m'
WHITE = '\033[37m'

LRED = '\033[91m'
LGREEN = '\033[92m'
LYELLOW = '\033[93m'
LBLUE = '\033[94m'
LWHITE = '\033[97m'

EventInServerPort = 43210		# UDP listener port, receiving events
EventOutServerPort = 43211		# TCP listener port, delivery of events


def color(dtext, dcolor):
	return "{}{}\033[0m".format(dcolor, dtext)


def fix_json(mess):
	"""
	JSON data we will receive from events is an mess, need to sort out that before loading JSON to a list
	input: unsorted JSON
	return: sorted JSON in a list
	"""
	dh_data = []
	start = 0
	result = ''

	for check in range(0, len(mess)):
		if mess[check] == '{':
			result += mess[check]
			start += 1
		elif start:
			result += mess[check]
			if mess[check] == '}':
				start -= 1
		if not start:
			try:
				if len(result):
					dh_data.append(json.loads(result))
			except JSONDecodeError:
				pass
			result = ''
	if start:
		log.warning('fix_json: not complete')
	return dh_data


def help_msg(dh_data):
	""" print help function """
	return '\033[92m[\033[91m{}\033[92m]\033[0m\n'.format(dh_data)


def help_all(msg, usage):
	"""
	Examples:

	usage = {
		"key0":"(value 0)",
		"key1":"(value 1)",
		"key2":"(value 2)",
		"key3":"(value 3)"
	}

	usage = {
		"key0":"(value 0)",
		"key1":{
			"subkey0":"(value 0)",
			"subkey1":"(value 1)"
		},
		"key2":"(value 2)",
		"key3":"(value 3)"
	}

	usage = {
		"key0":{
			"subkey0":"(value 0)",
			"subkey1":"(value 1)",
			"subkey2":"(value 2)"
		},
		"key1":{
			"subkey0":"(value 0)",
			"subkey1":"(value 1)"
		}
	}

	One same line for all usage()
	log.info('{}'.format(help_all(msg=msg,usage=usage)))
	return True
	"""

	if msg.find('-h'):
		msg = msg.strip('-h')
	cmd = msg.split()

	try:
		dh_data = '{}'.format(help_msg('usage'))

		for key in usage if not len(cmd) > 1 else usage.get(cmd[1]) if isinstance(usage.get(cmd[1]), dict) else {cmd[1]}:

			if isinstance(usage.get(key), dict):
				for subkey in usage.get(key):
					dh_data += '{} {} {} {}\n'.format(cmd[0], key, subkey, usage.get(key).get(subkey, '(1 Not defined)'))

			elif isinstance(usage.get(key) if not len(cmd) > 1 else key, str):
				dh_data += '{} {} {}\n'.format(
					cmd[0],
					'{} {}'.format(cmd[1], key) if len(cmd) > 1 else key,
					usage.get(
						key, '(Not defined: {})'.format(key)
						) if len(cmd) == 1 else usage.get(
						cmd[1]).get(key, '(Not defined: {})'.format(key))
					)
			else:
				print('[else]')
				print(type(key), key)

		return dh_data
	except AttributeError as e:
		print('[help_all]', repr(e))


def check_ip(ip_addr):
	""" Check if IP is valid """
	try:
		ip = ip_addr.split('.')
		if len(ip) != 4:
			return False
		for tmp in ip:
			if not tmp.isdigit():
				return False
			i = int(tmp)
			if i < 0 or i > 255:
				return False
		return True
	except ValueError:
		return False


def check_port(port):
	""" Check if PORT is valid """
	try:
		if not isinstance(port, int):
			port = int(port)
		if int(port) < 1 or int(port) > 65535:
			return False
		else:
			return True
	except ValueError:
		return False


def check_host(addr):
	""" Check if HOST is valid """
	try:
		""" Will generate exception if we try with FQDN or invalid IP """
		socket.inet_aton(addr)
		return addr
	except socket.error:
		""" Else check valid FQDN, and return the IP """
		try:
			return socket.gethostbyname(addr)
		except socket.error:
			return False


def binary_ip(host, endian="big"):
	""" Modified pwntools function from 'misc.py'

	big: 127.0.0.1 => b'\\x7f\\x00\\x00\\x01'

	little: 127.0.0.1 => b'\\x01\\x00\\x00\\x7f'
	"""
	try:
		""" Swap endianness if desired """
		return p32(u32(socket.inet_aton(socket.gethostbyname(host)), endian="big" if endian == "little" else "little"))
	except (Exception, KeyboardInterrupt, SystemExit) as e:
		return repr(e)


def unbinary_ip(host, endian="big"):
	"""
	big: b'\\x7f\\x00\\x00\\x01' => 127.0.0.1

	little: b'\\x01\\x00\\x00\\x7f' => 127.0.0.1
	"""
	try:
		# Swap endianness if desired
		host = p32(u32(host, endian="big" if endian == "little" else "little"))
		return '.'.join(str(x) for x in [u8(host[i:i+1]) for i in range(0, len(host), 1)])
	except (Exception, KeyboardInterrupt, SystemExit) as e:
		return repr(e)
