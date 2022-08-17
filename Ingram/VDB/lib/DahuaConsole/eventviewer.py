#!/usr/bin/env python3
from utils import *


def main():
	""" Simple Event Viewer """
	events = None
	try:
		events = remote('127.0.0.1', EventOutServerPort, ssl=False, timeout=5)

		while True:
			event_data = ''

			while True:
				tmp = len(event_data)
				event_data += events.recv(numb=8192, timeout=1).decode('latin-1')
				if tmp == len(event_data):
					break

			if len(event_data):
				# fix the JSON mess
				event_data = fix_json(event_data)
				if not len(event_data):
					log.warning('[Simple Event Viewer]: callback data invalid!\n')
					return False

				for event in event_data:
					log.info('[Event From]: {}\n{}'.format(color(event.get('host'), GREEN), event))

	except (PwnlibException, EOFError, KeyboardInterrupt):
		log.warning("[Simple Event Viewer]")
		if events:
			events.close()
		return False


if __name__ == '__main__':
	main()
