#!/usr/bin/python3

from itertools import cycle
from Crypto.Cipher import AES
import re
import os
import sys

def add_to_16(s):
    while len(s) % 16 != 0:
        s += b'\0'
    return s 

def decrypt(ciphertext, hex_key='279977f62f6cfd2d91cd75b889ce0c9a'):
    key = bytes.fromhex(hex_key)
    ciphertext = add_to_16(ciphertext)
    #iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

def xore(data, key=bytearray([0x73, 0x8B, 0x55, 0x44])):
    return bytes(a ^ b for a, b in zip(data, cycle(key)))

def strings(file):
    chars = r"A-Za-z0-9/\-:.,_$%'()[\]<> "
    shortestReturnChar = 2
    regExp = '[%s]{%d,}' % (chars, shortestReturnChar)
    pattern = re.compile(regExp)
    return pattern.findall(file)

def main():
    if len(sys.argv) <= 1 or not os.path.isfile(sys.argv[1]):
        return print(f'No valid config file provided to decrypt. For example:\n{sys.argv[0]} <configfile>')
    xor = xore( decrypt(open( sys.argv[1],'rb').read()) )
    result_list = strings(xor.decode('ISO-8859-1'))
    print(result_list)

if __name__ == '__main__':
    main()
