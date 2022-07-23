"""configuration file"""

#----------------------------
# overall
#----------------------------
DEBUG = False
TIMEOUT = 2


#----------------------------
# file names
#----------------------------
MASSCAN_TMP = 'masscan_tmp'
MASSCAN_RESULTS = 'masscan_results'
PAUSE = 'paused'
RESULTS_ALL = 'results_all.csv'
RESULTS_SIMPLE = 'results_simple.csv'
RESULTS_FAILED = 'not_vulnerable.csv'


#----------------------------
# camera
#----------------------------
USERS = ['admin']
PASSWORDS = ['admin', 'admin12345', 'asdf1234', 'abc12345', '12345admin', '12345abc']


#----------------------------
# snapshot
#----------------------------
MAX_RETRIES = 2


#----------------------------
# wechat
#----------------------------
# please refer to https://wxpusher.zjiecode.com/docs/#/
UIDS = ['']
TOKEN = ''


#----------------------------
# email (not supported yet...)
#----------------------------