from collections import OrderedDict as od

DEBUG = True
LOG_FILE_NAME = "/var/log/isu/vfd.log"
VFD_IP = "192.168.1.240"
VFD_PORT = 50157
VFD_TIMEOUT = 1 #seconds
SETTINGS_FILE_NAME = "/var/isu/settings.ini"
DEFAULT_ETHERNET = "p1p1"
VFD_MANUAL_MODE = 4
VFD_ALARM_STOP = 8
vfd_keys = (
    'word_status',
    'act_rpm',
    'active_power',
    'target_speed',
    'fout',
    'vout',
    'vint',
    'act_cur',
    'act_mom',
    'discrete_signals',
    'cos_phi',
    'error_code',
    'warning_code',
    'energy_sum',
    'energy_expended',
    'recuperation',
    'nominal_rpm',
    'max_rpm',
)

VFD_SERVICE_LEVEL = 4
VFD_EXPERT_LEVEL = 3

FAULT_OVER_CURRENT = 30001
FAULT_OVER_VOLTAGE = 30002
