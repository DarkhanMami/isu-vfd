#!/usr/bin/env python
import ConfigParser
from isu import shmemcls
from isu.utils.logconfig import configure_logging
from isu.utils import common as c
from isu.utils import defines as defines
from isu.vfd.version import product_version
from isu.vfd import defines as df
from isu.vfd import G120 as sinamics
from isu.vfd.shared_mem import SharedMemory as vfd_shm
from isu.dynamometer.isu_alarms import AlarmsISU as alarm_shm
from isu.dynamometer.shared_mem import SharedMemory as diagnostic_shmem
from isu.utils.settings import SettingsFile
from isu.utils.ctrlc import GracefulInterruptHandler
from itertools import cycle
import time
from isu.coordinator.constants import VFD_PID
from isu.utils.pidfile import PidFile

VFD_AUTO_MODE = 0
VFD_MANUAL_MODE = 1
VFD_REMOTE_MODE = 2
VFD_READY_COMMAND = 0x047e


def set_manual_mode(g120):
    g120.set_access_level(df.VFD_SERVICE_LEVEL)
    g120.set_priority(0)
    g120.send_telegram(VFD_READY_COMMAND)
    g120.set_access_level(df.VFD_EXPERT_LEVEL)
    rl.debug("SET PRIORITY 0")
    g120.send_telegram(VFD_READY_COMMAND)


def set_auto_mode(g120):
    g120.set_access_level(df.VFD_SERVICE_LEVEL)
    g120.set_priority(1)
    rl.debug("SET PRIORITY 1")
    g120.send_telegram(VFD_READY_COMMAND)
    g120.set_priority(2)
    rl.debug("SET PRIORITY 2")
    g120.send_telegram(VFD_READY_COMMAND)
    g120.set_access_level(df.VFD_EXPERT_LEVEL)
    g120.send_telegram(VFD_READY_COMMAND)


def stop_vfd_auto_mode(g120):
    rl.debug("STOP VFD")
    g120.stop()

    while True:
        vfd_state = g120.get_state()
        if vfd_state:
            if vfd_state['act_rpm'] == 0:
                return
            g120.send_telegram()
            time.sleep(1)
        else:
            return


def set_alarm(alarm_shm, alarm_value=0, emergency_stop=False):
    alarm_shm.set_alarm({
        'timestamp': c.current_timestamp(),
        'isu_alarm_code': defines.ALARM_VFD,
        'value': alarm_value,
        'emergency_stop': emergency_stop,
    })

    return


def check_alarm_broken_belt(moment, alarm_shmem):
    rl.debug("CHECK ALARM BROKEN BELT")
    max_moment = max(moment)
    min_moment = min(moment)
    s = max_moment - min_moment
    rl.debug("Min moment = %s\tMax moment = %s\tdelta = %s", min_moment, max_moment, s)
    if (s > 0) and (s < 20):
        alarm_shmem.set_alarm({
            'timestamp': c.current_timestamp(),
            'isu_alarm_code': defines.ALARM_BROKEN_BELT,
            'value': 0,
            'emergency_stop': True
        })

    return


def check_max_rpm(vfd_shmem, g120):
    global NOMINAL_RPM
    max_rpm = vfd_shmem.get_max_rpm()
    if max_rpm > NOMINAL_RPM:
        g120.set_max_rpm(1000)


def find_max(array):
    return max(array)


def find_min(array):
    return min(array)


def find_avg(array):
    return sum(array)/len(array)


def set_parameters_to_shmem(vfd_shm, d, current, voltage):
    d['current']['max'] = find_max(current)
    d['voltage']['max'] = find_max(voltage)
    d['current']['min'] = find_min(current)
    d['voltage']['min'] = find_min(voltage)
    d['current']['avg'] = find_avg(current)
    d['voltage']['avg'] = find_avg(voltage)
    rl.debug('d array = %s', d)
    vfd_shm.set_parameters(d)


def read_delta_alarm_settings():
    settings = SettingsFile().read_settings()
    delta_alarm = 60

    try:
        return int(settings['alarm']['delta_alarm'])
    except KeyError:
        SettingsFile().append_to_settings_file('alarm', {
            'delta_alarm': delta_alarm
        })

    return delta_alarm


class VFDControl():
    BROKEN_BELT_MAX_CNT = 40
    LIST_CNT = 60
    DELTA_TIME = 300        # 5 minutes

    def __init__(self):
        self.DELTA_ALARM = read_delta_alarm_settings()
        self.vfd_shmem = vfd_shm(shmemcls.MEM_WRITE)
        self.alarm_shmem = alarm_shm(shmemcls.MEM_WRITE)
        self.diagnoctic_shmem = diagnostic_shmem(shmemcls.MEM_WRITE)
        self.g120 = sinamics.SinamicsG120()
        self.g120.restart_network_iface()
        self.conf = self.g120.get_configuration()
        if not self.conf:
            set_alarm(self.alarm_shmem)
        self.g120.connect()

        self.vfd_prev_mode = -1
        self.vfd_prev_speed = 0

        self.broken_belt_cnt = 0
        self.cnt = 0
        self.moment = []

        self.d = {'current': {'max': 0, 'min': 0, 'avg': 0},
                  'voltage': {'max': 0, 'min': 0, 'avg': 0}}

        self.current = []
        self.voltage = []
        self.emergency_stop = False
        self.alarm_start_time = 0
        self.alarm_start = False
        self.vfd_state = {}

    def get_vfd_state(self):
        rl.debug('VFD getting state')
        self.vfd_state = self.g120.get_state()
        rl.debug('VFD checking state')
        self.check_vfd_state()

    def set_alarm(self, error_code, emergency_stop=False):
        self.alarm_shmem.set_alarm({
            'timestamp': c.current_timestamp(),
            'isu_alarm_code': defines.ALARM_VFD,
            'value': error_code,
            'emergency_stop': emergency_stop,
        })

    def check_error_code(self):
        rl.debug("\n========== ERROR CODE FOUND ==========\n")

        if int(self.vfd_state['error_code']) == df.FAULT_OVER_CURRENT:
            self.error_code(self.vfd_state['error_code'], True)

        rl.debug("ERROR check = %s", self.vfd_state['error_code'])
        alarm_timestamp = self.alarm_shmem.is_vfd_error_code_in_mem(self.vfd_state['error_code'])
        current_timestamp = c.current_timestamp()
        delta_timestamp = current_timestamp - alarm_timestamp

        rl.debug("ERROR check! Curr timestamp = %s\talarm_timestamp = %s\t"
                 "delta = %s\tDELTA_TIME = %s",
                 current_timestamp, alarm_timestamp, delta_timestamp, self.DELTA_TIME)

        if delta_timestamp < self.DELTA_TIME:
            self.emergency_stop = True
            rl.debug("Second repeated alarm in %s seconds! STOP VFD!", self.DELTA_TIME)

        if not self.alarm_shmem.is_vfd_error_code_repeat_in_mem(self.vfd_state['error_code']):
            self.set_alarm(self.vfd_state['error_code'], self.emergency_stop)

        if not self.emergency_stop:
            self.g120.flash_errors()
            self.g120.send_telegram(VFD_READY_COMMAND)
            rl.debug("Timeout started, vfd will restart after 30 seconds")
            time.sleep(30)

        rl.debug("\n========== END ERROR ==========\n")
        return

    def check_vfd_state(self):
        if not self.vfd_state:
            self.vfd_prev_mode = -1
            self.vfd_prev_speed = 0
            if not self.alarm_start:
                self.alarm_start_time = c.current_timestamp()
                self.alarm_start = True

            if self.alarm_start:
                delta = c.current_timestamp() - self.alarm_start_time
                rl.debug('delta = %s', delta)
                if delta > self.DELTA_ALARM:
                    set_alarm(self.alarm_shmem)
        else:
            self.alarm_start = False
            self.alarm_shmem.remove_alarm(defines.ALARM_VFD)

            if self.vfd_state['act_rpm'] == 0:
                self.diagnoctic_shmem.cycles_per_min(0)

            rl.debug('cnt = %s', self.cnt)
            self.current.append(self.vfd_state["act_cur"])
            self.voltage.append(self.vfd_state["vout"])
            if self.cnt >= self.LIST_CNT:
                rl.debug('Current = %s', self.current)
                rl.debug('Voltage = %s', self.voltage)
                # set_parameters_to_shmem(self.vfd_shmem, self.d, self.current, self.voltage)
                self.voltage = []
                self.current = []
                self.cnt = 0
            self.cnt += 1

            self.moment.append(self.vfd_state["act_mom"])
            self.broken_belt_cnt += 1

            rl.debug("BROKEN_BELT_CNT = %s", self.broken_belt_cnt)
            if self.broken_belt_cnt >= self.BROKEN_BELT_MAX_CNT:
                check_alarm_broken_belt(self.moment, self.alarm_shmem)
                self.broken_belt_cnt = 0
                self.moment = []

            # if self.vfd_shmem.is_alarm_stop():
            #     self.g120.send_telegram(VFD_READY_COMMAND)
            #     self.vfd_prev_speed = 0

            # vfd_mode_speed = self.vfd_shmem.get_vfd_mode_and_speed()
            rl.debug("Shared memory vfd = %s", vfd_mode_speed)

            if self.vfd_state['error_code']:
                self.check_error_code()

            if vfd_mode_speed["vfd_working_mode"] == VFD_MANUAL_MODE:
                if self.vfd_prev_mode != VFD_MANUAL_MODE:
                    self.alarm_shmem.reset_alarm()
                    self.emergency_stop = False
                    stop_vfd_auto_mode(self.g120)
                    set_manual_mode(self.g120)

                self.vfd_prev_mode = VFD_MANUAL_MODE
                self.vfd_prev_speed = 0
            elif vfd_mode_speed["vfd_working_mode"] == VFD_AUTO_MODE:
                if self.vfd_prev_mode != VFD_AUTO_MODE:
                    set_auto_mode(self.g120)

                self.vfd_prev_mode = VFD_AUTO_MODE
                stop_vfd = self.alarm_shmem.get_alarm_vfd_state()
                rl.debug("STOP VFD BY ALARM = %s", stop_vfd)
                if stop_vfd:
                    stop_vfd_auto_mode(self.g120)
                    self.vfd_prev_speed = 0
                else:
                    if self.vfd_prev_speed != vfd_mode_speed["current_speed"]:
                        if vfd_mode_speed["current_speed"] == 0:
                            self.g120.stop()
                        else:
                            self.g120.set_rpn(vfd_mode_speed["current_speed"])
                        self.vfd_prev_speed = vfd_mode_speed["current_speed"]

                    self.g120.send_telegram()

            rl.debug("Current working mode = %s", self.vfd_prev_mode)


def get_iface_settings():
    try:
        config = ConfigParser.RawConfigParser()
        config.read(df.SETTINGS_FILE_NAME)
        df.DEFAULT_ETHERNET = config.get('ethernet', 'interface')
        df.VFD_IP = config.get('ethernet', 'vfd_ip')
    except IOError as e:
        rl.error("I/O error({0}): {1}".format(e.errno, e.strerror))
        pass


if __name__ == "__main__":
    rl = configure_logging(df.LOG_FILE_NAME)
    rl.info('Version = %s' % product_version())
    get_iface_settings()
    vfd = VFDControl()

    with GracefulInterruptHandler() as h, PidFile(VFD_PID) as p:
        for i in cycle(range(10)):
            time.sleep(0.1)
            if i == 0:
                rl.debug('Get VFD state')
                vfd.get_vfd_state()
            if h.interrupted:
                rl.debug('Got SIGINT. Stopping threads...')
                break
