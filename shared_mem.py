import time
from datetime import datetime, timedelta, date
from isu import shmemcls
from isu.utils.logconfig import configure_logging
import defines as df
from isu.utils import defines as defines
from isu.utils import common as c
from isu.dynamometer.isu_alarms import AlarmsISU as alarm_shm


class SharedMemory():
    WORK_TIME_FILE = "/var/isu/work_time.txt"
    YESTERDAY_WORK_TIME_FILE = "/var/isu/yesterday_work_time.txt"

    def __init__(self, access=shmemcls.MEM_WRITE):
        self.vfd_shm = shmemcls.vfd_shm('/vfd', access)
        self.alarm_shmem = alarm_shm(shmemcls.MEM_READ)
        self.shm_work_time = 0
        self.beginning_work_time = 0
        self.beginning_down_time = 0
        self.work_time = self.read_work_time_from_file()
        self.down_time = 0
        self.next_date_timestamp = self.get_next_date_timestamp()
        self.yesterday_work_time = self.get_yesterday_work_time_from_file()

    def set_vfd_speed(self, speed):
        try:
            self.vfd_shm.lock()
            d = self.vfd_shm.data()
            d.current_speed = speed
        finally:
            self.vfd_shm.unlock()

    @staticmethod
    def vfd_mode(signal):
        mode = df.VFD_MANUAL_MODE & signal
        if mode:
            return 1
        return 0

    @staticmethod
    def get_next_date_timestamp():
        d = date.today() + timedelta(days=1)
        return int(time.mktime(d.timetuple()))

    def get_yesterday_work_time_from_file(self):
        work_time = 0
        try:
            with open(self.YESTERDAY_WORK_TIME_FILE, "r") as f:
                work_time = int(f.read())
        except IOError as e:
            rl.error("I/O error({0}): {1}".format(e.errno, e.strerror))

        return work_time

    def save_yesterday_work_time_to_file(self):
        if c.current_timestamp() >= self.next_date_timestamp:
            with open(self.YESTERDAY_WORK_TIME_FILE, "w") as f:
                f.write('%s' % self.work_time)

            self.yesterday_work_time = self.work_time
            self.next_date_timestamp = self.get_next_date_timestamp()

            self.beginning_work_time = 0
            self.work_time = 1
            self.save_work_time_to_file()

    def save_work_time_to_file(self):
        with open(self.WORK_TIME_FILE, "w") as f:
            f.write('%s' % self.work_time)

    def read_work_time_from_file(self):
        work_time = 0
        try:
            with open(self.WORK_TIME_FILE, "r") as f:
                work_time = int(f.read())
        except IOError as e:
            rl.error("I/O error({0}): {1}".format(e.errno, e.strerror))

        return work_time

    def calculate_work_time(self, rpm):
        if rpm > 0:
            if self.beginning_work_time == 0:
                self.beginning_work_time = c.current_timestamp()
                self.beginning_down_time = 0
                self.shm_work_time = self.read_work_time_from_file()

            self.work_time = (self.shm_work_time + c.current_timestamp() -
                              self.beginning_work_time)
            rl.debug("VFD working time = %s : %s",
                     self.work_time,
                     time.strftime("%H:%M:%S",
                                   time.localtime(self.work_time)))
        else:
            if self.beginning_down_time == 0:
                self.beginning_down_time = c.current_timestamp()
                self.beginning_work_time = 0

            self.down_time = c.current_timestamp() - self.beginning_down_time
            rl.debug("VFD downtime = %s : %s", self.down_time,
                     time.strftime("%H:%M:%S", time.gmtime(self.down_time)))

    @staticmethod
    def check_value(value):
        if int(round(value)) < 0:
            return 0

        return int(round(value))

    def set_parameters(self, dic):
        try:
            self.vfd_shm.lock()
            d = self.vfd_shm.data()
            d.current_max = dic['current']['max']
            d.current_min = dic['current']['min']
            d.current_avg = dic['current']['avg']
            d.voltage_max = dic['voltage']['max']
            d.voltage_min = dic['voltage']['min']
            d.voltage_avg = dic['voltage']['avg']
        finally:
            self.vfd_shm.unlock()

    def vfd_state(self, dic):
        try:
            self.vfd_shm.lock()
            d = self.vfd_shm.data()
            d.timestamp = c.current_timestamp()
            d.act_rpm = self.check_value(dic["act_rpm"])

            self.calculate_work_time(d.act_rpm)
            d.current_work_time = self.work_time
            self.save_work_time_to_file()

            self.save_yesterday_work_time_to_file()
            d.yesterday_work_time = self.yesterday_work_time

            d.active_power = float(dic["active_power"])
            d.target_speed = self.check_value(dic["target_speed"])
            d.fout = float(dic["fout"])
            d.vout = float(dic["vout"])
            d.vint = float(dic["vint"])
            d.act_cur = float(dic["act_cur"])
            d.act_mom = float(dic["act_mom"])
            d.discrete_signals = self.check_value(dic["discrete_signals"])
            d.vfd_working_mode = self.vfd_mode(d.discrete_signals)
            d.cos_phi = float(dic["cos_phi"])
            d.error_code = self.check_value(dic["error_code"])
            d.warning_code = self.check_value(dic["warning_code"])
            d.energy_sum = float(dic["energy_sum"])
            d.energy_expended = float(dic["energy_expended"])
            d.recuperation = float(dic["recuperation"])
            d.max_rpm = float(dic["max_rpm"])
            d.nominal_rpm = float(dic["nominal_rpm"])
        finally:
            self.vfd_shm.unlock()

    def get_state(self):
        """
        Get state information from shared memory
        :return: Dictionary object with all fields filled
        """

        if self.alarm_shmem.alarm_in_mem(defines.ALARM_VFD):
            return {}
        else:
            try:
                self.vfd_shm.lock()
                d = self.vfd_shm.data()
                return {
                    'timestamp': c.ts2dt(d.timestamp),
                    'act_rpm': d.act_rpm,
                    'current_work_time': d.current_work_time,
                    'yesterday_work_time': d.yesterday_work_time,
                    'active_power': d.active_power,
                    'target_speed': d.target_speed,
                    'fout': d.fout,
                    'vout': d.vout,
                    'vint': d.vint,
                    'act_cur': d.act_cur,
                    'act_mom': d.act_mom,
                    'discrete_signals': d.discrete_signals,
                    'vfd_working_mode': d.vfd_working_mode,
                    'cos_phi': d.cos_phi,
                    'error_code': d.error_code,
                    'warning_code': d.warning_code,
                    'energy_sum': d.energy_sum,
                    'energy_expended': d.energy_expended,
                    'recuperation': d.recuperation,
                    'max_rpm': d.max_rpm,
                    'nominal_rpm': d.nominal_rpm,
                    'current_max': d.current_max,
                    'current_min': d.current_min,
                    'current_avg': d.current_avg,
                    'voltage_max': d.voltage_max,
                    'voltage_min': d.voltage_min,
                    'voltage_avg': d.voltage_avg,
                }
            finally:
                self.vfd_shm.unlock()

    def get_max_rpm(self):
        try:
            self.vfd_shm.lock()
            d = self.vfd_shm.data()
            return d.max_rpm
        finally:
            self.vfd_shm.unlock()

    def get_rpm(self):
        try:
            self.vfd_shm.lock()
            d = self.vfd_shm.data()
            return d.act_rpm
        finally:
            self.vfd_shm.unlock()

    def is_alarm_stop(self):
        try:
            self.vfd_shm.lock()
            d = self.vfd_shm.data()
            mode = df.VFD_ALARM_STOP & d.discrete_signals
            if mode:
                return False
            return True
        finally:
            self.vfd_shm.unlock()

    def get_moment(self):
        try:
            self.vfd_shm.lock()
            d = self.vfd_shm.data()
            return d.act_mom
        finally:
            self.vfd_shm.unlock()

    def get_act_rpm(self):
        try:
            self.vfd_shm.lock()
            d = self.vfd_shm.data()
            return d.act_rpm
        finally:
            self.vfd_shm.unlock()

    def get_vfd_mode_and_speed(self):
        try:
            self.vfd_shm.lock()
            d = self.vfd_shm.data()
            return {
                'vfd_working_mode': d.vfd_working_mode,
                'current_speed': d.current_speed
            }
        finally:
            self.vfd_shm.unlock()


if __name__ == "__main__":
    rl = configure_logging(df.LOG_FILE_NAME)
else:
    import logging
    rl = logging.getLogger()
