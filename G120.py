#!/usr/bin/env python
import uuid
import threading
from collections import OrderedDict as od
from scapy.all import *
import time
import struct
import profinet
import subprocess
import shared_mem as shm
from isu.utils.logconfig import configure_logging
import defines as df
from profinet import (
    DCERPC, ProfinetGetParametersRequest, ProfinetSetParametersRequest,
    ProfinetConnectionResponse, ProfinetParameter, CreateEPMRequest,
    CreateProfinetConnectionRequest, CreateProfinetWriteRequest,
    CreateProfinetReadRequest, CheckEPMResponse, CheckProfinetWriteResponse,
    CheckProfinetReadResponse, GetProfinetParametersValue,
    ProfinetParametersValues, ProfinetParameterValue, ProfinetTelegram,
    GetAnnotation, GetObjectUUID, GetInterfaceUUID, GetPort)


class SinamicsG120():
    src_port = 12345
    dst_port = 34964
    DEFAULT_PASSWORD = 52190

    def __init__(self):
        self.cw = 0x047e
        self.rpm = 0
        self.annotation = 0
        self.ObjectUUID = ""
        self.InterfaceUUID = ""
        self.find_device = False
        self.connected = False
        self.request_id = 0
        self.dcerpc_id = 0
        self.pnio_id = -1
        self.ip_id = 1

        self.dst_mac_address = None
        self.src_ip_address = None

        self.dst_ip_address = df.VFD_IP
        self.src_mac_address = self.get_src_mac_address()
        self.get_dst_mac_address(self.dst_ip_address)
        # self.vfd_shm = shm.SharedMemory()

    @staticmethod
    def get_src_mac_address():
        interface = df.DEFAULT_ETHERNET
        rl.debug("Ethernet interface types on device = %s", get_if_list())

        for i in get_if_list():
            if i == interface:
                conf.iface = i
                rl.debug("Selected ethernet interface type = %s", i)
                return get_if_hwaddr(i)

        rl.debug("Error %s interface not found", interface)

    def get_dst_mac_address(self, ip_address):
        res, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=1)
        if res:
            self.dst_mac_address = res[0][1].src
            rl.debug("Dst MAC address = %s", self.dst_mac_address)
            self.src_ip_address = res[0][1].pdst
            rl.debug("Src IP address = %s", self.src_ip_address)
            self.find_device = True

    def increment_id(self):
        self.dcerpc_id += 1
        if self.dcerpc_id > 0xFFFFFFFF:
            self.dcerpc_id = 0
        self.pnio_id += 1
        if self.pnio_id > 0xFFFF:
            self.pnio_id = 0

    def check_packet(self, packet):
        if packet:
            if UDP in packet:
                if packet['IP'].src == self.dst_ip_address and packet['IP'].dst == self.src_ip_address:
                    if packet['UDP'].sport == self.dst_port and packet['UDP'].dport == self.src_port:
                        return True
                    else:
                        rl.error("Incorrect reply ip address is no equal")
                else:
                    rl.error("IP addresse in packet invalid! Packet['IP'].src = %s\tPacket['IP'].dst = %s", packet['IP'].src, packet['IP'].dst)
            else:
                rl.error("Incorrect reply is not UDP packet")
        else:
            rl.error("Packet is empty")
        return False

    def create_packet(self, packet):
        self.ip_id += 1
        if self.ip_id > 0xffff:
            self.ip_id = 0
        ethernet = Ether(dst=self.dst_mac_address,
                         src=self.src_mac_address,
                         type=0x0800)
        ip = IP(version=4L,
                ihl=5L,
                ttl=128,
                id=self.ip_id,
                flags=0x00,
                proto=0x11,
                src=self.src_ip_address,
                dst=self.dst_ip_address)
        udp = UDP(sport=self.src_port, dport=self.dst_port)
        self.increment_id()
        return ethernet/ip/udp/packet

    def get_configuration(self):
        rl.debug("Get configuration")
        epm = CreateEPMRequest()
        pkt = self.create_packet(epm)
        reply = srp1(pkt, timeout=2)
        if self.check_packet(reply):
            epm_reply = CheckEPMResponse(reply.load)
            if epm_reply:
                epm = CreateEPMRequest(epm_reply.Handle)
                pkt = self.create_packet(epm)
                reply = srp1(pkt, timeout=2)
                if self.check_packet(reply):
                    epm_reply = CheckEPMResponse(reply.load)
                    if epm_reply:
                        self.annotation = GetAnnotation(epm_reply)
                        rl.debug(self.annotation)
                        self.dst_port = GetPort(epm_reply)
                        rl.debug("Dst port = %s", self.dst_port)

                        self.ObjectUUID = GetObjectUUID(epm_reply)
                        if self.ObjectUUID:
                            profinet.OBJECT_UUID = self.ObjectUUID
                        rl.debug("ObjectUUID = %s", uuid.UUID(bytes_le=self.ObjectUUID))

                        self.InterfaceUUID = GetInterfaceUUID(epm_reply)
                        if self.InterfaceUUID:
                            profinet.INTERFACE__UUID = self.InterfaceUUID
                        rl.debug("InterfaceUUID = %s", uuid.UUID(bytes_le=self.InterfaceUUID))

                        profinet.AR_UUID = uuid.uuid4().bytes
                        profinet.SESSION_UUID = uuid.uuid1().bytes_le

                        return True
        return False

    def acyclic_access(self, pkt):
        data = None
        res = False
        reply = srp1(pkt, timeout=2)
        if self.check_packet(reply) and CheckProfinetWriteResponse(reply.load):
            self.request_id += 1
            pkt = self.create_packet(CreateProfinetReadRequest(self.dcerpc_id, self.pnio_id, 564, 64))  # TODO: define constants instead of 564 and 64
            reply = srp1(pkt, timeout=2)
            if self.check_packet(reply):
                res, data = CheckProfinetReadResponse(reply.load)
                res = True
        self.connected = res
        return res, data

    def restart_network_iface(self):
        subprocess.call("ifdown %s && ifup %s" % (conf.iface, conf.iface), shell=True)
        time.sleep(5)

    def connect(self):
        self.restart_network_iface()
        self.get_configuration()

        rl.debug("Connect to G120")
        if not self.find_device:
            self.get_dst_mac_address(self.dst_ip_address)
            return False

        self.request_id = 0
        self.dcerpc_id = 0
        self.pnio_id = -1
        self.ip_id = 1

        pnio_connect = CreateProfinetConnectionRequest()
        pkt = self.create_packet(pnio_connect)
        reply = srp1(pkt, timeout=1)                # TODO: define timeout
        if not self.check_packet(reply):
            return False

        dcerpc = DCERPC(reply.load)
        if not (dcerpc.PacketType == 2 and dcerpc.OperationNumber == 0):
            return False
        pnio = ProfinetConnectionResponse(dcerpc.load)
        if pnio.Status != 0:
            return False
        self.connected = True

        if not self.set_access_level(df.VFD_SERVICE_LEVEL):
            return False
        self.set_password(self.DEFAULT_PASSWORD)
        for i in xrange(3):
            self.get_errors()
        #self.set_watchdog(50000)
        self.set_watchdog(0)
        self.set_priority(1)
        self.send_telegram()
        self.set_priority(2)
        self.set_password(0)
        self.set_access_level(df.VFD_EXPERT_LEVEL)
        #self.telegraming()

    def get_status(self):
        data = ProfinetGetParametersRequest(Reference=self.request_id,
                                            Parameters=[
                                                ProfinetParameter(Indices=1, ID=2120, Index=0),
                                                ProfinetParameter(Indices=1, ID=2)
                                            ])
        pkt = self.create_packet(CreateProfinetWriteRequest(self.dcerpc_id, self.pnio_id, data))
        self.acyclic_access(pkt)

    def get_errors(self):
        data = ProfinetGetParametersRequest(Reference=self.request_id,
                                            Parameters=[ProfinetParameter(Indices=1, ID=2120, Index=0)])
        pkt = self.create_packet(CreateProfinetWriteRequest(self.dcerpc_id, self.pnio_id, data))
        self.acyclic_access(pkt)

    def set_priority(self, priority):
        parameters = ProfinetSetParametersRequest(Reference=self.request_id,
                                                  Parameters=[ProfinetParameter(Indices=1, ID=3980, Index=0)])
        value = ProfinetParametersValues(Values=[ProfinetParameterValue(
            Format=3,
            NumIndex=1,
            Value=struct.pack(">H", priority))])
        pkt = self.create_packet(CreateProfinetWriteRequest(self.dcerpc_id, self.pnio_id, parameters/value))
        self.acyclic_access(pkt)

    def flash_errors(self):
        rl.debug("Flash ERROR = %s", self.request_id)
        parameters = ProfinetSetParametersRequest(Reference=self.request_id,
                                                  Parameters=[ProfinetParameter(Indices=1, ID=3981, Index=0)])
        value = ProfinetParametersValues(Values=[ProfinetParameterValue(
            Format=0x41,
            NumIndex=1,
            Value=struct.pack("<H", 1))]
        )

        pkt = self.create_packet(CreateProfinetWriteRequest(self.dcerpc_id, self.pnio_id, parameters/value))
        res, data = self.acyclic_access(pkt)
        rl.debug("res = %s\tdata = %s", res, data)
        return res

    def set_password(self, password):
        parameters = ProfinetSetParametersRequest(Reference=self.request_id,
                                                  Parameters=[ProfinetParameter(Indices=1, ID=3950, Index=0)])
        value = ProfinetParametersValues(Values=[ProfinetParameterValue(Format=66, NumIndex=1, Value=struct.pack(">H", password))])
        pkt = self.create_packet(CreateProfinetWriteRequest(self.dcerpc_id, self.pnio_id, parameters/value))
        res, data = self.acyclic_access(pkt)

    def set_access_level(self, level):
        parameters = ProfinetSetParametersRequest(Reference=self.request_id,
                                                  Parameters=[ProfinetParameter(Indices=1, ID=3, Index=0)])
        value = ProfinetParametersValues(Values=[ProfinetParameterValue(Format=3, NumIndex=1, Value=struct.pack(">H", level))])
        pkt = self.create_packet(CreateProfinetWriteRequest(self.dcerpc_id, self.pnio_id, parameters/value))
        res, data = self.acyclic_access(pkt)
        return res

    def set_watchdog(self, timeout):
        parameters = ProfinetSetParametersRequest(Reference=self.request_id,
                                                  Parameters=[ProfinetParameter(Indices=1, ID=3984, Index=0)])  # TODO: define constant
        value = ProfinetParametersValues(Values=[ProfinetParameterValue(Format=67, NumIndex=1, Value=struct.pack(">I", timeout))])
        pkt = self.create_packet(CreateProfinetWriteRequest(self.dcerpc_id, self.pnio_id, parameters/value))
        res, data = self.acyclic_access(pkt)
        return res

    def send_telegram(self, cw=0, rpm=0):
        if cw:
            self.cw = cw
        if rpm:
            self.rpm = rpm

        telegram = ProfinetTelegram(CW=self.cw, RPM=self.rpm)
        print telegram

        rl.debug("cw = %s, rpm = %s", hex(self.cw), self.rpm)

        pkt = self.create_packet(CreateProfinetWriteRequest(self.dcerpc_id, self.pnio_id, telegram, 0x0065)) # TODO: define constant
        reply = srp1(pkt, timeout=1)
        if not self.check_packet(reply) or not CheckProfinetWriteResponse(reply.load):
            self.connected = False

    def telegraming(self):
        threading.Timer(5.0, self.telegraming).start()
        self.send_telegram()

    def flash_error(self):
        self.cw = 0x04FE

    def start(self):
        self.cw = 0x047F

    def stop(self):
        self.cw = 0x047E

    @staticmethod
    def convert_percentage_to_rpn(percentage):
        return int((percentage * 16384) / 100)

    def set_rpn(self, percentage):
        self.rpm = self.convert_percentage_to_rpn(percentage) # rpn
        self.start()

    @staticmethod
    def set_values_to_dict(data):
        return od(zip(df.vfd_keys, data))

    def set_parameters(self, parameter, type_format, struct_format, value):
        rl.debug("set parameters  = %s", parameter)
        parameters = ProfinetSetParametersRequest(Reference=self.request_id,
                                                  Parameters=[ProfinetParameter(Indices=1, ID=parameter, Index=0)])
        value = ProfinetParametersValues(Values=[ProfinetParameterValue(
            Format=type_format,
            NumIndex=1,
            Value=struct.pack(struct_format, value))]
        )

        pkt = self.create_packet(CreateProfinetWriteRequest(self.dcerpc_id, self.pnio_id, parameters/value))
        res, data = self.acyclic_access(pkt)
        rl.debug("res = %s\tdata = %s", res, data)
        return res

    def set_max_rpm(self, max_rpm_value):
        self.set_parameters(10, 0x03, ">h", 1)
        self.set_parameters(1082, 0x08, "!f", max_rpm_value)
        self.set_parameters(3900, 0x03, ">h", 1)

    def get_state(self):
        if not self.connected:
            self.connect()
        if self.connected:
            self.request_id += 1
            if self.request_id > 255:
                self.request_id = 1

            data = ProfinetGetParametersRequest(Reference=self.request_id,
                                                Parameters=[
                                                    ProfinetParameter(ID=2089, Index=0),
                                                    ProfinetParameter(ID=63),
                                                    ProfinetParameter(ID=82, Index=2),
                                                    ProfinetParameter(ID=1073),
                                                    ProfinetParameter(ID=66),
                                                    ProfinetParameter(ID=72),
                                                    ProfinetParameter(ID=70),
                                                    ProfinetParameter(ID=68, Index=1),
                                                    ProfinetParameter(ID=80, Index=1),
                                                    ProfinetParameter(ID=722),
                                                    ProfinetParameter(ID=87),
                                                    ProfinetParameter(ID=2131),
                                                    ProfinetParameter(ID=2132),
                                                    ProfinetParameter(ID=39, Index=0),
                                                    ProfinetParameter(ID=39, Index=1),
                                                    ProfinetParameter(ID=39, Index=2),
                                                    ProfinetParameter(ID=2000),
                                                    ProfinetParameter(ID=1082),
                                                ])

            pkt = self.create_packet(CreateProfinetWriteRequest(self.dcerpc_id, self. pnio_id, data))
            reply = srp1(pkt, timeout=2)
            if self.check_packet(reply) and CheckProfinetWriteResponse(reply.load):
                pkt = self.create_packet(CreateProfinetReadRequest(self.dcerpc_id, self. pnio_id, 564, 64))
                reply = srp1(pkt, timeout=2)
                if self.check_packet(reply):
                    res, data = CheckProfinetReadResponse(reply.load)
                    if res and data:
                        vfd_values = self.set_values_to_dict(GetProfinetParametersValue(data))
                        # self.vfd_shm.vfd_state(vfd_values)
                        rl.debug("Parameters value = %s", vfd_values)

                        return vfd_values
                else:
                    self.connected = False
            else:
                self.connected = False

        rl.debug("self.connected = %s", self.connected)
        return None

if __name__ == '__main__':
    rl = configure_logging(df.LOG_FILE_NAME)
    g120 = SinamicsG120("192.168.1.240")
    g120.get_configuration()
    g120.connect()

    while True:
        time.sleep(20)
        g120.set_rpn(8000)
        time.sleep(30)
        g120.set_rpn(0x4000)
        time.sleep(30)
        g120.stop()
else:
    import logging
    rl = logging.getLogger()
