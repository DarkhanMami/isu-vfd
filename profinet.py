#!/usr/bin/env python

import uuid
from scapy.all import *
import time

STATION_NAME = "PLC"

DCERPC_REQUEST = 0x00
DCERPC_RESPONSE = 0x02

EMP_LOOKUP = 0x02

PNIO_READ = 0x02
PNIO_WRITE = 0x03


PNIO_INT8 = 0x02
PNIO_INT16 = 0x03
PNIO_INT32 = 0x04
PNIO_UINT8 = 0x05
PNIO_UINT16 = 0x06
PNIO_UINT32 = 0x07
PNIO_FLOAT = 0x08
PNIO_STRING = 0x10
PNIO_TIME = 0x13
PNIO_BYTE = 0x41
PNIO_WORD = 0x42
PNIO_DWORD = 0x43


OBJECT_UUID = uuid.UUID('{dea00000-6c97-11d1-8271-00000511002a}').bytes_le
INTERFACE_UUID = uuid.UUID('{dea00001-6c97-11d1-8271-00a02442df7d}').bytes_le
AR_UUID = uuid.uuid4().bytes
SESSION_UUID = uuid.uuid1().bytes_le


def ajust_len(length):
    if length < 4:
        return 4 - length

    return length % 4


class EPMObject(Packet):
    name = "EMPObject part of DCE/RPC Endpoint Mapper packet"
    fields_desc = [
        IntField("ReferentID", 0x01000000),
        StrFixedLenField("UUID", None, 16)
    ]


class EPMInteface(Packet):
    name = "EMPInteface part of DCE/RPC Endpoint Mapper packet"
    fields_desc = [
        IntField("ReferentID", 0x02000000),
        StrFixedLenField("UUID", None, 16),
        ShortField("VersionMajor", 0),
        ShortField("VersionMinor", 0)
    ]


class EPMRequest(Packet):
    name = "DCE/RPC Endpoint Mapper request packet"
    fields_desc = [
        IntField("InquiryType", 0),
        PacketField("Object", EPMObject(), EPMObject),
        PacketField("Interface", EPMInteface(), EPMInteface),
        IntField("Option", 0x01000000),
        StrFixedLenField("Handle", None, 20),
        IntField("MaxEntries", 0x01000000)
    ]


class EPMFloor(Packet):
    fields_desc = [
        LEShortField("LHSLangth", 0),
        StrLenField("Data", "", length_from=lambda pkt:pkt.LHSLangth),
        LEShortField("RHSLangth", 0),
        StrLenField("Data2", "", length_from=lambda pkt:pkt.RHSLangth),
    ]


class EPMResponseEntry(Packet):
    name = "DCE/RPC Endpoint Mapper response packet entry"
    fields_desc = [
        StrFixedLenField("ObjectUUID", None, 16),
        LEIntField("ID", 0),
        LEIntField("AnnotationOffset", 0),
        LEIntField("AnnotationLangth", 0),
        StrLenField("Annotation", "", length_from=lambda pkt:(pkt.AnnotationLangth + ajust_len(pkt.AnnotationLangth)) ),
        LEIntField("Langth1", 0),
        LEIntField("Langth2", 0),
        LEFieldLenField("NumFloors", None, count_of="Floors"),
        PacketListField("Floors", None, EPMFloor, count_from=lambda pkt: pkt.NumFloors)
    ]


class EPMResponseEntries(Packet):
    name = "DCE/RPC Endpoint Mapper response packet entrries"
    fields_desc = [
        LEIntField("MaxCount", 0),
        LEIntField("Offset", 0),
        FieldLenField("ActualCount", None, count_of="Entry", fmt="<I"),
        PacketListField("Entry", None, EPMResponseEntry, count_from=lambda pkt: pkt.ActualCount)
    ]


class EPMResponse(Packet):
    name = "DCE/RPC Endpoint Mapper response packet"
    fields_desc = [
        StrFixedLenField("Handle", None, 20),
        FieldLenField("NumEntries", None, count_of="Entries", fmt="<I"),
        PacketListField("Entries", None, EPMResponseEntries, count_from=lambda pkt: pkt.NumEntries)
    ]


class CMInitiator(Packet):
    name = "CMInitiator part of ARBlockRequest"
    fields_desc = [
        MACField("MacAdd", "00:00:00:00:00:00"),
        StrFixedLenField("ObjectUUID",uuid.UUID('{dea00000-6c97-11d1-8271-00000f01002a}').bytes, 16),
        IntField("Properties", 0x00000111),
        ShortField("TimeoutFactor", 110),
        ShortField("UDPRTPort", 0x0000),
        FieldLenField("StationNameLength", None, length_of="StationName"),
        StrLenField("StationName", "", length_from=lambda pkt:pkt.len)
    ]


class ARBlockRequest(Packet):
    name = "AARBlockRequest part of Profinet Connection Request"
    fields_desc = [
        ShortField("BlockType", 0x0101),
        ShortField("BlockLength", 0x0039),
        ByteField("VersionHigh", 1),
        ByteField("VersionLow", 0),
        ShortField("Type", 0x0006),
        StrFixedLenField("UUID",  AR_UUID, 16),
        ShortField("SessionKey", 0x0001),
        PacketField("CMInitiator", CMInitiator(StationName=STATION_NAME), CMInitiator)
    ]


class IODWriteResHeader(Packet):
    name = "IODWriteResHeader part of Profinet Write Response"
    fields_desc = [
        ShortField("BlockType", 0),
        ShortField("BlockLength", 0x003c),
        ByteField("VersionHigh", 1),
        ByteField("VersionLow", 0),
        ShortField("SeqNumber", 0),
        StrFixedLenField("ARUUID",  AR_UUID, 16),
        LEIntField("API", 0),
        ShortField("SlotNumber",    2),
        ShortField("SubslotNumber", 1),
        StrFixedLenField("Padding1", "\x00\x00", 2),
        LEShortField("Index", 0x2f00),
        LEIntField("RecordDataLength", 0),
        LEShortField("AdditionalValue1", 0),
        LEShortField("AdditionalValue2", 0),
        LEIntField("Status", 0),
        StrFixedLenField("Padding2", None, 16),
    ]


class IODReadResHeader(Packet):
    name = "IODReadResHeader part of Profinet Read Response"
    fields_desc = [
        ShortField("BlockType", 0),
        ShortField("BlockLength", 0x003c),
        ByteField("VersionHigh", 1),
        ByteField("VersionLow", 0),
        ShortField("SeqNumber", 0),
        StrFixedLenField("ARUUID",  AR_UUID, 16),
        LEIntField("API", 0),
        ShortField("SlotNumber",    2),
        ShortField("SubslotNumber", 1),
        StrFixedLenField("Padding1", "\x00\x00", 2),
        LEShortField("Index", 0x2f00),
        IntField("RecordDataLength", 0),
        LEShortField("AdditionalValue1", 0),
        LEShortField("AdditionalValue2", 0),
        StrFixedLenField("Padding2", None, 20),
        StrLenField("Data", None, length_from=lambda pkt:pkt.RecordDataLength)
    ]


class IODRequest(Packet):
    name = "IODRequest part of Profinet Request"
    fields_desc = [
        ShortField("BlockType", 0),
        ShortField("BlockLength", 0x003c),
        ByteField("VersionHigh", 1),
        ByteField("VersionLow", 0),
        ShortField("SeqNumber", 0),
        StrFixedLenField("UUID",  AR_UUID, 16),
        LEIntField("API", 3801088),
        ShortField("SlotNumber",    2),
        ShortField("SubslotNumber", 1),
        StrFixedLenField("Padding1", "\x00\x00", 2),
        ShortField("Index", 0x002f),
        LEFieldLenField("RecordDataLength", None, length_of="Data", fmt = "I"), #LEFieldLenField
        StrFixedLenField("Padding2", None, 24),
        StrLenField("Data", None, length_from=lambda pkt:pkt.len)
    ]


class ProfinetHeader(Packet):
    name = "Profinet Header"
    fields_desc = [
        LEIntField("ArgsMaxamum",  0),
        LEIntField("ArgsLength",   0),
        LEIntField("MaximumCount", 0),
        LEIntField("Offset",       0),
        LEIntField("ActualCount",  0)
    ]


class ProfinetConnectionPacket(Packet):
    name = "Profinet Connection Request Body"
    fields_desc = [
        PacketField("Header", ProfinetHeader(), ProfinetHeader),
        PacketField("ARBlock", ARBlockRequest(), ARBlockRequest)
    ]


class ProfinetConnectionResponse(Packet):
    name = "Profinet Connection Response Body"
    fields_desc = [
        LEIntField("Status",  0),
        LEIntField("ArgsLength",   0),
        LEIntField("MaximumCount", 0),
        LEIntField("Offset",       0),
        LEIntField("ActualCount",  0),
        PacketField("ARBlock", ARBlockRequest(), ARBlockRequest)
    ]


class ProfinetWriteResponse(Packet):
    name = "Profinet Write Response Body"
    fields_desc = [
        LEIntField("Status",  0),
        LEIntField("ArgsLength",   0),
        LEIntField("MaximumCount", 0),
        LEIntField("Offset",       0),
        LEIntField("ActualCount",  0),
        PacketField("IODWriteResponse", IODWriteResHeader(), IODWriteResHeader)
    ]


class ProfinetReadResponse(Packet):
    name = "Profinet Read Response Body"
    fields_desc = [
        LEIntField("Status",  0),
        LEIntField("ArgsLength",   0),
        LEIntField("MaximumCount", 0),
        LEIntField("Offset",       0),
        LEIntField("ActualCount",  0),
        PacketField("IODReadResponse", IODReadResHeader(), IODReadResHeader)
    ]


class ProfinetWritePacket(Packet):
    name = "Profinet Write Request"
    fields_desc = [
        PacketField("Header", ProfinetHeader(), ProfinetHeader),
        PacketField("WriteRequest", IODRequest(BlockType=0x0008, BlockLength=0x003c), IODRequest),
    ]


class ProfinetReadPacket(Packet):
    name = "Profinet Read Request"
    fields_desc = [
        PacketField("Header", ProfinetHeader(), ProfinetHeader),
        PacketField("ReadRequest", IODRequest(BlockType=0x0009, BlockLength=0x003c), IODRequest)
    ]


class DCERPC(Packet):
    name = "DCE/RPC protocol"
    fields_desc = [
        ByteField("ProtocolVersion", 4),              # RPC protocol major version (4 LSB only)
        ByteField("PacketType", 0),                   # Packet type (5 LSB only)
        ByteField("Flags1", 0x20),                    # Packet flags
        ByteField("Flags2", 0x00),                    # Packet flags
        ByteField("ByteOrder", 0x10),
        ByteField("Character", 0),
        ByteField("Floating-point", 0),
        ByteField("SerialNumberHigh", 0),             # High byte of serial number
        StrFixedLenField("ObjectUUID",    OBJECT_UUID, 16),     # Object identifier
        StrFixedLenField("InterfaceUUID", INTERFACE_UUID, 16),  # Interface identifier
        StrFixedLenField("ActivityUUID",  SESSION_UUID, 16),    # Activity identifier
        LEIntField("BootTime", 0),                    # Server boot time
        LEIntField("InterfaceVersion", 1),            # Interface version
        LEIntField("SequenceNumber", 0),              # Sequence number
        LEShortField("OperationNumber", 0),           # Operation number
        LEShortField("InterfaceHint", 0xffff),        # Interface hint
        LEShortField("ActivityHint",  0xffff),        # Activity hint
        LEShortField("PacketLength",   0),            # Length of packet body
        LEShortField("FragmentNumber", 0),            # Fragment number
        ByteField("AuthenticationProtocolID", 0),     # Authentication protocol identifier
        ByteField("SerialNumberLow", 0)               # Low byte of serial number
    ]


class ProfinetConnectionRequest(Packet):
    name = "Profinet Connection Request using DCE/RPC protocol"
    fields_desc = [
        PacketField("DCERPC", DCERPC(PacketLength=81), DCERPC),
        PacketField("PNIO", ProfinetConnectionPacket(Header=ProfinetHeader(ArgsMaxamum=61,
                                                                           ArgsLength=61,
                                                                           MaximumCount=61,
                                                                           ActualCount=61)), ProfinetConnectionPacket)
    ]


class ProfinetWriteRequest(Packet):
    name = "Profinet Write Request"
    fields_desc = [
        PacketField("DCERPC", DCERPC(
            SequenceNumber=1,
            PacketLength=106,
            OperationNumber=PNIO_WRITE), DCERPC),
        PacketField("PNIO", ProfinetWritePacket(), ProfinetWritePacket)
    ]


class ProfinetReadRequest(Packet):
    name = "Profinet Read Request"
    fields_desc = [
        PacketField("DCERPC", DCERPC(PacketLength=106, OperationNumber=PNIO_READ), DCERPC),
        PacketField("PNIO", ProfinetReadPacket(), ProfinetReadPacket)
    ]


class ProfinetParameter(Packet):
    name = "Profinet Parameter"
    fields_desc = [
        ByteField("Attibute", 0x10),
        ByteField("Indices",  0x00),
        ShortField("ID", 0),
        ShortField("Index", 0),
    ]


class ProfinetGetParametersRequest(Packet):
    name = "Profinet Get Parameters Request"
    fields_desc = [
        ByteField("Reference", 0x00),
        ByteField("Type", 0x01),      # 01 - Read 02 - Write
        ByteField("Axis", 0x01),
        FieldLenField("ParametersNumber", None, count_of="Parameters", fmt="B"),
        PacketListField("Parameters", None, ProfinetParameter, count_from=lambda pkt: pkt.ParametersNumber),
    ]


class ProfinetSetParametersRequest(Packet):
    name = "Profinet Set Parameters Request"
    fields_desc = [
        ByteField("Reference", 0x00),
        ByteField("Type", 0x02),      # 01 - Read 02 - Write
        ByteField("Axis", 0x01),
        FieldLenField("ParametersNumber", None, count_of="Parameters", fmt="B"),
        PacketListField("Parameters", None, ProfinetParameter, count_from=lambda pkt: pkt.ParametersNumber),
    ]


class ProfinetTelegram(Packet):
    name = "Profinet Telegram"
    fields_desc = [
        ByteField("Reference", 0x00),
        ByteField("Type",  0x01),
        ByteField("Axis",  0x00),
        ByteField("Undefined1",  0x08),
        ByteField("Undefined2",  0x01),
        ByteField("Undefined3",  0x00),
        ByteField("Undefined4",  0x00),
        ByteField("Undefined5",  0x01),
        ShortField("CW", 0),
        ShortField("RPM", 0)
    ]


class ProfinetParametersDataHeader(Packet):
    name = "Profinet Get Parameters Data Header"
    fields_desc = [
        ByteField("Reference", 0x00),
        ByteField("Type",  0x00),
        ByteField("Axis",  0x01),
        ByteField("ParametersNumber",  0x01)
    ]


class ProfinetParameterValue(Packet):
    name = "Profinet Value"
    fields_desc = [
        ByteField("Format", 0x00),
        ByteField("NumIndex",  0x00),
        StrField("Value", None)
    ]


class ProfinetParametersValues(Packet):
    name = "Profinet Values List"
    fields_desc = [
        PacketListField("Values", None, ProfinetParameterValue)
    ]


def CreateEPMRequest(handle=None):
    dcerpc = DCERPC(SequenceNumber=0,
                    ObjectUUID=uuid.UUID('{00000000-0000-0000-0000-000000000000}').bytes_le,
                    InterfaceUUID=uuid.UUID('{e1af8308-5d1f-11c9-91a4-08002b14a0fa}').bytes_le,
                    ActivityUUID=uuid.uuid1(),
                    InterfaceVersion=3,
                    PacketLength=76,
                    OperationNumber=PNIO_READ)

    if handle is None:
        emp = EPMRequest()
    else:
        emp = EPMRequest(Handle=handle)

    return dcerpc/emp


def CreateProfinetConnectionRequest():
    pnio_connect = ProfinetConnectionRequest()
    return pnio_connect


def CreateProfinetWriteRequest(dcerpc_id, pnio_id, data, index=None):
    print '------------------------'
    print data
    print '------------------------'
    length = len(data)
    if index is None:
        index = 0x002f

    pnio = ProfinetWriteRequest(DCERPC=DCERPC(SequenceNumber=dcerpc_id, PacketLength=84+length, OperationNumber=PNIO_WRITE),
                                PNIO=ProfinetWritePacket(
                                    Header=ProfinetHeader(
                                        ArgsMaxamum=64+length,
                                        ArgsLength=64+length,
                                        MaximumCount=64+length,
                                        ActualCount=64+length),
                                    WriteRequest=IODRequest(
                                        BlockType=0x0008,
                                        BlockLength=0x003c,
                                        SeqNumber=pnio_id,
                                        Index=index,
                                        Data=data)))
    return pnio


def CreateProfinetReadRequest(dcerpc_id, pnio_id, max, len):
    pnio = ProfinetReadRequest(DCERPC=DCERPC(SequenceNumber=dcerpc_id, PacketLength = 84, OperationNumber=PNIO_READ),
                               PNIO=ProfinetReadPacket(
                                   Header=ProfinetHeader(
                                       ArgsMaxamum=max,
                                       ArgsLength=len,
                                       MaximumCount=max,
                                       ActualCount=len),
                                   ReadRequest=IODRequest(
                                       BlockType=0x0009,
                                       BlockLength=0x003c,
                                       SeqNumber=pnio_id,
                                       RecordDataLength=max-64)))
    return pnio


def CheckEPMResponse(packet):
    dcerpc = DCERPC(packet)
    if dcerpc.PacketType == DCERPC_RESPONSE and dcerpc.OperationNumber == EMP_LOOKUP:
        epm = EPMResponse(dcerpc.load)
        return epm
    return None


def GetAnnotation(epm):
    if epm.NumEntries > 0:
        if epm.Entries[0].ActualCount > 0:
            return epm.Entries[0].Entry[0].Annotation
    return None


def GetPort(epm):
    if epm.NumEntries > 0:
        if epm.Entries[0].ActualCount > 0:
            floor = epm.Entries[0].Entry[0].Floors[0]
            for i in xrange(epm.Entries[0].Entry[0].NumFloors):
                if floor.LHSLangth == 1:
                    if floor.Data == "\x08":
                        value = struct.unpack(">H", floor.Data2)[0]
                        return value
                floor = EPMFloor(floor.load)
    return None


def GetObjectUUID(epm):
    if epm.NumEntries > 0:
        if epm.Entries[0].ActualCount > 0:
            return epm.Entries[0].Entry[0].ObjectUUID
    return None


def GetInterfaceUUID(epm):
    if epm.NumEntries > 0:
        if epm.Entries[0].ActualCount > 0:
            floor = epm.Entries[0].Entry[0].Floors[0]
            for i in xrange(epm.Entries[0].Entry[0].NumFloors):
                if floor.LHSLangth == 19:
                    if ord(floor.Data[0]) == 0x0d:
                        return floor.Data[1:17]
                floor = EPMFloor(floor.load)
    return None


def CheckProfinetWriteResponse(packet):
    dcerpc = DCERPC(packet)
    if dcerpc.PacketType == DCERPC_RESPONSE and dcerpc.OperationNumber == PNIO_WRITE:
        pnio = ProfinetWriteResponse(dcerpc.load)
        if pnio.Status == 0 and pnio.IODWriteResponse.Status == 0:
            return True
    return False


def CheckProfinetReadResponse(packet):
    dcerpc = DCERPC(packet)
    if dcerpc.PacketType == DCERPC_RESPONSE and dcerpc.OperationNumber == PNIO_READ :
        pnio = ProfinetReadResponse(dcerpc.load)
        if pnio.Status == 0:
            return True, pnio.IODReadResponse.Data
    return False, None


def GetValue(format, packet):
    value = None
    offset = 0
    format_str = None

    if format == PNIO_INT8:
        offset = 1
        format_str = "b"
    elif format == PNIO_INT16:
        offset = 2
        format_str = ">h"
    elif format == PNIO_INT32:
        offset = 4
        format_str = ">i"
    elif format == PNIO_UINT8 or format == PNIO_BYTE:
        offset = 1
        format_str = "B"
    elif format == PNIO_UINT16 or format == PNIO_WORD:
        offset = 2
        format_str = ">H"
    elif format == PNIO_UINT32 or format == PNIO_DWORD:
        offset = 4
        format_str = ">I"
    elif format == PNIO_FLOAT:
        offset = 4
        format_str = "!f"
    elif format == PNIO_STRING:
        offset = 4
        format_str = "!f"

    if format_str:
        value = struct.unpack(format_str, packet[:offset])[0]

    return value, offset


def GetProfinetParametersValue(data):
    parameters_value = []
    header = ProfinetParametersDataHeader(data)
    if header.Type == 0x01:
        data_pkt = str(header.load)
        for i in xrange(header.ParametersNumber):
            format = struct.unpack('<b', data_pkt[0])[0]
            index = struct.unpack('<b', data_pkt[1])[0]
            data_pkt = data_pkt[2:]
            for i in xrange(0, index):
                value, offset = GetValue(format, data_pkt)
                parameters_value.append(value)
                data_pkt = data_pkt[offset:]

    return parameters_value