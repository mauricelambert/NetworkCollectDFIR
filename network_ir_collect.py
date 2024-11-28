#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This script collects data for incident response
#    and forensic (useful for CTF and DFIR challenges!)
#    Copyright (C) 2024  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

from re import sub
from json import dump
from scapy.all import *
from sys import argv, exit
from os import getcwd, makedirs
from urllib.parse import urlparse
from os.path import join, basename
from scapy.contrib.oncrpc import *
from hashlib import sha512, md5, sha1
from dataclasses import dataclass, field
from collections import Counter, defaultdict
from time import gmtime, strftime, struct_time

if len(argv) != 2:
    print("USAGES: python3 network_ir_collect.py <file.pcap>")
    exit(1)

@dataclass
class IpAddressStats:
    ip: set = field(default_factory=set)
    ports: set = field(default_factory=set)
    communications: set = field(default_factory=set)
    http_requests: set = field(default_factory=set)

@dataclass
class File:
    filename: str = None
    protocol: str = None
    type: str = None
    content: bytearray = field(default_factory=bytearray)
    size: int = 0
    md5: str = None
    sha1: str = None
    sha512: str = None
    close: bool = False

@dataclass
class SessionTcp:
    source: int
    ip_source: str
    destination: int
    ip_destination: str
    start: str
    index: int
    end: str = None
    reset: bool = False
    close: bool = False
    ack: bool = False
    init: bool = False
    packet_count: int = 0
    size: int = 0
    indexes: List[int] = field(default_factory=list)
    request_files: List[File] = field(default_factory=list)
    response_files: List[File] = field(default_factory=list)
    window: int = 1

load_layer("http")

to_datetime = lambda x: strftime("%Y-%m-%d %H:%M:%S", gmtime(float(x.time)))

def add_datetime(datetime_string: str, value: str, datetimes: dict) -> None:
    if value in datetimes:
        return
    datetimes[value] = datetime_string

counters = defaultdict(Counter)
datetimes = defaultdict(dict)
counters_diff = defaultdict(IpAddressStats)
application_counters = defaultdict(lambda *x:defaultdict(Counter))

dns_servers = set()
ntp_servers = set()
ldap_servers = set()
kerberos_servers = set()

counters["ip-number"]
counters["ports-number"]
counters["communications-number"]
counters["icmp-echo-request"]
counters["arp-request"]
counters["arp-reply"]
counters["tcp-syn"]
counters["tcp-opn"]
counters["tcp-cls"]
counters["tcp-rst"]
counters["udp-snd"]
counters["http-path-number"]
counters["ip"]
counters["conversations"]
counters["flux-tcp"]
counters["flux-udp"]

tcp_sessions = []
active_tcp_sessions = {}
active_smb_sessions = {}

#pcap_filename = "2023-04-Unit42-Wireshark-quiz.pcap"
pcap_filename = argv[1]

for index, packet in enumerate(sniff(offline=pcap_filename)):
#for packet in sniff(offline="exam.pcap"):
    index += 1
    if packet.haslayer(IP):
        datetime = to_datetime(packet)
        counters["ip"][f"{packet[IP].src} ({packet[Ether].src})"] += 1
        counters["ip"][f"{packet[IP].dst} ({packet[Ether].dst})"] += 1
        add_datetime(datetime, packet[IP].src, datetimes["ip"])
        add_datetime(datetime, packet[IP].dst, datetimes["ip"])
        if f"{packet[IP].dst}->{packet[IP].src}" in counters["conversations"]:
            counters["conversations"][f"{packet[IP].dst}->{packet[IP].src}"] += 1
        else:
            counters["conversations"][f"{packet[IP].src}->{packet[IP].dst}"] += 1
            add_datetime(datetime, f"{packet[IP].src}->{packet[IP].dst}", datetimes["conversations"])
        is_udp = packet.haslayer(UDP)
        is_tcp = packet.haslayer(TCP)
        if is_tcp:
            send = True
            if packet[TCP].flags == 2:
                counters["tcp-syn"][packet[IP].src] += 1
                counters_diff[packet[IP].src].ip.add(packet[IP].dst)
                counters_diff[packet[IP].src].ports.add(packet[TCP].dport)
                counters_diff[packet[IP].src].communications.add(f"{packet[IP].dst}:{packet[TCP].dport}")
                session = SessionTcp(packet[TCP].sport, packet[IP].src, packet[TCP].dport, packet[IP].dst, datetime, len(tcp_sessions) + 1)
                active_tcp_sessions[(packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)] = session
                tcp_sessions.append(session)
                session.init = True
            elif packet[TCP].flags & 2:
                counters["tcp-opn"][packet[IP].dst] += 1
                session = active_tcp_sessions.get((packet[IP].dst, packet[TCP].dport, packet[IP].src, packet[TCP].sport))
                if session:
                    session.ack = True
            elif packet[TCP].flags & 1:
                session = active_tcp_sessions.get((packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport))
                if not session:
                    send = False
                    counters["tcp-cls"][packet[IP].dst] += 1
                    session = active_tcp_sessions.setdefault((packet[IP].dst, packet[TCP].dport, packet[IP].src, packet[TCP].sport), SessionTcp(packet[TCP].sport, packet[IP].src, packet[TCP].dport, packet[IP].dst, datetime, len(tcp_sessions) + 1))
                else:
                    counters["tcp-cls"][packet[IP].src] += 1
                session.end = datetime
                session.close = True
            elif packet[TCP].flags & 4:
                session = active_tcp_sessions.get((packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport))
                if not session:
                    send = False
                    counters["tcp-rst"][packet[IP].dst] += 1
                    session = active_tcp_sessions.setdefault((packet[IP].dst, packet[TCP].dport, packet[IP].src, packet[TCP].sport), SessionTcp(packet[TCP].sport, packet[IP].src, packet[TCP].dport, packet[IP].dst, datetime, len(tcp_sessions) + 1))
                else:
                    counters["tcp-rst"][packet[IP].src] += 1
                session.end = datetime
                session.reset = True
            else:
                session = active_tcp_sessions.get((packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport))
                if not session:
                    send = False
                    session = active_tcp_sessions.setdefault((packet[IP].dst, packet[TCP].dport, packet[IP].src, packet[TCP].sport), SessionTcp(packet[TCP].sport, packet[IP].src, packet[TCP].dport, packet[IP].dst, datetime, len(tcp_sessions) + 1))
            if packet[TCP].sport == 88:
                kerberos_servers.add(packet[IP].src)
            payload_length = len(raw(packet[TCP].payload))
            zero_window_probe = False
            if not session.window and payload_length == 1:
                zero_window_probe = True
            session.window = packet[TCP].window
            session.size += payload_length
            session.packet_count += 1
            session.indexes.append(index)
            if f"{packet[IP].dst}:{packet[TCP].dport}->{packet[IP].src}:{packet[TCP].sport}" in counters["flux-tcp"]:
                counters["flux-tcp"][f"{packet[IP].dst}:{packet[TCP].dport}->{packet[IP].src}:{packet[TCP].sport}"] += 1
            else:
                counters["flux-tcp"][f"{packet[IP].src}:{packet[TCP].sport}->{packet[IP].dst}:{packet[TCP].dport}"] += 1
                add_datetime(datetime, f"{packet[IP].src}->{packet[IP].dst}:{packet[TCP].dport}", datetimes["client-service-tcp"])
                add_datetime(datetime, f"{packet[IP].src}:{packet[TCP].sport}->{packet[IP].dst}:{packet[TCP].dport}", datetimes["flux-tcp"])
        elif is_udp:
            counters["udp-snd"][packet[IP].src] += 1
            if packet[UDP].sport == 53:
                dns_servers.add(packet[IP].src)
            elif packet[UDP].sport == 389:
                ldap_servers.add(packet[IP].src)
            elif packet.haslayer(NTPHeader) and packet[NTPHeader].mode == 4:
                ntp_servers.add(packet[IP].src)
            if f"{packet[IP].dst}:{packet[UDP].dport}->{packet[IP].src}:{packet[UDP].sport}" in counters["flux-udp"]:
                counters["flux-udp"][f"{packet[IP].dst}:{packet[UDP].dport}->{packet[IP].src}:{packet[UDP].sport}"] += 1
            else:
                counters["flux-udp"][f"{packet[IP].src}:{packet[UDP].sport}->{packet[IP].dst}:{packet[UDP].dport}"] += 1
                add_datetime(datetime, f"{packet[IP].src}->{packet[IP].dst}:{packet[UDP].dport}", datetimes["client-service-udp"])
                add_datetime(datetime, f"{packet[IP].src}:{packet[UDP].sport}->{packet[IP].dst}:{packet[UDP].dport}", datetimes["flux-udp"])
        elif packet.haslayer(ICMP) and packet[ICMP].type == 8:
            counters["icmp-echo-request"][packet[IP].src] += 1
        layers = packet.layers()
        if is_udp and packet[UDP].sport == 137 and not packet.haslayer(NBNSQueryRequest):
            response = NBNSQueryResponse(
                raw(NBNSHeader(raw(packet[UDP].payload)).payload)
            )
            if response.QUESTION_TYPE == 32:
                add_datetime(datetime, f"NetbiosName ({packet[1].src}): {', '.join(x.NB_ADDRESS for x in response.ADDR_ENTRY if not isinstance(x, Raw))} ({response.RR_NAME.decode('latin-1')})", datetimes["name-resolution"])
            elif response.QUESTION_TYPE == 33:
                response = NBNSNodeStatusResponse(
                    raw(NBNSHeader(raw(packet[UDP].payload)).payload)
                )
                add_datetime(datetime, f"NetbiosIP ({packet[1].src}): ({', '.join(x.NETBIOS_NAME.decode('latin-1') for x in response.NODE_NAME)})", datetimes["name-resolution"])
        elif is_udp and (packet[UDP].sport == 5353 or packet[UDP].sport == 5355 or packet[UDP].sport == 53):
            if packet[UDP].sport == 5353:
                response = LLMNRResponse(raw(packet[UDP].payload))
                protocol = "LLMNR"
            else:
                response = DNS(raw(packet[UDP].payload))
                protocol = "DNS" if packet[UDP].sport == 53 else "MDNS"
            if response.an:
                if response.an.type == 12:
                    add_datetime(datetime, f"{protocol} IP ({packet[1].src}): {response.an.rrname.decode('latin-1')} ({response.an.rdata.decode('latin-1')})", datetimes["name-resolution"])
                elif response.an.type == 1 or response.an.type == 28:
                    add_datetime(datetime, f"{protocol} Name ({packet[1].src}): {response.an.rdata} ({response.an.rrname.decode('latin-1')})", datetimes["name-resolution"])
        elif is_udp and packet[UDP].dport == 111:
            add_datetime(datetime, f"MachineName: {RPC(raw(packet[UDP].payload))[RPC_Call].a_unix.mname.fields['_name'].decode('latin-1')} ({packet[IP].src})", datetimes["rpc"])
        elif packet.haslayer(NBTDatagram):
            add_datetime(datetime, f"SMB info: SourceName = {packet[NBTDatagram].SourceName.decode('latin-1')} ({packet[NBTDatagram].SourceIP}, {packet[IP].src}) -> {packet[NBTDatagram].DestinationName.decode('latin-1')} ({packet[IP].dst})", datetimes["smb-info"])
            if packet.haslayer(SMB_Header):
                if packet[SMB_Header].Command == 0x25 and packet.haslayer(SMBMailslot_Write):
                    for buffer in packet[SMBMailslot_Write].Buffer:
                        if buffer[0] == 'Data':
                            if isinstance(buffer[1], BRWS_BecomeBackup):
                                add_datetime(datetime, f"SMB info: BrowserToPromote={buffer[1].BrowserToPromote.decode('latin-1')}", datetimes["smb-info"])
                            elif isinstance(buffer[1], BRWS_HostAnnouncement):
                                add_datetime(datetime, f"SMB info: ServerName={buffer[1].ServerName.decode('latin-1')}", datetimes["smb-info"])
        elif is_udp and packet.haslayer(CLDAP):
            if hasattr(packet.protocolOp, "filter"):
                for filters in packet.protocolOp.filter.filter.fields.values():
                    if isinstance(filters, list):
                        for filter_ in filters:
                            attr_type = filter_.filter.attributeType.val.decode('latin-1')
                            if attr_type == "DomainGuid":
                                parts = struct.unpack('<IHH8s', filter_.filter.attributeValue.val)
                                value = f"{parts[0]:08x}-{parts[1]:04x}-{parts[2]:04x}-{parts[3].hex()[:4]}-{parts[3].hex()[4:]}"
                            elif attr_type == "DomainSid":
                                revision = filter_.filter.attributeValue.val[0]
                                sub_authority_count = filter_.filter.attributeValue.val[1]
                                authority = struct.unpack('>Q', b'\x00\x00' + filter_.filter.attributeValue.val[2:8])[0]
                                sub_authorities = struct.unpack('<' + 'I' * sub_authority_count, filter_.filter.attributeValue.val[8:])
                                value = f"S-{revision}-{authority}-{'-'.join(map(str, sub_authorities))}"
                            elif attr_type == "NtVer":
                                value = hex(int.from_bytes(filter_.filter.attributeValue.val, 'little'))
                            elif attr_type == "AAC":
                                value = filter_.filter.attributeValue.val.hex(":")
                            else:
                                value = filter_.filter.attributeValue.val.decode('latin-1')
                            add_datetime(datetime, f"LDAP filter: {attr_type}={value}", datetimes["ldap-filter"])
        elif is_udp and packet.haslayer(NTPHeader) and packet[NTPHeader].sent:
            time = gmtime(float(packet[NTPHeader].sent))
            if time.tm_mday > 17:
                day = (time.tm_mday - 17)
            else:
                day = 17 - time.tm_mday
                try:
                    for d in range(33):
                        strftime("%d", struct_time((time.tm_year - 70, time.tm_mon - 1, d, 0, 0, 0, 0, 0, 0)))
                except ValueError:
                    d -= 1
                day = d - day
            time = struct_time((time.tm_year - 70, time.tm_mon, day, time.tm_hour, time.tm_min, time.tm_sec, time.tm_wday, time.tm_yday, time.tm_isdst))
            add_datetime(datetime, strftime("%Y-%m-%d %H:%M:%S", time), datetimes["ntp-time"])
        elif is_tcp and packet.haslayer(HTTPRequest):
            path = packet[HTTPRequest].Path.decode('latin-1')
            host = packet[HTTPRequest].Host.decode('latin-1')
            counters_diff[packet[IP].src].http_requests.add((host, path))
            add_datetime(datetime, f"Host: {host}", datetimes["http"])
            add_datetime(datetime, f"User-Agent: {(packet[HTTPRequest].User_Agent or b'No User-Agent').decode('latin-1')}", datetimes["http"])
            add_datetime(datetime, f"Path ({packet[HTTPRequest].Method.decode('latin-1')}): {path}", datetimes["http"])
            filename = basename(urlparse(path).path) or "index.html"
            file = File()
            file.protocol = "HTTP"
            file.filename = filename
            session.response_files.append(file)
            file = File()
            file.protocol = "HTTP"
            file.filename = filename
            session.request_files.append(file)
            if packet[HTTPRequest].Authorization:
                add_datetime(datetime, f"Authorization: {packet[HTTPRequest].Authorization.decode('latin-1')}", datetimes["http"])
            if packet[HTTPRequest].Content_Type:
                content_type = packet[HTTPRequest].Content_Type.decode('latin-1')
                add_datetime(datetime, f"Content-Type: {content_type}", datetimes["http"])
                file.type = content_type
            if packet.haslayer(Raw) and not zero_window_probe:
                file.content.extend(raw(packet[Raw]))
        elif is_tcp and packet.haslayer(HTTPResponse):
            application_counters["http-status"][packet[IP].dst][packet[HTTPResponse].Status_Code.decode('latin-1')] += 1
            if packet[HTTPResponse].Content_Type:
                content_type = packet[HTTPResponse].Content_Type.decode('latin-1')
                add_datetime(datetime, f"Content-Type: {content_type}", datetimes["http"])
                session.response_files[-1].type = content_type
            add_datetime(datetime, f"Server: {(packet[HTTPResponse].Server or b'No Server').decode('latin-1')}", datetimes["http"])
            add_datetime(datetime, f"Status code: {packet[HTTPResponse].Status_Code.decode('latin-1')}", datetimes["http"])
            if packet.haslayer(Raw) and not zero_window_probe:
                session.response_files[-1].content.extend(raw(packet[Raw]))
        elif is_tcp and packet.haslayer(HTTP) and packet.haslayer(Raw) and not zero_window_probe:
            (session.request_files[-1] if send else session.response_files[-1]).content.extend(raw(packet[Raw]))
        elif is_tcp and packet.haslayer(Kerberos):
            if isinstance(packet[Kerberos].root, KRB_AS_REQ):
                for name in packet[Kerberos].root.reqBody.cname.nameString:
                    add_datetime(datetime, f"CName: {name.val.decode('latin-1')}", datetimes["kerberos"])
                for name in packet[Kerberos].root.reqBody.sname.nameString:
                    add_datetime(datetime, f"SName: {name.val.decode('latin-1')}", datetimes["kerberos"])
                for address in packet[Kerberos].root.reqBody.addresses:
                    add_datetime(datetime, f"Address: {address.address.val.decode('latin-1')}", datetimes["kerberos"])
        elif is_tcp and packet.haslayer(SMBNegociate_Protocol_Request_Header_Generic) and ((send and session.request_files and not session.request_files[-1].close) or (not send and session.response_files and not session.response_files[-1].close)):
            (session.request_files[-1] if send else session.response_files[-1]).content.extend(raw(packet[TCP].payload))
        elif is_tcp and packet.haslayer(SMB2_Header):
            if packet[SMB2_Header].Command == 1:
                if packet.haslayer(SMB2_Session_Setup_Request):
                    if packet[SMB2_Session_Setup_Request].Buffer:
                        for buffer in packet[SMB2_Session_Setup_Request].Buffer:
                            if buffer[0] == 'Security' and getattr(buffer[1], 'token', None):
                                if buffer[1].token.responseToken and buffer[1].token.responseToken.value.val.startswith(b'NTLMSSP'):
                                    auth = NTLM_AUTHENTICATE_V2(buffer[1].token.responseToken.value.val)
                                    for payload in auth.Payload:
                                        if payload[0] == 'UserName':
                                            add_datetime(datetime, f"SMB User: {payload[1]}", datetimes["users"])
                elif packet.haslayer(SMB2_Session_Setup_Response):
                    if packet[SMB2_Session_Setup_Response].Buffer:
                        for buffer in packet[SMB2_Session_Setup_Response].Buffer:
                            if buffer[0] == 'Security' and getattr(buffer[1], 'token', None):
                                if buffer[1].token.responseToken and not isinstance(buffer[1].token.responseToken.value, Kerberos):
                                    for payload in buffer[1].token.responseToken.value.Payload:
                                        if payload[0] == "TargetInfo":
                                            for value in payload[1]:
                                                add_datetime(datetime, f"SMB info: {repr(value).split('AvId=')[1].split()[0]} = {value.Value}", datetimes["smb-info"])
                                        if payload[0] == "TargetName":
                                            add_datetime(datetime, f"SMB info: TargetName = {payload[1]}", datetimes["smb-info"])
            elif packet[SMB2_Header].Command == 3:
                if packet.haslayer(SMB2_Tree_Connect_Request):
                    for buffer in packet[SMB2_Tree_Connect_Request].Buffer:
                        if buffer[0] == "Path":
                            add_datetime(datetime, f"SMB share: {buffer[1]}", datetimes["smb-path"])
            elif packet[SMB2_Header].Command == 5:
                if packet.haslayer(SMB2_Create_Request):
                    for buffer in packet[SMB2_Create_Request].Buffer:
                        if buffer[0] == 'Name':
                            filename = buffer[1]
                            file = File()
                            file.protocol = "SMB"
                            file.filename = basename(filename)
                            session.response_files.append(file)
                            file = File()
                            file.protocol = "SMB"
                            file.filename = basename(filename)
                            session.request_files.append(file)
                            active_smb_sessions[packet[SMB2_Header].SessionId] = session
                            add_datetime(datetime, f"SMB file: {filename}", datetimes["smb-path"])
            elif packet[SMB2_Header].Command == 9:
                if packet.haslayer(SMB2_Write_Request):
                    for buffer in packet[SMB2_Write_Request].Buffer:
                        if buffer[0] == 'Data':
                            active_smb_sessions[packet[SMB2_Header].SessionId].request_files[-1].content.extend(buffer[1])
            elif packet[SMB2_Header].Command == 8:
                if packet.haslayer(SMB2_Read_Response):
                    for buffer in packet[SMB2_Read_Response].Buffer:
                        if buffer[0] == 'Data':
                            active_smb_sessions[packet[SMB2_Header].SessionId].response_files[-1].content.extend(buffer[1])
            elif packet[SMB2_Header].Command == 6:
                if packet[SMB2_Header].SessionId in active_smb_sessions:
                    if packet.haslayer(SMB2_Close_Response) and active_smb_sessions[packet[SMB2_Header].SessionId].response_files:
                        active_smb_sessions[packet[SMB2_Header].SessionId].response_files[-1].close = True
                    elif packet.haslayer(SMB2_Close_Request) and active_smb_sessions[packet[SMB2_Header].SessionId].request_files:
                        active_smb_sessions[packet[SMB2_Header].SessionId].request_files[-1].close = True
        if len(layers) > 3 and layers[3] != "Raw":
            layers = "/".join(x.__name__ for x in layers[2:])
            add_datetime(datetime, f"{packet[IP].src}->{packet[IP].dst} ({layers})", datetimes["client-protocol"])
    elif packet.haslayer(ARP):
        if packet[ARP].op == 1:
            counters["arp-request"][packet[Ether].src] += 1
        elif packet[ARP].op == 2:
            counters["arp-reply"][f"{packet[Ether].src} ({packet[ARP].psrc})"] += 1

for index, session in enumerate(tcp_sessions):
    for source in ("request", "response"):
        files = getattr(session, source + "_files")
        for i, file in enumerate(files):
            if file.content:
                directory = join(getcwd(), pcap_filename + "_extract")
                extract_filename = join(directory, str(session.index) + ".tcp." + source + str(i) + "." + sub(r'[^\w\-_\. ]', '', str(file.filename)).replace(' ', '_'))
                makedirs(directory, exist_ok=True)
                file.sha512 = sha512(file.content).hexdigest()
                file.sha1 = sha1(file.content).hexdigest()
                file.md5 = md5(file.content).hexdigest()
                file.size = len(file.content)
                with open(extract_filename, "wb") as iofile:
                    iofile.write(file.content)
                print("Extracted:", extract_filename, len(file.content))
            if not file.content:
                files[i] = None
            else:
                del file.__dict__['content']
                files[i] = file.__dict__
    tcp_sessions[index] = session.__dict__
    del tcp_sessions[index]["window"]
    tcp_sessions[index]["request_files"] = [file for file in session.request_files if file is not None]
    tcp_sessions[index]["response_files"] = [file for file in session.response_files if file is not None]
    if not session.request_files:
        del tcp_sessions[index]["request_files"]
    if not session.response_files:
        del tcp_sessions[index]["response_files"]

for ip, ip_stat in counters_diff.items():
    counters["ip-number"][ip] = len(ip_stat.ip)
    counters["ports-number"][ip] = len(ip_stat.ports)
    counters["communications-number"][ip] = len(ip_stat.communications)
    counters["http-path-number"][ip] = len(ip_stat.http_requests)


report = {
    "roles": {
        "kerberos": list(kerberos_servers),
        "dns": list(dns_servers),
        "ldap": list(ldap_servers),
        "ntp": list(ntp_servers),
    },
    "counters": {x: dict(y.most_common()) for x, y in counters.items()},
    "application-counters": {
        x: {z: dict(a.most_common()) for z, a in y.items()} for x, y in application_counters.items()
    },
    "datetimes": datetimes,
    "sessions-tcp": tcp_sessions,
}

with open("report.json", "w") as file:
    dump(report, file, indent=4)

print("Report written in 'report.json' file.")