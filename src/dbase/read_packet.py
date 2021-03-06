from sqlite3.dbapi2 import Cursor

import sys
import sqlite3
import json
from datetime import datetime
from packet.layers.pcap_header import PcapHeader
from packet.layers.packet_builder import PacketBuilder

db_filename = "/Users/jpdube/hull-voip/db/index.db"
pcap_path = "/Users/jpdube/hull-voip/db/pcap"

PCAP_GLOBAL_HEADER_SIZE = 24
PCAP_PACKET_HEADER_SIZE = 16

TIMESTAMP = 12
FILE_ID = 11
PACKET_PTR = 10

filter_count = 0


def get_packet(file_id: int, ptr_list):
    global filter_count
    # print(f"=============================================")
    # print(f"===> Getting from: {file_id}, {len(ptr_list)}")
    # print(f"=============================================")
    # print('.', end='', flush=True)
    packet_list = []
    with open(f"{pcap_path}/{file_id}.pcap", "rb") as f:
        for ptr in ptr_list:
            f.seek(ptr)
            header = f.read(PCAP_PACKET_HEADER_SIZE)
            pcap_hdr = PcapHeader(header)
            packet = f.read(pcap_hdr.incl_len)
            pb = PacketBuilder()
            pb.from_bytes(packet, pcap_hdr)
            # pb.summary()
            # print(f"""ETH -> Dst: {pb.get_field("eth.dst")}, Src: {pb.get_field("eth.src")}, Vlan: {pb.get_field("eth.vlan")}, Ethertype: {pb.get_field("eth.ethertype"):04x}, Src IP: {pb.get_field("ip.src")}\tDst IP: {pb.get_field("ip.dst")},\tUDP Dst: {pb.get_field("udp.dst")}, UDP Src: {pb.get_field("udp.src")}""")
            packet_list.append(pb.export())
            filter_count += 1
    return packet_list


def sql(pql: str) -> Cursor:
    conn = sqlite3.connect(db_filename)
    cursor = conn.cursor()

    conn.execute("""PRAGMA synchronous = OFF""")
    conn.execute("""PRAGMA journal_mode = MEMORY;""")
    conn.execute("""PRAGMA threads = 4;""")
    conn.execute("""PRAGMA temp_store = memory;""")
    cursor.execute(pql)
    # rows = cursor.fetchall()

    return cursor


def query(pql: str):
    start_time = datetime.now()
    packet_list = sql(pql)
    # print(f"*** PACKET LIST: {len(list(packet_list))}")
    return_list = []
    count = 0
    current_id = -1
    ptr_list = []
    if packet_list:
        for p in packet_list:
            if current_id == -1:
                current_id = p[FILE_ID]

            if p[FILE_ID] == current_id:
                ptr_list.append(p[PACKET_PTR])
            else:
                return_list.extend(get_packet(current_id, ptr_list))
                current_id = p[FILE_ID]
                ptr_list = []
                ptr_list.append(p[PACKET_PTR])

            count += 1
        if current_id != -1:
            return_list.extend(get_packet(current_id, ptr_list))

    print(f'*** Packet list length: {len(return_list)}')

    print(f"Count: {count}")
    print(f"Execution time: {datetime.now() - start_time}")

    return return_list
