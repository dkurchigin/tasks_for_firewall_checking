import re
import json
import time
import binascii

from models import commit_, load_input_packet, load_output_packet

int_pattern = r'\((\d+)\)'
dt_pattern = r'(RTZ.*\(.*\))$'

in_ = 0
out_ = 0

i = 0

STUPID_SHIFT = 2
INPUT_PACKET_HEADER = 16 * STUPID_SHIFT
INPUT_SESSION_LEN = 64 * STUPID_SHIFT
OUTPUT_SESSION_LEN = 45 * STUPID_SHIFT


def format_to_ip(string_):
    ip = binascii.unhexlify(string_)
    ip_to_string = f'{ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}'
    return ip_to_string


def hex_simple_convert(string_):
    number = binascii.unhexlify(string_)
    return int.from_bytes(number, 'big')


def hex_simple_convert_little(string_):
    number = binascii.unhexlify(string_)
    return int.from_bytes(number, 'little')


def get_session(string_, frame_number, frame_time):
    dict_ = {}
    dict_['source_ip'] = format_to_ip(string_[8:16])
    dict_['source_nat_ip'] = format_to_ip(string_[16:24])
    dict_['destination_ip'] = format_to_ip(string_[24:32])
    dict_['destination_nat_ip'] = format_to_ip(string_[32:40])

    dict_['source_port'] = hex_simple_convert(string_[40:44])
    dict_['source_nat_port'] = hex_simple_convert(string_[44:48])
    dict_['destination_port'] = hex_simple_convert(string_[48:52])
    dict_['destination_nat_port'] = hex_simple_convert(string_[52:56])

    dict_['start_stream'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(hex_simple_convert(string_[56:64])))
    dict_['end_stream'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(hex_simple_convert(string_[64:72])))

    dict_['frame_number'] = frame_number
    dict_['frame_time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(frame_time)))

    load_input_packet(dict_)
    # print(f'source {source_ip}:{source_port}')
    # print(f'source_nated {source_nat_ip}:{source_nat_port}')
    # print(f'destination {destination_ip}:{destination_port}')
    # print(f'destination_nated {destination_nat_ip}:{destination_nat_port}')
    # print(f'{start_stream} - {end_stream}')


def get_output_session(string_, frame_number, frame_time):
    dict_ = {}
    dict_['source_ip'] = format_to_ip(string_[0:8])
    dict_['source_port'] = hex_simple_convert_little(string_[8:12])

    dict_['nat_ip'] = format_to_ip(string_[12:20])
    dict_['port_nat_begin'] = hex_simple_convert_little(string_[20:24])
    dict_['port_nat_end'] = hex_simple_convert_little(string_[24:28])

    dict_['destination_ip'] = format_to_ip(string_[28:36])
    dict_['destination_port'] = hex_simple_convert_little(string_[36:40])

    dict_['session_begin'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(hex_simple_convert_little(string_[40:56])))
    dict_['session_end'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(hex_simple_convert_little(string_[56:72])))

    dict_['packet_number'] = hex_simple_convert_little(string_[72:88])
    dict_['traffic_type'] = hex_simple_convert_little(string_[88:90])

    dict_['frame_number'] = frame_number
    dict_['frame_time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(frame_time)))

    load_output_packet(dict_)
    # print(f'source {source_ip}:{source_port}')
    # print(f'nat ip {nat_ip}:{port_nat_begin}:{port_nat_end}')
    # print(f'destination {destination_ip}:{destination_port}')
    # print(f'session {session_begin} - {session_end}')
    # print(f'number and traffic type {packet_number}|{traffic_type}')


wanna_load = input('Загрузить пакеты в базу?')

if wanna_load == 'да':
    with open("1.json", 'r') as read_file:
        string_ = ''
        opened_pattern = r'[\s]\{|^\{'
        closed_pattern = r'\}[\s,]$|\}$'
        opened = 0
        closed = 0
        first_ = False

        for line in read_file:
            if re.findall(opened_pattern, line):
                first_ = True
                opened += 1
            elif re.findall(closed_pattern, line):
                closed += 1
            string_ += line
            if opened == closed and first_:
                string_ = re.sub(r'\[\n', '', string_)
                string_ = re.sub(r',\n$', '', string_)
                try:
                    data = json.loads(string_)
                except Exception as e:
                    print(string_)
                    print(e)
                    raise

                frame_number = data["_source"]["layers"]["frame"]["frame.number"]
                frame_time = data["_source"]["layers"]["frame"]["frame.time_epoch"]

                if data["_source"]["layers"]["udp"]["udp.dstport"] == '9002':
                    print(f'in {frame_number}')

                    udp_data = data["_source"]["layers"]["data"]["data.data"].replace(':', '')
                    session_len = (int(data["_source"]["layers"]["data"]["data.len"]) * STUPID_SHIFT) - INPUT_PACKET_HEADER
                    packet_byte_shift = 0
                    list_ = []

                    for packet in range(int(session_len / INPUT_SESSION_LEN)):
                        try:
                            get_session(udp_data[32+packet_byte_shift:96+packet_byte_shift], frame_number, frame_time)
                            packet_byte_shift += INPUT_SESSION_LEN
                        except Exception as e:
                            print(f"Can't parse in {udp_data[32+packet_byte_shift:96+packet_byte_shift]}")
                            print(e)

                elif data["_source"]["layers"]["udp"]["udp.dstport"] == '22222':
                    print(f'out {frame_number}')

                    try:
                        udp_data = data["_source"]["layers"]["data"]["data.data"].replace(':', '')
                    except KeyError:
                        string_ = ''
                        opened = 0
                        closed = 0
                        first_ = False
                        continue

                    session_len = (int(data["_source"]["layers"]["data"]["data.len"]) * STUPID_SHIFT)
                    packet_byte_shift = 0

                    for packet in range(int(session_len / OUTPUT_SESSION_LEN)):
                        try:
                            get_output_session(udp_data[0+packet_byte_shift:90+packet_byte_shift], frame_number, frame_time)
                            packet_byte_shift += OUTPUT_SESSION_LEN
                        except Exception as e:
                            print(f"Can't parse out {udp_data[0+packet_byte_shift:90+packet_byte_shift]}")
                            print(e)

                string_ = ''
                opened = 0
                closed = 0
                first_ = False
                if int(frame_number) % 20000 == 0:
                    print('commit')
                    commit_()
        commit_()
